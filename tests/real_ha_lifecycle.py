"""Optional real-HA canary; run directly in an environment with HA installed.

All state is temporary. Socket connections, listeners and DNS are denied before
HA imports. This runs separately from tests/test_access.py, which installs stubs.
"""

# ruff: noqa: E402 -- install the network guard before importing Home Assistant.
import argparse
import asyncio
import importlib.metadata
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, patch


def deny_network(event, _args):
    if event in {
        "socket.connect",
        "socket.bind",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.sendto",
    }:
        raise RuntimeError("Network disabled in real-HA canary: " + event)


sys.addaudithook(deny_network)
sys.dont_write_bytecode = True
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--component-root", type=Path, default=Path(__file__).resolve().parents[1])
options, test_args = parser.parse_known_args()
component_root = options.component_root.resolve()
sys.path.insert(0, str(component_root))

from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from homeassistant import auth, loader, setup
from homeassistant.auth.const import GROUP_ID_ADMIN
from homeassistant.components.http import HomeAssistantHTTP
from homeassistant.config import async_process_component_config
from homeassistant.config_entries import ConfigEntries
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry, entity_registry
from homeassistant.helpers.storage import Store

import custom_components

custom_components.__path__ = [str(component_root / "custom_components")]
from custom_components import ha_access_session as integration

assert Path(integration.__file__).resolve() == (
    component_root / "custom_components/ha_access_session/__init__.py"
)


class RealHALifecycleTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="ha-access-canary-")
        self.hass = HomeAssistant(self.state.name)
        loader.async_setup(self.hass)
        device_registry.async_setup(self.hass)
        await device_registry.async_load(self.hass, load_empty=True)
        await entity_registry.async_load(self.hass, load_empty=True)
        self.hass.config_entries = ConfigEntries(self.hass, {})
        self.hass.auth = await auth.auth_manager_from_config(self.hass, [], [])
        self.hass.http = self.http_server()
        self.user = await self.hass.auth.async_create_user(
            "Synthetic canary administrator", group_ids=[GROUP_ID_ADMIN]
        )
        self.config = {
            "issuer": "https://access.example.invalid",
            "origin": "https://dashboard.example.invalid",
            "audience": "synthetic-canary",
            "email": "owner@example.invalid",
            "user_id": self.user.id,
        }
        self.ha_integration = loader.Integration.resolve_from_root(
            self.hass, custom_components, integration.DOMAIN
        )
        validated = await async_process_component_config(
            self.hass, {integration.DOMAIN: self.config}, self.ha_integration, integration
        )
        self.assertFalse(validated.exception_info_list)
        self.assertIsNotNone(validated.config)
        # Only dependency startup is substituted. The HTTP server/router is real
        # but never bound; auth, storage, schema and scheduler remain real.
        with patch.object(setup, "async_process_deps_reqs", AsyncMock()):
            self.assertTrue(
                await setup.async_setup_component(
                    self.hass, integration.DOMAIN, {integration.DOMAIN: self.config}
                )
            )
        self.view = self.hass.data[integration.DOMAIN]
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.view.keys = {"canary": self.key.public_key()}
        self.view.fetched = time.monotonic()

    def http_server(self):
        return HomeAssistantHTTP(self.hass, None, None, None, ["127.0.0.1"], 0, [], "modern")

    async def asyncTearDown(self):
        for cancel in list(self.view.timers.values()):
            cancel()
        await self.hass.async_stop(force=True)
        self.state.cleanup()

    def assertion(self, lifetime=600):
        return jwt.encode(
            {
                "iss": self.config["issuer"],
                "aud": self.config["audience"],
                "sub": "synthetic-owner",
                "email": self.config["email"],
                "type": "app",
                "iat": int(time.time()) - 2,
                "exp": int(time.time()) + lifetime,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": "canary"},
        )

    def request(self, raw, query=""):
        return make_mocked_request(
            "POST",
            self.view.url + query,
            headers={
                "Host": "dashboard.example.invalid",
                "Origin": self.config["origin"],
                "Cf-Access-Jwt-Assertion": raw,
            },
        )

    async def exchange(self, raw):
        response = await self.view.post(self.request(raw))
        body = json.loads(response.body)
        self.assertEqual(body["contract_version"], 1)
        self.assertGreater(body["expires_in"], 0)
        self.assertLessEqual(body["expires_in"], 300)
        refresh = self.hass.auth.async_validate_access_token(body["access_token"])
        self.assertIsNotNone(refresh)
        self.assertEqual(refresh.user.id, self.user.id)
        return body

    async def test_assertion_expiry_removes_refresh_token_on_event_loop(self):
        raw = self.assertion(lifetime=3)
        body = await self.exchange(raw)
        loop_thread = threading.get_ident()
        removal_threads = []
        remove = self.hass.auth.async_remove_refresh_token

        def record_removal(token):
            removal_threads.append(threading.get_ident())
            remove(token)

        with patch.object(self.hass.auth, "async_remove_refresh_token", record_removal):
            await asyncio.sleep(body["session_expires_at"] - time.time() + 0.1)
            await self.hass.async_block_till_done()
        self.assertEqual(removal_threads, [loop_thread], "expiry escaped HA's event loop")
        self.assertFalse(self.view.sessions)
        self.assertFalse(self.view.timers)
        self.assertFalse(self.user.refresh_tokens)
        self.assertIsNone(self.hass.auth.async_validate_access_token(body["access_token"]))

    async def test_logout_revokes_real_access_token_and_prevents_replay(self):
        raw = self.assertion()
        body = await self.exchange(raw)
        response = await self.view.post(self.request(raw, "?revoke=1"))
        self.assertEqual(response.status, 204)
        self.assertIsNone(self.hass.auth.async_validate_access_token(body["access_token"]))
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))

    async def test_setup_restores_durable_tombstones_and_revokes_old_tokens(self):
        raw = self.assertion()
        body = await self.exchange(raw)
        stored = await Store(self.hass, 1, integration.DOMAIN + ".used_assertions").async_load()
        self.assertEqual(stored, self.view.tombstones)
        for cancel in self.view.timers.values():
            cancel()
        self.hass.http = self.http_server()
        self.assertTrue(await integration.async_setup(self.hass, {integration.DOMAIN: self.config}))
        self.view = self.hass.data[integration.DOMAIN]
        self.view.keys = {"canary": self.key.public_key()}
        self.view.fetched = time.monotonic()
        self.assertIsNone(self.hass.auth.async_validate_access_token(body["access_token"]))
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))
        self.assertTrue(
            any(
                route.method == "POST" and route.resource.canonical == self.view.url
                for route in self.hass.http.app.router.routes()
            )
        )

    async def test_invalid_yaml_is_classified_as_configuration_error(self):
        result = await async_process_component_config(
            self.hass,
            {integration.DOMAIN: self.config | {"token_lifetime_seconds": 301}},
            self.ha_integration,
            integration,
        )
        self.assertIsNone(result.config)
        self.assertEqual(result.exception_info_list[0].translation_key, "config_validation_err")


if __name__ == "__main__":
    print(
        "Real-HA canary: Python "
        + sys.version.split()[0]
        + "; Home Assistant "
        + importlib.metadata.version("homeassistant"),
        flush=True,
    )
    unittest.main(argv=[sys.argv[0], *test_args], verbosity=2)
