"""Offline boundary tests: real RSA signatures, fake HA lifecycle and key transport."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

for name in (
    "homeassistant",
    "homeassistant.components",
    "homeassistant.components.http",
    "homeassistant.helpers",
    "homeassistant.helpers.aiohttp_client",
    "homeassistant.helpers.event",
):
    sys.modules[name] = ModuleType(name)
sys.modules["homeassistant.components.http"].HomeAssistantView = object
sys.modules["homeassistant.helpers.aiohttp_client"].async_get_clientsession = (
    lambda hass: hass.http_client
)
sys.modules["homeassistant.helpers.event"].async_call_later = (
    lambda hass, seconds, cb: hass.timers.append((seconds, cb))
)
spec = importlib.util.spec_from_file_location(
    "access",
    Path(__file__).resolve().parents[1] / "custom_components/ha_access_session/access.py",
)
access = importlib.util.module_from_spec(spec)
sys.modules["access"] = access
spec.loader.exec_module(access)
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CONFIG = {
    "issuer": "https://access.example.invalid",
    "origin": "https://dashboard.example.invalid",
    "audience": "test-audience",
    "email": "owner@example.invalid",
    "user_id": "0" * 32,
}


class AccessTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.user = SimpleNamespace(
            is_admin=True,
            is_active=True,
            local_only=False,
            system_generated=False,
            refresh_tokens={},
        )

        async def create(user, **options):
            token = SimpleNamespace(id=str(len(user.refresh_tokens)), **options)
            user.refresh_tokens[token.id] = token
            return token

        self.auth = SimpleNamespace(
            async_get_user=AsyncMock(return_value=self.user),
            async_get_users=AsyncMock(return_value=[self.user]),
            async_create_refresh_token=AsyncMock(side_effect=create),
            async_remove_refresh_token=Mock(
                side_effect=lambda token: self.user.refresh_tokens.pop(token.id, None)
            ),
            async_create_access_token=Mock(return_value="synthetic-token"),
        )
        self.hass = SimpleNamespace(
            auth=self.auth, timers=[], http=SimpleNamespace(register_view=Mock())
        )
        self.persist = AsyncMock()
        self.view = access.AccessSessions(self.hass, CONFIG, persist=self.persist)
        self.view.keys = {"key": KEY.public_key()}
        self.view.fetched = time.monotonic()

    def claims(self, **changes):
        return {
            "iss": CONFIG["issuer"],
            "aud": [CONFIG["audience"]],
            "sub": "owner-subject",
            "email": CONFIG["email"],
            "type": "app",
            "iat": int(time.time()) - 5,
            "exp": int(time.time()) + 3600,
            **changes,
        }

    def sign(self, claims=None):
        return jwt.encode(claims or self.claims(), KEY, algorithm="RS256", headers={"kid": "key"})

    def request(self, raw=None, headers=None, path=access.SESSION_PATH):
        return make_mocked_request(
            "POST",
            path,
            headers={
                "Host": "dashboard.example.invalid",
                "Origin": CONFIG["origin"],
                access.HEADER: raw or self.sign(),
                **(headers or {}),
            },
        )

    async def test_signed_owner_concurrency_bounded_token_no_refresh_disclosure(self):
        raw = self.sign()
        responses = await asyncio.gather(*(self.view.post(self.request(raw)) for _ in range(8)))
        for response in responses:
            body = json.loads(response.body)
            self.assertEqual(body["access_token"], "synthetic-token")
            self.assertEqual(body["contract_version"], 1)
            self.assertEqual(body["expires_in"], 300)
            self.assertNotIn("refresh_token", body)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.auth.async_create_refresh_token.assert_awaited_once()
        self.auth.async_get_user.assert_awaited_with(CONFIG["user_id"])
        self.persist.assert_awaited_once()
        self.assertEqual(len(self.hass.timers), 1)
        self.hass.timers[0][1](None)
        self.assertEqual(self.view.sessions, {})
        self.auth.async_remove_refresh_token.assert_called_once()

    async def test_invalid_signatures_claims_and_lifetimes_fail_closed(self):
        bad = [
            {"iss": "https://evil.example.invalid"},
            {"aud": ["other-app"]},
            {"email": "other@example.invalid"},
            {"sub": ""},
            {"type": "service"},
            {"exp": int(time.time()) - 1},
            {"iat": int(time.time()) + 60},
            {"nbf": int(time.time()) + 60},
            {"iat": 0},
            {"iat": True},
            {"exp": str(int(time.time()) + 3600)},
            {"exp": int(time.time()) + 86401},
            {"common_name": None},
            {"nbf": None},
            {"nbf": True},
        ]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(web.HTTPUnauthorized):
                await self.view.post(self.request(self.sign(self.claims(**change))))
        for field in ("iat", "exp", "sub", "email", "aud", "iss", "type"):
            claims = self.claims()
            del claims[field]
            with self.subTest(field=field), self.assertRaises(web.HTTPUnauthorized):
                await self.view.post(self.request(self.sign(claims)))
        for raw in (
            "not-a-token",
            jwt.encode(self.claims(), "x" * 32, algorithm="HS256", headers={"kid": "key"}),
            jwt.encode(
                self.claims(),
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                algorithm="RS256",
                headers={"kid": "key"},
            ),
        ):
            with self.assertRaises(web.HTTPUnauthorized):
                await self.view.post(self.request(raw))
        self.auth.async_create_refresh_token.assert_not_awaited()

    async def test_cross_site_lan_spoof_and_duplicate_assertions_cannot_login(self):
        for headers in (
            {"Origin": "https://evil.example.invalid"},
            {"Origin": ""},
            {"Host": "ha.example.invalid"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            with self.assertRaises(web.HTTPForbidden):
                await self.view.post(self.request(headers=headers))
        request = make_mocked_request(
            "POST",
            access.SESSION_PATH,
            headers=[
                ("Host", "dashboard.example.invalid"),
                ("Origin", CONFIG["origin"]),
                (access.HEADER, self.sign()),
                (access.HEADER, self.sign()),
            ],
        )
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(request)

    async def test_trusted_network_requires_opt_in_exact_claims_and_real_signature(
        self,
    ):
        claims = self.claims(sub="", aud=CONFIG["audience"])
        del claims["email"]
        raw = self.sign(claims)
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))
        self.view.config = access.AccessConfig(**CONFIG, allow_trusted_network=True)
        self.assertEqual((await self.view.post(self.request(raw))).status, 200)
        for change in (
            {"email": None},
            {"email": "other@example.invalid"},
            {"common_name": None},
            {"common_name": "service-token"},
            {"sub": "service"},
            {"sub": None},
        ):
            with self.subTest(change=change), self.assertRaises(web.HTTPUnauthorized):
                await self.view.post(self.request(self.sign({**claims, **change})))
        forged = jwt.encode(
            claims,
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            algorithm="RS256",
            headers={"kid": "key"},
        )
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(forged, headers={"CF-Connecting-IP": "192.0.2.1"}))

    async def test_mapping_rejects_user_input_and_ineligible_accounts(self):
        for query in (
            "user_id=attacker",
            "redirect_uri=https://evil.example.invalid",
            "revoke=1&revoke=1",
            "revoke=0",
        ):
            with self.assertRaises(web.HTTPBadRequest):
                await self.view.post(self.request(path=access.SESSION_PATH + "?" + query))
        for flag, value in (
            ("is_admin", False),
            ("is_active", False),
            ("local_only", True),
            ("system_generated", True),
        ):
            previous = getattr(self.user, flag)
            setattr(self.user, flag, value)
            with self.subTest(flag=flag), self.assertRaises(web.HTTPForbidden):
                await self.view.post(self.request())
            setattr(self.user, flag, previous)
        self.auth.async_get_user.return_value = None
        with self.assertRaises(web.HTTPForbidden):
            await self.view.post(self.request())
        self.auth.async_create_refresh_token.assert_not_awaited()

    async def test_expiry_logout_and_logout_before_first_exchange(self):
        raw = self.sign(self.claims(exp=int(time.time()) + 50))
        response = await self.view.post(self.request(raw))
        self.assertLess(json.loads(response.body)["expires_in"], 50)
        self.assertEqual(
            (
                await self.view.post(self.request(raw, path=access.SESSION_PATH + "?revoke=1"))
            ).status,
            204,
        )
        self.assertEqual(self.user.refresh_tokens, {})
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))
        new = self.sign(self.claims(sub="second-assertion"))
        await self.view.post(self.request(new, path=access.SESSION_PATH + "?revoke=1"))
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(new))

    async def test_profile_revocation_and_restart_do_not_restore_assertion(self):
        raw = self.sign()
        await self.view.post(self.request(raw))
        self.user.refresh_tokens.clear()
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))
        restored = access.AccessSessions(
            self.hass,
            CONFIG,
            persist=self.persist,
            tombstones=self.persist.call_args.args[0],
        )
        restored.keys = self.view.keys
        restored.fetched = self.view.fetched
        with self.assertRaises(web.HTTPUnauthorized):
            await restored.post(self.request(raw))

    async def test_signature_encoding_aliases_cannot_bypass_revocation(self):
        raw = self.sign()
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        # A 2048-bit RSA signature ends in four unused base64url bits.
        alias = raw[:-1] + alphabet[alphabet.index(raw[-1]) + 1]
        await self.view.post(self.request(raw))
        await self.view.post(self.request(raw, path=access.SESSION_PATH + "?revoke=1"))
        for alternative in (raw, raw + "=", raw + "==", alias):
            with (
                self.subTest(alternative=alternative[-8:]),
                self.assertRaises(web.HTTPUnauthorized),
            ):
                await self.view.post(self.request(alternative))
        self.auth.async_create_refresh_token.assert_awaited_once()

    async def test_persistence_failure_never_issues_credential(self):
        self.persist.side_effect = OSError("synthetic failure")
        with self.assertRaises(web.HTTPServiceUnavailable):
            await self.view.post(self.request())
        self.auth.async_create_refresh_token.assert_not_awaited()

    async def test_session_bound_and_compatibility_adapter(self):
        self.view.config = access.AccessConfig(**CONFIG, max_sessions=1)
        await self.view.post(self.request())
        with self.assertRaises(web.HTTPTooManyRequests):
            await self.view.post(self.request(self.sign(self.claims(sub="other"))))
        adapter = access.AccessSessions(
            self.hass,
            CONFIG,
            persist=self.persist,
            session_path="/api/custom_dashboard/session",
            client_id=CONFIG["origin"] + "/custom-session",
            view_name="api:custom:session",
        )
        self.assertEqual(adapter.url, "/api/custom_dashboard/session")
        self.assertEqual(adapter.name, "api:custom:session")

    async def test_jwks_fixed_destination_rotation_rate_limit_and_failure(self):
        key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
        key.update(kid="rotated", alg="RS256", use="sig")

        async def chunks(_):
            yield json.dumps({"keys": [key]}).encode()

        response = SimpleNamespace(status=200, content=SimpleNamespace(iter_chunked=chunks))
        context = AsyncMock()
        context.__aenter__.return_value = response
        self.hass.http_client = SimpleNamespace(get=Mock(return_value=context))
        self.view.fetched = 0
        raw = jwt.encode(
            self.claims(),
            KEY,
            algorithm="RS256",
            headers={"kid": "rotated", "jku": "https://evil.example.invalid"},
        )
        await self.view.post(self.request(raw))
        self.assertEqual(
            self.hass.http_client.get.call_args.args,
            (CONFIG["issuer"] + "/cdn-cgi/access/certs",),
        )
        self.assertFalse(self.hass.http_client.get.call_args.kwargs["allow_redirects"])
        for _ in range(3):
            with self.assertRaises(web.HTTPUnauthorized):
                await self.view.post(self.request(self.sign()))
        self.hass.http_client.get.assert_called_once()
        self.view.fetched = 0
        response.status = 302
        with self.assertRaises(web.HTTPServiceUnavailable):
            await self.view.post(self.request(raw))
        self.view.fetched = 0
        response.status = 200

        async def huge(_):
            yield b" " * 65537

        response.content.iter_chunked = huge
        with self.assertRaises(web.HTTPUnauthorized):
            await self.view.post(self.request(raw))


class ConfigurationTest(unittest.TestCase):
    def test_invalid_values(self):
        for field, value in (
            ("issuer", "http://access.example.invalid"),
            ("origin", "https://dashboard.example.invalid/"),
            ("origin", "https://owner@dashboard.example.invalid"),
            ("origin", "https://dashboard.example.invalid?next=x"),
            ("audience", ""),
            ("email", "invalid"),
            ("user_id", "attacker"),
            ("allow_trusted_network", "true"),
            ("token_lifetime_seconds", 301),
            ("max_sessions", 129),
            ("token_lifetime_seconds", True),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                access.AccessConfig(**{**CONFIG, field: value})


class IntegrationSetupTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        storage = ModuleType("homeassistant.helpers.storage")
        self.store = SimpleNamespace(async_load=AsyncMock(return_value={}), async_save=AsyncMock())
        storage.Store = Mock(return_value=self.store)
        sys.modules["homeassistant.helpers.storage"] = storage
        folder = Path(__file__).resolve().parents[1] / "custom_components/ha_access_session"
        module_spec = importlib.util.spec_from_file_location(
            "integration_under_test",
            folder / "__init__.py",
            submodule_search_locations=[str(folder)],
        )
        self.integration = importlib.util.module_from_spec(module_spec)
        sys.modules["integration_under_test"] = self.integration
        module_spec.loader.exec_module(self.integration)
        self.managed = SimpleNamespace(
            id="managed", client_id=CONFIG["origin"] + "/ha-access-session/v1"
        )
        self.normal = SimpleNamespace(id="normal", client_id="https://other.example.invalid/")
        user = SimpleNamespace(refresh_tokens={"managed": self.managed, "normal": self.normal})
        self.hass = SimpleNamespace(
            data={},
            http=SimpleNamespace(register_view=Mock()),
            auth=SimpleNamespace(
                async_get_users=AsyncMock(return_value=[user]), async_remove_refresh_token=Mock()
            ),
        )

    async def test_restart_removes_only_managed_credentials_and_loads_tombstones(self):
        self.store.async_load.return_value = {"a" * 64: int(time.time()) + 300, "b" * 64: 1}
        config = self.integration.CONFIG_SCHEMA({"ha_access_session": CONFIG})
        self.assertTrue(await self.integration.async_setup(self.hass, config))
        self.hass.auth.async_remove_refresh_token.assert_called_once_with(self.managed)
        view = self.hass.http.register_view.call_args.args[0]
        self.assertEqual(list(view.tombstones), ["a" * 64])
        self.assertIs(view.persist, self.store.async_save)

    async def test_disabled_or_corrupt_configuration_never_registers_a_view(self):
        self.assertTrue(await self.integration.async_setup(self.hass, {}))
        for bad in ([], {"invalid-hash": 42}, {"a" * 64: True}):
            self.store.async_load.return_value = bad
            with self.assertRaises(ValueError):
                await self.integration.async_setup(self.hass, {"ha_access_session": CONFIG})
        self.hass.http.register_view.assert_not_called()
        with self.assertRaises(self.integration.vol.Invalid):
            self.integration.CONFIG_SCHEMA({"ha_access_session": {**CONFIG, "user_id": "bad"}})


if __name__ == "__main__":
    unittest.main()
