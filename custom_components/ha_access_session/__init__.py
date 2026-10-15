"""YAML setup for the HA Access Session beta integration."""

import re
import time

import voluptuous as vol
from homeassistant.helpers.storage import Store

from .access import AccessConfig, AccessSessions

DOMAIN = "ha_access_session"


def validated_config(value):
    try:
        config = AccessConfig(**value)
    except (TypeError, ValueError) as error:
        raise vol.Invalid(str(error)) from error
    return config


CONFIG_SCHEMA = vol.Schema({vol.Optional(DOMAIN): validated_config}, extra=vol.ALLOW_EXTRA)


async def async_setup(hass, config):
    if DOMAIN not in config:
        return True
    settings = config[DOMAIN]
    if not isinstance(settings, AccessConfig):
        settings = validated_config(settings)
    store = Store(hass, 1, DOMAIN + ".used_assertions")
    data = await store.async_load()
    if data is not None and not isinstance(data, dict):
        raise ValueError("Invalid session store")
    tombstones = {}
    for key, expires in (data or {}).items():
        if not re.fullmatch(r"[0-9a-f]{64}", key) or type(expires) is not int:
            raise ValueError("Invalid session store")
        if expires > int(time.time()):
            tombstones[key] = expires
    # Existing managed refresh tokens cannot survive a process restart. The
    # persisted used-assertion hashes prohibit replay of those old assertions.
    for user in await hass.auth.async_get_users():
        for token in list(user.refresh_tokens.values()):
            if token.client_id == settings.client_id:
                hass.auth.async_remove_refresh_token(token)
    view = AccessSessions(hass, settings, persist=store.async_save, tombstones=tombstones)
    hass.http.register_view(view)
    hass.data[DOMAIN] = view
    return True
