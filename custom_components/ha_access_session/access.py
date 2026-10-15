"""Version 1 signed Access assertion -> bounded Home Assistant session contract."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
import json
import re
import time
from urllib.parse import urlsplit

from aiohttp import ClientError, ClientTimeout, web
import jwt
from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_call_later

HEADER = "Cf-Access-Jwt-Assertion"
SESSION_PATH = "/api/ha_access_session/v1/session"
CONTRACT_VERSION = 1


def https_origin(value):
    """Require a literal HTTPS origin, with no path or URL-selected credentials."""
    if not isinstance(value, str) or any(c.isspace() for c in value):
        raise ValueError("Expected an HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or any(c in value for c in "\\?#")
        or parsed.port == 0
    ):
        raise ValueError("Expected an HTTPS origin without a trailing slash")
    return value


@dataclass(frozen=True)
class AccessConfig:
    """Explicit single-account mapping; callers never supply an account ID."""

    issuer: str
    origin: str
    audience: str
    email: str
    user_id: str
    allow_trusted_network: bool = False
    token_lifetime_seconds: int = 300
    max_assertion_lifetime_seconds: int = 86400
    max_sessions: int = 32

    def __post_init__(self):
        https_origin(self.issuer)
        https_origin(self.origin)
        if (
            not isinstance(self.audience, str)
            or not 1 <= len(self.audience) <= 256
            or any(c.isspace() for c in self.audience)
        ):
            raise ValueError("Invalid audience")
        if (
            not isinstance(self.email, str)
            or not re.fullmatch(r"[^\s@]+@[^\s@]+", self.email)
            or len(self.email) > 254
        ):
            raise ValueError("Invalid mapped email")
        if not isinstance(self.user_id, str) or not re.fullmatch(r"[0-9a-f]{32}", self.user_id):
            raise ValueError("Invalid Home Assistant user ID")
        if type(self.allow_trusted_network) is not bool:
            raise ValueError("allow_trusted_network must be a boolean")
        for field, lower, upper in (
            ("token_lifetime_seconds", 1, 300),
            ("max_assertion_lifetime_seconds", 1, 86400),
            ("max_sessions", 1, 128),
        ):
            value = getattr(self, field)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("Invalid " + field)

    @property
    def client_id(self):
        return self.origin + "/ha-access-session/v1"


class AccessSessions(HomeAssistantView):
    """Both standalone integration and thin compatibility adapters use this view.

    persist is an async callable accepting {assertion_sha256: expiry}. Every used
    assertion is durably marked before issuance. On restart these records become
    tombstones, preventing restoration of previously revoked sessions.
    """

    url = SESSION_PATH
    name = "api:ha_access_session:v1"
    requires_auth = False

    def __init__(
        self,
        hass,
        config,
        *,
        persist,
        tombstones=None,
        session_path=SESSION_PATH,
        client_id=None,
        view_name=None,
    ):
        self.hass = hass
        self.config = config if isinstance(config, AccessConfig) else AccessConfig(**config)
        if not re.fullmatch(r"/api/[a-zA-Z0-9_/-]+", session_path) or "//" in session_path:
            raise ValueError("Invalid session path")
        self.url = session_path
        self.name = view_name or self.name
        self.client_id = client_id or self.config.client_id
        if not self.client_id.startswith(self.config.origin + "/"):
            raise ValueError("Client ID must belong to the configured origin")
        self.persist = persist
        self.lock = asyncio.Lock()
        self.keys, self.fetched = {}, 0
        self.sessions = {}
        self.tombstones = dict(tombstones or {})
        self.timers = {}

    async def verify(self, raw):
        # Revocation keys use the compact JWT bytes. Reject aliases (padding or
        # unused base64 bits) so one signed assertion has exactly one key.
        parts = raw.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid compact assertion")
        for part in parts:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", part):
                raise ValueError("Noncanonical assertion")
            decoded = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
            if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != part:
                raise ValueError("Noncanonical assertion")
        header = jwt.get_unverified_header(raw)
        kid = header.get("kid")
        if (
            header.get("alg") != "RS256"
            or not isinstance(kid, str)
            or not 1 <= len(kid) <= 256
            or header.get("crit")
        ):
            raise ValueError("Invalid signing key")
        age = time.monotonic() - self.fetched
        if not self.keys or age > 300 or (kid not in self.keys and age > 30):
            # Configured HTTPS origin only; JWT jku/x5u cannot select a key service.
            async with async_get_clientsession(self.hass).get(
                self.config.issuer + "/cdn-cgi/access/certs",
                timeout=ClientTimeout(total=5),
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise web.HTTPServiceUnavailable(text="Identity verification unavailable")
                raw_keys = bytearray()
                async for chunk in response.content.iter_chunked(8192):
                    raw_keys.extend(chunk)
                    if len(raw_keys) > 65536:
                        raise ValueError("Invalid key set")
            keys = jwt.PyJWKSet.from_dict(json.loads(raw_keys))
            self.keys = {
                key.key_id: key.key
                for key in keys.keys
                if key.algorithm_name == "RS256"
                and key.public_key_use == "sig"
                and getattr(key.key, "key_size", 0) >= 2048
            }
            self.fetched = time.monotonic()
        if kid not in self.keys:
            raise ValueError("Unknown signing key")
        claims = jwt.decode(
            raw,
            self.keys[kid],
            algorithms=["RS256"],
            issuer=self.config.issuer,
            audience=self.config.audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "type"]},
        )
        now = int(time.time())
        if (
            type(claims["exp"]) is not int
            or type(claims["iat"]) is not int
            or claims["iat"] <= 0
            or claims["iat"] > now
            or claims["exp"] <= now
            or not 0 < claims["exp"] - claims["iat"] <= self.config.max_assertion_lifetime_seconds
            or ("nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > now))
        ):
            raise ValueError("Invalid assertion lifetime")
        network = (
            self.config.allow_trusted_network
            and claims["sub"] == ""
            and "email" not in claims
            and "common_name" not in claims
        )
        owner = (
            isinstance(claims["sub"], str)
            and bool(claims["sub"])
            and claims.get("email") == self.config.email
            and "common_name" not in claims
        )
        if claims["type"] != "app" or not (owner or network):
            raise ValueError("Identity is not mapped")
        return claims

    def expire(self, key):
        session = self.sessions.pop(key, None)
        self.timers.pop(key, None)
        if session:
            self.hass.auth.async_remove_refresh_token(session)

    async def _mark_used(self, key, expires):
        now = int(time.time())
        self.tombstones = {k: v for k, v in self.tombstones.items() if v > now}
        self.tombstones[key] = expires
        try:
            await self.persist(dict(self.tombstones))
        except Exception:
            # Failure to persist must never create a usable credential.
            raise web.HTTPServiceUnavailable(text="Session storage unavailable") from None

    async def post(self, request):
        """POST empty body, optionally ?revoke=1. No redirect or account parameters."""
        config = self.config
        if (
            request.host != urlsplit(config.origin).netloc
            or request.headers.getall("Origin", []) != [config.origin]
            or request.headers.get("Sec-Fetch-Site") == "cross-site"
        ):
            raise web.HTTPForbidden()
        if (
            request.method != "POST"
            or request.can_read_body
            or list(request.query.items()) not in ([], [("revoke", "1")])
        ):
            raise web.HTTPBadRequest(text="Expected an empty version 1 session request")
        assertions = request.headers.getall(HEADER, [])
        if len(assertions) != 1 or not 0 < len(assertions[0]) <= 16384:
            raise web.HTTPUnauthorized()
        raw = assertions[0]
        async with self.lock:
            try:
                claims = await self.verify(raw)
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                raise web.HTTPUnauthorized(text="Invalid Access identity") from None
            except (ClientError, OSError, asyncio.TimeoutError):
                raise web.HTTPServiceUnavailable(text="Identity verification unavailable") from None
            key = sha256(raw.encode()).hexdigest()
            session = self.sessions.get(key)
            now = int(time.time())
            if request.query.get("revoke") == "1":
                if (
                    key not in self.tombstones
                    and len([v for v in self.tombstones.values() if v > now]) >= config.max_sessions
                ):
                    raise web.HTTPTooManyRequests()
                await self._mark_used(key, claims["exp"])
                self.expire(key)
                return web.Response(status=204, headers={"Cache-Control": "no-store"})
            if key in self.tombstones and not session:
                raise web.HTTPUnauthorized(text="Session revoked or restarted; sign in again")
            user = await self.hass.auth.async_get_user(config.user_id)
            if (
                not user
                or not user.is_active
                or not user.is_admin
                or user.local_only
                or user.system_generated
            ):
                self.expire(key)
                raise web.HTTPForbidden(text="Mapped Home Assistant account unavailable")
            if not session:
                if len([v for v in self.tombstones.values() if v > now]) >= config.max_sessions:
                    raise web.HTTPTooManyRequests()
                await self._mark_used(key, claims["exp"])
                session = await self.hass.auth.async_create_refresh_token(
                    user,
                    client_id=self.client_id,
                    client_name="HA Access Session",
                    access_token_expiration=timedelta(seconds=config.token_lifetime_seconds),
                )
                self.sessions[key] = session
                self.timers[key] = async_call_later(
                    self.hass,
                    max(0, claims["exp"] - time.time()),
                    lambda _: self.expire(key),
                )
            elif session.id not in user.refresh_tokens:
                self.expire(key)
                raise web.HTTPUnauthorized(text="Session revoked")
            remaining = claims["exp"] - int(time.time())
            if remaining <= 1:
                self.expire(key)
                raise web.HTTPUnauthorized()
            lifetime = min(config.token_lifetime_seconds, remaining - 1)
            session.access_token_expiration = timedelta(seconds=lifetime)
            token = self.hass.auth.async_create_access_token(session)
            return web.json_response(
                {
                    "contract_version": CONTRACT_VERSION,
                    "access_token": token,
                    "expires_in": lifetime,
                    "session_expires_at": claims["exp"],
                },
                headers={"Cache-Control": "no-store"},
            )
