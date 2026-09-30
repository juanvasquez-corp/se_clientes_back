import asyncio
from unittest.mock import patch

import jwt
from redis.asyncio import Redis

from repositories.sessions import RedisSessionStore
from services.auth import AuthService
from services.errors import (
    AuthenticationError,
    PermissionDenied,
    RateLimited,
    StorageUnavailable,
)
from tests.support import IntegrationCase, PASSWORD


class AuthenticationTests(IntegrationCase):
    async def test_concurrent_logins_leave_only_one_session(self):
        user = await self.account("master")
        pairs = await asyncio.gather(self.login(user), self.login(user))
        results = await asyncio.gather(
            *(self.principal(pair) for pair in pairs), return_exceptions=True
        )
        self.assertEqual(sum(not isinstance(r, Exception) for r in results), 1)
        self.assertEqual(
            sum(isinstance(r, AuthenticationError) for r in results), 1
        )

    async def test_failed_login_preserves_current_session(self):
        user = await self.account()
        pair = await self.login(user)
        with self.assertRaises(AuthenticationError):
            await self.login(user, "wrong-password")
        await self.principal(pair)

    async def test_refresh_keeps_absolute_deadline_and_detects_reuse(self):
        user = await self.account()
        first = await self.login(user)
        async with self.services() as (auth, _, _):
            second = await auth.refresh(first.refresh_token, first.csrf_token)
        self.assertEqual(first.session_expires_at, second.session_expires_at)
        self.assertNotEqual(first.refresh_token, second.refresh_token)
        await self.principal(second)
        snapshot = await self.sessions.get(user.uuid)
        with self.assertRaises(AuthenticationError):
            async with self.services() as (auth, _, _):
                await auth.refresh(first.refresh_token, first.csrf_token)
        # Restaurar Redis no debe resucitar una sesión revocada en PostgreSQL.
        await self.sessions.replace(user.uuid, snapshot)
        with self.assertRaises(AuthenticationError):
            await self.principal(second)

    async def test_refresh_near_deadline_caps_access_and_expires_session(self):
        user = await self.account()
        pair = await self.login(user)
        with patch(
            "services.auth.time.time",
            return_value=pair.session_expires_at - 20,
        ):
            async with self.services() as (auth, _, _):
                renewed = await auth.refresh(
                    pair.refresh_token, pair.csrf_token
                )
            self.assertEqual(renewed.expires_in, 20)
            payload = jwt.decode(
                renewed.access_token, options={"verify_signature": False}
            )
            self.assertEqual(payload["exp"], pair.session_expires_at)
        with patch(
            "services.auth.time.time", return_value=pair.session_expires_at + 1
        ):
            with self.assertRaises(AuthenticationError):
                async with self.services() as (auth, _, _):
                    await auth.refresh(pair.refresh_token, pair.csrf_token)

    async def test_csrf_and_token_purpose_are_enforced(self):
        user = await self.account()
        pair = await self.login(user)
        for csrf in (None, "wrong", "inválido"):
            with self.subTest(csrf=csrf):
                with self.assertRaises(PermissionDenied):
                    async with self.services() as (auth, _, _):
                        await auth.refresh(pair.refresh_token, csrf)
        await self.principal(pair)
        with self.assertRaises(AuthenticationError):
            async with self.services() as (auth, _, _):
                await auth.authenticate(pair.refresh_token)

    async def test_logout_revokes_immediately_and_persistently(self):
        user = await self.account()
        pair = await self.login(user)
        snapshot = await self.sessions.get(user.uuid)
        async with self.services() as (auth, _, _):
            await auth.logout(pair.refresh_token, pair.csrf_token)
        self.assertIsNone(await self.sessions.get(user.uuid))
        await self.sessions.replace(user.uuid, snapshot)
        with self.assertRaises(AuthenticationError):
            await self.principal(pair)

    async def test_redis_failure_does_not_bypass_authentication(self):
        user = await self.account()
        pair = await self.login(user)
        client = Redis(port=1, socket_connect_timeout=0.1, socket_timeout=0.1)
        try:
            async with self.services() as (_, _, repository):
                auth = AuthService(
                    repository, RedisSessionStore(client), self.crypto
                )
                with self.assertRaises(StorageUnavailable):
                    await auth.authenticate(pair.access_token)
        finally:
            await client.aclose()

    async def test_login_throttle_is_shared_and_bounded(self):
        user = await self.account()
        for _ in range(10):
            with self.assertRaises(AuthenticationError):
                await self.login(user, "incorrect")
        with self.assertRaises(RateLimited):
            await self.login(user, PASSWORD)

    async def test_concurrent_refresh_compare_and_swap(self):
        user = await self.account()
        await self.login(user)
        session = await self.sessions.get(user.uuid)
        results = await asyncio.gather(*(
            self.sessions.rotate(
                user.uuid, session.session_id, session.refresh_digest,
                f"synthetic-next-{index}",
            )
            for index in range(2)
        ))
        self.assertEqual(sorted(results), [False, True])
        self.assertIsNone(await self.sessions.get(user.uuid))
