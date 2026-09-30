import json

import httpx

from config import settings
from database import get_db
from dependencies import DatabaseDep, get_auth_service, get_user_service
from main import app
from repositories.users import SqlAlchemyUserRepository
from services.auth import AuthService
from services.users import UserService
from tests.support import IntegrationCase, PASSWORD


class HttpTests(IntegrationCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.origins = list(settings.FRONTEND_ORIGINS)
        self.secure = settings.COOKIE_SECURE
        self.same_site = settings.COOKIE_SAMESITE
        settings.FRONTEND_ORIGINS[:] = ["https://client.example.test"]
        settings.COOKIE_SECURE = True
        settings.COOKIE_SAMESITE = "none"
        app.middleware_stack = None

        async def database_override():
            async with self.factory() as session:
                yield session

        def auth_override(db: DatabaseDep):
            return AuthService(
                SqlAlchemyUserRepository(db), self.sessions, self.crypto
            )

        def users_override(db: DatabaseDep):
            return UserService(SqlAlchemyUserRepository(db), self.crypto)

        app.dependency_overrides[get_db] = database_override
        app.dependency_overrides[get_auth_service] = auth_override
        app.dependency_overrides[get_user_service] = users_override
        self.addCleanup(self.restore_app)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://api.example.test",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://client.example.test",
            },
        )
        self.addAsyncCleanup(self.client.aclose)

    def restore_app(self):
        app.dependency_overrides.clear()
        settings.FRONTEND_ORIGINS[:] = self.origins
        settings.COOKIE_SECURE = self.secure
        settings.COOKIE_SAMESITE = self.same_site
        app.middleware_stack = None

    async def http_login(self, user):
        response = await self.client.post(
            "/api/auth/login", json={"email": user.email, "psswd": PASSWORD}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.client.headers["Authorization"] = (
            f"Bearer {response.json()['access_token']}"
        )
        return response

    async def test_profiles_do_not_expose_private_data(self):
        user = await self.account()
        await self.http_login(user)
        response = await self.client.get("/api/users?page=0&size=100")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["total_records"], 1)
        self.assertEqual(payload["current_page"], 1)
        self.assertEqual(payload["page_size"], 50)
        self.assertTrue(
            {"id", "cedula", "hashed_psswd", "psswd"}.isdisjoint(
                payload["data"][0]
            )
        )
        response = await self.client.put(
            "/api/users/me", json={"name": "Changed", "email": user.email}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["name"], "Changed")
        self.assertIsNone(response.json()["last_name"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    async def test_visualizer_cannot_modify_or_enumerate_accounts(self):
        user = await self.account("visualizer")
        other = await self.account()
        await self.http_login(user)
        profile = await self.client.get("/api/users/me")
        self.assertEqual(profile.status_code, 200)
        for method, path, body in (
            ("GET", "/api/users", None),
            ("GET", f"/api/users/{other.uuid}", None),
            ("PUT", "/api/users/me", {"name": "No", "email": user.email}),
            ("DELETE", f"/api/users/{user.uuid}", None),
        ):
            response = await self.client.request(method, path, json=body)
            self.assertEqual(response.status_code, 403, response.text)

    async def test_cookie_rotation_csrf_and_idempotent_logout(self):
        user = await self.account()
        response = await self.http_login(user)
        cookie = ";".join(response.headers.get_list("set-cookie")).lower()
        self.assertIn("httponly", cookie)
        self.assertIn("secure", cookie)
        self.assertIn("samesite=none", cookie)
        self.assertIn("path=/api/auth", cookie)
        csrf = response.json()["csrf_token"]
        csrf_response = await self.client.get("/api/auth/csrf")
        self.assertEqual(csrf_response.json()["csrf_token"], csrf)
        denied = await self.client.post("/api/auth/refresh")
        self.assertEqual(denied.status_code, 403)
        renewed = await self.client.post(
            "/api/auth/refresh", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(renewed.status_code, 200, renewed.text)
        self.client.headers["Authorization"] = (
            f"Bearer {renewed.json()['access_token']}"
        )
        response = await self.client.post(
            "/api/auth/logout", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.cookies.get("refresh_token"))
        profile = await self.client.get("/api/users/me")
        self.assertEqual(profile.status_code, 401)
        repeated_logout = await self.client.post("/api/auth/logout")
        self.assertEqual(repeated_logout.status_code, 200)

    async def test_login_content_type_and_validation_redact_inputs(self):
        marker = "SENSITIVE_MARKER"
        body = json.dumps({"email": "bad-email", "psswd": marker})
        for content_type in (
            "text/plain", "application/x-www-form-urlencoded"
        ):
            response = await self.client.post(
                "/api/auth/login", content=body,
                headers={"Content-Type": content_type},
            )
            self.assertEqual(response.status_code, 415)
            self.assertNotIn(marker, response.text)
        response = await self.client.post(
            "/api/auth/login", content=body,
            headers={"Content-Type": "Application/JSON; charset=utf-8"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text)
        self.assertNotIn("bad-email", response.text)

    async def test_cors_rejects_untrusted_origins(self):
        for origin, expected in (
            ("https://client.example.test", 200), ("https://evil.example", 400)
        ):
            response = await self.client.options(
                "/api/auth/refresh", headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": (
                        "X-CSRF-Token,X-Requested-With"
                    ),
                },
            )
            self.assertEqual(response.status_code, expected)
        response = await self.client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "psswd": PASSWORD},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(response.status_code, 403)
        response = await self.client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "psswd": PASSWORD},
            headers={"X-Requested-With": ""},
        )
        self.assertEqual(response.status_code, 403)

    async def test_body_limit_applies_without_content_length(self):
        async def chunks():
            yield b'{"psswd":"'
            yield b"x" * (settings.MAX_REQUEST_BYTES + 1)
            yield b'"}'

        response = await self.client.post(
            "/api/auth/login", content=chunks(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 413, response.text)

    async def test_bootstrap_is_serialized_and_requires_a_secret(self):
        async with self.services() as (_, service, _):
            with self.assertRaises(RuntimeError):
                await service.bootstrap(None)
        async with self.services() as (_, service, _):
            await service.bootstrap(PASSWORD)
        async with self.services() as (_, service, repository):
            await service.bootstrap(None)
            self.assertEqual(await repository.count_admins(), 1)
