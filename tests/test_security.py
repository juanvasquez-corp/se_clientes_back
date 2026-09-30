import time
import unittest
from uuid import uuid4

import jwt
from pydantic import ValidationError

from schemas.user import UserRegister, UserResponse, UserUpdate
from security import Security
from services.contracts import UserAccount
from services.errors import AuthenticationError
from tests.support import PASSWORD, test_settings


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = test_settings()
        self.security = Security(self.config)

    async def test_password_uses_random_salt_and_pepper(self):
        first = await self.security.hash_password(PASSWORD)
        second = await self.security.hash_password(PASSWORD)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("$argon2id$"))
        self.assertTrue(await self.security.verify_password(first, PASSWORD))
        self.assertFalse(
            await self.security.verify_password(first, "incorrect")
        )
        changed = Security(test_settings(PEPPER="different-pepper-" * 3))
        self.assertFalse(await changed.verify_password(first, PASSWORD))

    async def test_jwt_rejects_missing_or_invalid_claims(self):
        valid = self.security.issue_token(
            uuid4(), str(uuid4()), 1, "access", int(time.time()) + 120
        )
        payload = jwt.decode(valid, options={"verify_signature": False})
        self.security.decode_token(valid, "access")
        for claim in payload:
            with self.subTest(missing=claim):
                incomplete = dict(payload)
                incomplete.pop(claim)
                token = jwt.encode(
                    incomplete, self.config.SECRET_KEY.get_secret_value(),
                    algorithm="HS256",
                )
                with self.assertRaises(AuthenticationError):
                    self.security.decode_token(token, "access")
        for changes in (
            {"iss": "wrong"}, {"aud": "wrong"}, {"sub": "not-a-uuid"},
            {"sid": 42}, {"jti": None}, {"ver": True},
            {"token_type": "refresh"}, {"exp": int(time.time()) - 1},
            {"exp": int(time.time()) + 3600},
        ):
            with self.subTest(changes=changes):
                token = jwt.encode(
                    payload | changes,
                    self.config.SECRET_KEY.get_secret_value(),
                    algorithm="HS256",
                )
                with self.assertRaises(AuthenticationError):
                    self.security.decode_token(token, "access")
        for algorithm in ("none", "HS384"):
            token = jwt.encode(
                payload,
                None if algorithm == "none" else "another-signing-key-" * 4,
                algorithm=algorithm,
            )
            with self.assertRaises(AuthenticationError):
                self.security.decode_token(token, "access")


class SchemaTests(unittest.TestCase):
    def test_identity_validation_and_optional_fields(self):
        attributes = {
            "name": "Test", "email": "TEST@example.com",
            "psswd": PASSWORD, "rol": "master",
        }
        for cedula in ("0", "0" * 20):
            user = UserRegister(cedula=cedula, **attributes)
            self.assertEqual(user.email, "test@example.com")
            self.assertIsNone(user.phone_number)
            self.assertIsNone(user.last_name)
            self.assertNotIn(PASSWORD, repr(user))
        for cedula in ("", "0" * 21, "12\n", "１２", "abc"):
            with self.subTest(cedula=cedula):
                with self.assertRaises(ValidationError):
                    UserRegister(cedula=cedula, **attributes)
        for changes in ({"rol": "user"}, {"psswd": ""}, {"is_active": True}):
            with self.assertRaises(ValidationError):
                UserRegister(cedula="1", **(attributes | changes))

    def test_output_and_mass_assignment(self):
        user = UserAccount(
            uuid=uuid4(), cedula="12345", name="Test",
            email="test@example.com", hashed_psswd="private-hash",
            rol="master",
        )
        output = UserResponse.model_validate(user).model_dump()
        self.assertTrue({"id", "cedula", "hashed_psswd"}.isdisjoint(output))
        self.assertNotIn("private-hash", repr(user))
        for field in ("rol", "cedula", "psswd", "is_active", "is_deleted"):
            with self.assertRaises(ValidationError):
                UserUpdate(name="Test", email=user.email, **{field: "value"})

    def test_configuration_rejects_unsafe_combinations(self):
        for values in (
            {"SECRET_KEY": "short"}, {"PEPPER": ""},
            {"ENVIRONMENT": "prodution"},
            {"ACCESS_TOKEN_EXPIRE_MINUTES": 3},
            {"REFRESH_TOKEN_EXPIRE_DAYS": 2},
            {"COOKIE_SAMESITE": "none", "COOKIE_SECURE": False},
            {"FRONTEND_ORIGINS": ["*"]},
            {"FRONTEND_ORIGINS": ["https://example.com/path"]},
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValidationError):
                    test_settings(**values)
