import hashlib
import secrets
import time
from uuid import UUID, uuid4

import anyio
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from starlette.concurrency import run_in_threadpool

from config import Settings
from services.contracts import TokenClaims, TokenType
from services.errors import AuthenticationError, StorageUnavailable

ALGORITHM = "HS256"


class Security:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.hasher = PasswordHasher(
            memory_cost=12288, time_cost=3, parallelism=1
        )
        self._hash_limiter = anyio.CapacityLimiter(4)
        self._dummy_hash: str | None = None

    def _password_bytes(self, password: str) -> bytes:
        pepper = self.settings.PEPPER.get_secret_value()
        return f"{password}{pepper}".encode("utf-8")

    async def hash_password(self, password: str) -> str:
        async with self._hash_limiter:
            return await run_in_threadpool(
                self.hasher.hash, self._password_bytes(password)
            )

    async def verify_password(self, hashed: str, password: str) -> bool:
        try:
            async with self._hash_limiter:
                return await run_in_threadpool(
                    self.hasher.verify, hashed, self._password_bytes(password)
                )
        except VerifyMismatchError:
            return False
        except (InvalidHashError, VerificationError) as error:
            raise StorageUnavailable() from error

    async def dummy_verify(self, password: str) -> None:
        # El caso sin cuenta también paga el costo de verificar Argon2.
        if self._dummy_hash is None:
            self._dummy_hash = await self.hash_password(
                secrets.token_urlsafe(32)
            )
        await self.verify_password(self._dummy_hash, password)

    def needs_rehash(self, hashed: str) -> bool:
        return self.hasher.check_needs_rehash(hashed)

    def issue_token(
        self,
        user_uuid: UUID,
        session_id: str,
        version: int,
        token_type: TokenType,
        expires_at: int,
    ) -> str:
        payload = {
            "sub": str(user_uuid),
            "sid": session_id,
            "ver": version,
            "jti": str(uuid4()),
            "token_type": token_type,
            "iss": self.settings.JWT_ISSUER,
            "aud": self.settings.JWT_AUDIENCE,
            "iat": int(time.time()),
            "exp": expires_at,
        }
        return jwt.encode(
            payload,
            self.settings.SECRET_KEY.get_secret_value(),
            algorithm=ALGORITHM,
        )

    def decode_token(self, token: str, token_type: TokenType) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self.settings.SECRET_KEY.get_secret_value(),
                algorithms=[ALGORITHM],
                issuer=self.settings.JWT_ISSUER,
                audience=self.settings.JWT_AUDIENCE,
                options={
                    "require": [
                        "sub", "sid", "ver", "jti", "token_type",
                        "iss", "aud", "iat", "exp",
                    ],
                    "strict_aud": True,
                },
            )
            if payload["token_type"] != token_type:
                raise ValueError("Propósito incorrecto")
            for field in ("ver", "iat", "exp"):
                if type(payload[field]) is not int or payload[field] < 0:
                    raise ValueError("Claim numérico inválido")
            lifetime = payload["exp"] - payload["iat"]
            maximum = 120 if token_type == "access" else 86400
            if not 0 < lifetime <= maximum:
                raise ValueError("Duración inválida")
            if any(
                not isinstance(payload[name], str)
                for name in ("sub", "sid", "jti")
            ):
                raise ValueError("Identificador inválido")
            UUID(payload["jti"])
            UUID(payload["sid"])
            return TokenClaims(
                user_uuid=UUID(payload["sub"]),
                session_id=payload["sid"],
                auth_version=payload["ver"],
                expires_at=payload["exp"],
                issued_at=payload["iat"],
            )
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
            raise AuthenticationError() from error


def token_digest(token: str) -> str:
    # Los tokens son aleatorios; este resumen no se usa para contraseñas.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
