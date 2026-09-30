import secrets
import time
from dataclasses import dataclass, field
from uuid import uuid4

from security import token_digest
from services.contracts import (
    AuthenticationRepository,
    Principal,
    SessionRecord,
    SessionStore,
    TokenClaims,
    TokenSecurity,
    UserAccount,
)
from services.errors import AuthenticationError, PermissionDenied, RateLimited


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_in: int
    session_expires_at: int


class AuthService:
    def __init__(
        self, repository: AuthenticationRepository, sessions: SessionStore,
        security: TokenSecurity, access_seconds: int = 120,
        session_seconds: int = 86400,
    ):
        self.repository = repository
        self.sessions = sessions
        self.security = security
        self.access_seconds = access_seconds
        self.session_seconds = session_seconds

    def _pair(
        self, user: UserAccount, session: SessionRecord, refresh: str
    ) -> TokenPair:
        now = int(time.time())
        expires_at = min(now + self.access_seconds, session.expires_at)
        if expires_at <= now:
            raise AuthenticationError()
        access = self.security.issue_token(
            user.uuid, session.session_id, user.auth_version,
            "access", expires_at,
        )
        return TokenPair(
            access, refresh, session.csrf_token,
            expires_at - now, session.expires_at,
        )

    async def login(
        self, email: str, password: str, client_address: str
    ) -> TokenPair:
        email = email.strip().lower()
        allowed = await self.sessions.allow_login(
            token_digest(email), token_digest(client_address)
        )
        if not allowed:
            raise RateLimited()
        candidate = await self.repository.find_email(email)
        if candidate is None:
            await self.security.dummy_verify(password)
            raise AuthenticationError("Credenciales incorrectas")
        verified = await self.security.verify_password(
            candidate.hashed_psswd, password
        )
        if not verified:
            raise AuthenticationError("Credenciales incorrectas")

        # Serializa login, refresh y logout incluso entre workers diferentes.
        user = await self.repository.get(candidate.uuid, lock=True)
        if user is None or not user.is_active or user.is_deleted:
            raise AuthenticationError("Credenciales incorrectas")
        if user.hashed_psswd != candidate.hashed_psswd:
            if not await self.security.verify_password(
                user.hashed_psswd, password
            ):
                raise AuthenticationError("Credenciales incorrectas")
        if self.security.needs_rehash(user.hashed_psswd):
            user.hashed_psswd = await self.security.hash_password(password)
        user.auth_version += 1
        await self.repository.save(user)
        expires_at = int(time.time()) + self.session_seconds
        session_id = str(uuid4())
        refresh = self.security.issue_token(
            user.uuid, session_id, user.auth_version, "refresh", expires_at
        )
        session = SessionRecord(
            session_id, token_digest(refresh), secrets.token_urlsafe(32),
            expires_at, user.auth_version,
        )
        await self.sessions.replace(user.uuid, session)
        await self.repository.audit(user.uuid, user.uuid, "auth.login", [])
        await self.repository.commit()
        return self._pair(user, session, refresh)

    async def _validate(
        self, claims: TokenClaims, *, lock: bool = False
    ) -> tuple[UserAccount, SessionRecord]:
        user = await self.repository.get(claims.user_uuid, lock=lock)
        if (
            user is None or user.is_deleted or not user.is_active
            or user.auth_version != claims.auth_version
        ):
            raise AuthenticationError()
        session = await self.sessions.get(user.uuid)
        if (
            session is None or session.session_id != claims.session_id
            or session.auth_version != user.auth_version
            or session.expires_at <= int(time.time())
            or claims.expires_at > session.expires_at
        ):
            raise AuthenticationError()
        return user, session

    async def authenticate(self, token: str) -> Principal:
        claims = self.security.decode_token(token, "access")
        await self._validate(claims)
        return Principal(
            claims.user_uuid, claims.session_id, claims.auth_version
        )

    @staticmethod
    def _check_csrf(session: SessionRecord, csrf_token: str | None) -> None:
        if (
            not csrf_token
            or not csrf_token.isascii()
            or not secrets.compare_digest(session.csrf_token, csrf_token)
        ):
            raise PermissionDenied("Verificación CSRF fallida")

    async def refresh(self, token: str, csrf_token: str | None) -> TokenPair:
        claims = self.security.decode_token(token, "refresh")
        user, session = await self._validate(claims, lock=True)
        self._check_csrf(session, csrf_token)
        refresh = self.security.issue_token(
            user.uuid, session.session_id, user.auth_version,
            "refresh", session.expires_at,
        )
        if not await self.sessions.rotate(
            user.uuid, session.session_id,
            token_digest(token), token_digest(refresh),
        ):
            # Restaurar un respaldo de Redis no revive la sesión revocada.
            user.auth_version += 1
            await self.repository.save(user)
            await self.repository.audit(
                user.uuid, user.uuid, "auth.session_invalidated", []
            )
            await self.repository.commit()
            raise AuthenticationError()
        await self.repository.commit()
        return self._pair(user, session, refresh)

    async def csrf(self, token: str) -> str:
        claims = self.security.decode_token(token, "refresh")
        _, session = await self._validate(claims)
        if not secrets.compare_digest(
            session.refresh_digest, token_digest(token)
        ):
            raise AuthenticationError()
        return session.csrf_token

    async def logout(self, token: str, csrf_token: str | None) -> None:
        claims = self.security.decode_token(token, "refresh")
        user, session = await self._validate(claims, lock=True)
        self._check_csrf(session, csrf_token)
        user.auth_version += 1
        await self.repository.save(user)
        await self.sessions.revoke(user.uuid)
        await self.repository.audit(user.uuid, user.uuid, "auth.logout", [])
        await self.repository.commit()
