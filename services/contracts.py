from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

UserRole = Literal["superadmin", "master", "visualizer"]
TokenType = Literal["access", "refresh"]


@dataclass(frozen=True, slots=True)
class TokenClaims:
    user_uuid: UUID
    session_id: str
    auth_version: int
    expires_at: int
    issued_at: int


@dataclass(slots=True)
class UserAccount:
    uuid: UUID
    cedula: str = field(repr=False)
    name: str
    email: str = field(repr=False)
    hashed_psswd: str = field(repr=False)
    rol: UserRole
    last_name: str | None = None
    phone_number: str | None = None
    is_active: bool = True
    is_deleted: bool = False
    auth_version: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None
    deleted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Principal:
    user_uuid: UUID
    session_id: str
    auth_version: int


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    refresh_digest: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_at: int
    auth_version: int


class AccountReader(Protocol):
    async def get(
        self, user_uuid: UUID, *, lock: bool = False
    ) -> UserAccount | None: ...

    async def find_email(self, email: str) -> UserAccount | None: ...


class AuthenticationRepository(AccountReader, Protocol):
    async def save(self, user: UserAccount) -> None: ...

    async def audit(
        self,
        actor: UUID | None,
        target: UUID,
        action: str,
        fields: list[str],
    ) -> None: ...

    async def commit(self) -> None: ...


class UserRepository(AuthenticationRepository, Protocol):
    async def lock_administration(self) -> None: ...

    async def has_users(self) -> bool: ...

    async def count_admins(self) -> int: ...

    async def list_users(
        self, page: int, size: int
    ) -> tuple[int, list[UserAccount]]: ...

    async def create(self, user: UserAccount) -> None: ...

    async def rollback(self) -> None: ...


class SessionStore(Protocol):
    async def replace(
        self, user_uuid: UUID, session: SessionRecord
    ) -> None: ...

    async def get(self, user_uuid: UUID) -> SessionRecord | None: ...

    async def rotate(
        self,
        user_uuid: UUID,
        session_id: str,
        previous_digest: str,
        next_digest: str,
    ) -> bool: ...

    async def revoke(self, user_uuid: UUID) -> None: ...

    async def allow_login(self, account_key: str, client_key: str) -> bool: ...


class PasswordHashing(Protocol):
    async def hash_password(self, password: str) -> str: ...


class PasswordSecurity(PasswordHashing, Protocol):
    async def verify_password(self, hashed: str, password: str) -> bool: ...

    async def dummy_verify(self, password: str) -> None: ...

    def needs_rehash(self, hashed: str) -> bool: ...


class TokenSecurity(PasswordSecurity, Protocol):
    def issue_token(
        self, user_uuid: UUID, session_id: str, version: int,
        token_type: TokenType, expires_at: int,
    ) -> str: ...

    def decode_token(
        self, token: str, token_type: TokenType
    ) -> TokenClaims: ...
