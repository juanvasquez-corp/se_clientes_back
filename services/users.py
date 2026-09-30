from datetime import datetime, timezone
from uuid import UUID, uuid4

from services.contracts import (
    PasswordHashing,
    Principal,
    UserAccount,
    UserRepository,
)
from services.errors import (
    AuthenticationError,
    Conflict,
    NotFound,
    PermissionDenied,
)

PROFILE_FIELDS = frozenset({"name", "last_name", "phone_number", "email"})
ADMIN_FIELDS = PROFILE_FIELDS | {"cedula", "rol"}


class UserService:
    def __init__(self, repository: UserRepository, security: PasswordHashing):
        self.repository = repository
        self.security = security

    async def _actor(
        self, principal: Principal, *, admin: bool = False, lock: bool = False
    ) -> UserAccount:
        actor = await self.repository.get(principal.user_uuid, lock=lock)
        if (
            actor is None or actor.is_deleted or not actor.is_active
            or actor.auth_version != principal.auth_version
        ):
            raise AuthenticationError()
        if admin and actor.rol != "superadmin":
            raise PermissionDenied()
        return actor

    async def _target(self, user_uuid: UUID) -> UserAccount:
        user = await self.repository.get(user_uuid, lock=True)
        if user is None or user.is_deleted:
            raise NotFound()
        return user

    async def _protect_last_admin(self, user: UserAccount) -> None:
        if user.rol == "superadmin" and user.is_active:
            if await self.repository.count_admins() <= 1:
                raise Conflict("Debe permanecer un superadmin activo")

    async def read(self, principal: Principal, user_uuid: UUID) -> UserAccount:
        actor = await self._actor(principal)
        if actor.uuid != user_uuid and actor.rol != "superadmin":
            raise PermissionDenied()
        user = await self.repository.get(user_uuid)
        if user is None or user.is_deleted:
            raise NotFound()
        return user

    async def search(self, principal: Principal, email: str) -> UserAccount:
        await self._actor(principal, admin=True)
        user = await self.repository.find_email(email)
        if user is None or user.is_deleted:
            raise NotFound()
        return user

    async def list_users(
        self, principal: Principal, page: int, size: int
    ) -> tuple[int, list[UserAccount]]:
        await self._actor(principal, admin=True)
        return await self.repository.list_users(page, size)

    async def create(
        self, principal: Principal, attributes: dict, password: str
    ) -> UserAccount:
        await self._actor(principal, admin=True)
        hashed = await self.security.hash_password(password)
        await self.repository.lock_administration()
        actor = await self._actor(principal, admin=True, lock=True)
        user = UserAccount(
            uuid=uuid4(), hashed_psswd=hashed, **attributes
        )
        await self.repository.create(user)
        await self.repository.audit(
            actor.uuid, user.uuid, "user.created", sorted(attributes)
        )
        await self.repository.commit()
        return user

    async def update(
        self, principal: Principal, user_uuid: UUID,
        changes: dict, *, administrative: bool = False,
    ) -> UserAccount:
        await self.repository.lock_administration()
        actor = await self._actor(
            principal, admin=administrative, lock=True
        )
        if not administrative:
            if (
                actor.uuid != user_uuid
                or actor.rol not in {"master", "superadmin"}
            ):
                raise PermissionDenied()
        permitted = ADMIN_FIELDS if administrative else PROFILE_FIELDS
        if changes.keys() - permitted:
            raise PermissionDenied("El perfil contiene campos no editables")
        user = await self._target(user_uuid)
        if "rol" in changes and changes["rol"] != user.rol:
            if actor.uuid == user.uuid:
                raise PermissionDenied("No puedes cambiar tu propio rol")
            await self._protect_last_admin(user)
            user.auth_version += 1
        modified = [
            name for name, value in changes.items()
            if getattr(user, name) != value
        ]
        for name in modified:
            setattr(user, name, changes[name])
        if modified:
            user.updated_at = datetime.now(timezone.utc)
            await self.repository.save(user)
            await self.repository.audit(
                actor.uuid, user.uuid, "user.updated", sorted(modified)
            )
        await self.repository.commit()
        return user

    async def set_status(
        self, principal: Principal, user_uuid: UUID, is_active: bool
    ) -> None:
        await self.repository.lock_administration()
        actor = await self._actor(principal, admin=True, lock=True)
        user = await self._target(user_uuid)
        if not is_active:
            if actor.uuid == user.uuid:
                raise PermissionDenied("No puedes desactivar tu propia cuenta")
            await self._protect_last_admin(user)
        if user.is_active != is_active:
            user.is_active = is_active
            user.auth_version += 1
            user.updated_at = datetime.now(timezone.utc)
            await self.repository.save(user)
            await self.repository.audit(
                actor.uuid, user.uuid, "user.status_changed", ["is_active"]
            )
        await self.repository.commit()

    async def delete(self, principal: Principal, user_uuid: UUID) -> None:
        await self.repository.lock_administration()
        actor = await self._actor(principal, admin=True, lock=True)
        if actor.uuid == user_uuid:
            raise PermissionDenied("No puedes eliminar tu propia cuenta")
        user = await self._target(user_uuid)
        await self._protect_last_admin(user)
        user.is_deleted = True
        user.is_active = False
        user.auth_version += 1
        user.deleted_at = user.updated_at = datetime.now(timezone.utc)
        await self.repository.save(user)
        await self.repository.audit(
            actor.uuid, user.uuid, "user.deleted", ["is_deleted", "is_active"]
        )
        # La versión persistida invalida JWT aunque Redis conserve la entrada.
        await self.repository.commit()

    async def bootstrap(self, password: str | None) -> None:
        await self.repository.lock_administration()
        if await self.repository.has_users():
            await self.repository.commit()
            return
        if password is None or not 15 <= len(password) <= 128:
            raise RuntimeError(
                "Configura BOOTSTRAP_ADMIN_PASSWORD con 15 a 128 caracteres"
            )
        user = UserAccount(
            uuid=uuid4(), cedula="1234567890", name="admin",
            last_name="system", email="superadmin.system@aliar.com",
            hashed_psswd=await self.security.hash_password(password),
            rol="superadmin",
        )
        await self.repository.create(user)
        await self.repository.audit(None, user.uuid, "user.bootstrapped", [])
        await self.repository.commit()
