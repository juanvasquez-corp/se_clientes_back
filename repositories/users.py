from dataclasses import asdict, fields
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models.audit import AuditModel
from models.user import UserModel
from services.contracts import UserAccount
from services.errors import Conflict

# Todas las operaciones administrativas comparten este bloqueo transaccional.
ADMINISTRATION_LOCK = 748213091


class SqlAlchemyUserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session
        self._loaded: dict[UUID, UserModel] = {}

    def _account(self, model: UserModel) -> UserAccount:
        self._loaded[model.uuid] = model
        return UserAccount(**{
            field.name: getattr(model, field.name)
            for field in fields(UserAccount)
        })

    async def get(
        self, user_uuid: UUID, *, lock: bool = False
    ) -> UserAccount | None:
        statement = select(UserModel).where(UserModel.uuid == user_uuid)
        if lock:
            statement = statement.with_for_update().execution_options(
                populate_existing=True
            )
        model = (await self.session.execute(statement)).scalar_one_or_none()
        return self._account(model) if model is not None else None

    async def find_email(self, email: str) -> UserAccount | None:
        statement = select(UserModel).where(
            func.lower(UserModel.email) == email.lower()
        )
        model = (await self.session.execute(statement)).scalar_one_or_none()
        return self._account(model) if model is not None else None

    async def lock_administration(self) -> None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": ADMINISTRATION_LOCK},
        )

    async def has_users(self) -> bool:
        result = await self.session.execute(select(UserModel.uuid).limit(1))
        return result.scalar_one_or_none() is not None

    async def count_admins(self) -> int:
        statement = select(func.count()).select_from(UserModel).where(
            UserModel.rol == "superadmin",
            UserModel.is_active.is_(True),
            UserModel.is_deleted.is_(False),
        )
        return (await self.session.execute(statement)).scalar_one()

    async def list_users(
        self, page: int, size: int
    ) -> tuple[int, list[UserAccount]]:
        visible = UserModel.is_deleted.is_(False)
        count = await self.session.execute(
            select(func.count()).select_from(UserModel).where(visible)
        )
        total = count.scalar_one()
        rows = await self.session.execute(
            select(UserModel).where(visible).order_by(UserModel.id)
            .offset((page - 1) * size).limit(size)
        )
        return total, [self._account(row) for row in rows.scalars()]

    async def create(self, user: UserAccount) -> None:
        model = UserModel(**asdict(user))
        self.session.add(model)
        try:
            # Materializa la identidad antes del evento con FK a ese usuario.
            await self.session.flush()
        except IntegrityError as error:
            await self.rollback()
            raise Conflict(
                "El correo o la cédula ya están reservados"
            ) from error
        self._loaded[user.uuid] = model
        user.created_at = model.created_at

    async def save(self, user: UserAccount) -> None:
        model = self._loaded[user.uuid]
        for name, value in asdict(user).items():
            setattr(model, name, value)

    async def audit(
        self,
        actor: UUID | None,
        target: UUID,
        action: str,
        fields: list[str],
    ) -> None:
        self.session.add(AuditModel(
            actor_uuid=actor,
            target_uuid=target,
            action=action,
            fields=fields,
        ))

    async def commit(self) -> None:
        try:
            await self.session.commit()
        except IntegrityError as error:
            await self.rollback()
            raise Conflict(
                "El correo o la cédula ya están reservados"
            ) from error

    async def rollback(self) -> None:
        await self.session.rollback()
