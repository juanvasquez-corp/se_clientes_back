from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class UserModel(Base):
    __tablename__ = "tbl_usuarios"
    __table_args__ = (
        CheckConstraint(
            "rol IN ('superadmin', 'master', 'visualizer')",
            name="ck_users_role",
        ),
        CheckConstraint(
            "cedula ~ '^[0-9]{1,20}$'", name="ck_users_cedula"
        ),
        CheckConstraint(
            "NOT is_deleted OR NOT is_active", name="ck_users_deleted_state"
        ),
        CheckConstraint("auth_version >= 0", name="ck_users_auth_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    uuid: Mapped[UUID] = mapped_column(
        default=uuid4, unique=True, index=True
    )
    cedula: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    last_name: Mapped[str | None] = mapped_column(String)
    phone_number: Mapped[str | None] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_psswd: Mapped[str] = mapped_column(String)
    rol: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_deleted: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    auth_version: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0")
    )
    # Los registros previos a la migración no tienen una fecha reconstruible.
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


# Incluye eliminados: las identidades siguen reservadas después del borrado.
Index("uq_users_email_normalized", func.lower(UserModel.email), unique=True)
