from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AuditModel(Base):
    __tablename__ = "user_audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    actor_uuid: Mapped[UUID | None] = mapped_column(
        ForeignKey("tbl_usuarios.uuid", ondelete="RESTRICT"), index=True
    )
    target_uuid: Mapped[UUID] = mapped_column(
        ForeignKey("tbl_usuarios.uuid", ondelete="RESTRICT"), index=True
    )
    action: Mapped[str] = mapped_column(String(40))
    # Registrar nombres de campos evita copiar datos personales al historial.
    fields: Mapped[list[str]] = mapped_column(JSONB)
