import uuid
from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class UserModel(Base):
    __tablename__ = "tbl_usuarios"

    # ID entero interno para optimización de la BD
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Identificador público expuesto a la red (Patrón Anti-enumeración)
    uuid = Column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        unique=True,
        index=True,
        nullable=False
    )

    # Campo de negocio indexado y único (cumplimiento del protocolo de Proteccion PII)
    cedula = Column(String, unique=True, index=True, nullable=False)

    name = Column(String, nullable=False)
    last_name = Column(String, nullable=True)
    phone_number = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_psswd = Column(String, nullable=False)
    rol = Column(String, default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
