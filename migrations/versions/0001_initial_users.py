"""Representa el esquema original, antes de sesiones y borrado lógico."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tbl_usuarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cedula", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("last_name", sa.String(), nullable=True),
        sa.Column("phone_number", sa.String(), nullable=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("hashed_psswd", sa.String(), nullable=False),
        sa.Column("rol", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_tbl_usuarios_id", "tbl_usuarios", ["id"])
    for column in ("uuid", "cedula", "email"):
        op.create_index(
            f"ix_tbl_usuarios_{column}", "tbl_usuarios", [column], unique=True
        )


def downgrade() -> None:
    op.drop_table("tbl_usuarios")
