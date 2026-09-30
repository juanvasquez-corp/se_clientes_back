"""Reserva identidades eliminadas y registra cambios administrativos."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Detenerse antes de transformar datos ambiguos; no fusionar identidades.
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (
                SELECT 1 FROM tbl_usuarios
                GROUP BY lower(btrim(email)) HAVING count(*) > 1
            ) THEN
                RAISE EXCEPTION 'Resuelva correos duplicados antes de migrar';
            END IF;
            IF EXISTS (
                SELECT 1 FROM tbl_usuarios
                WHERE rol NOT IN ('superadmin', 'master', 'visualizer')
                   OR cedula !~ '^[0-9]{1,20}$'
            ) THEN
                RAISE EXCEPTION 'Revise roles y cedulas antes de migrar';
            END IF;
        END $$;
    """)
    op.execute("UPDATE tbl_usuarios SET email = lower(btrim(email))")
    op.add_column(
        "tbl_usuarios",
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "tbl_usuarios",
        sa.Column(
            "auth_version", sa.Integer(), nullable=False,
            server_default=sa.text("0"),
        ),
    )
    for column in ("created_at", "updated_at", "deleted_at"):
        op.add_column(
            "tbl_usuarios",
            sa.Column(column, sa.DateTime(timezone=True), nullable=True),
        )
    # El valor predeterminado solo aplica a nuevas filas, no inventa historia.
    op.alter_column("tbl_usuarios", "created_at", server_default=sa.func.now())
    constraints = {
        "ck_users_role": "rol IN ('superadmin', 'master', 'visualizer')",
        "ck_users_cedula": "cedula ~ '^[0-9]{1,20}$'",
        "ck_users_deleted_state": "NOT is_deleted OR NOT is_active",
        "ck_users_auth_version": "auth_version >= 0",
    }
    for name, condition in constraints.items():
        op.create_check_constraint(name, "tbl_usuarios", condition)
    op.create_index(
        "uq_users_email_normalized", "tbl_usuarios",
        [sa.text("lower(email)")], unique=True,
    )
    op.create_table(
        "user_audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "actor_uuid", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tbl_usuarios.uuid", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "target_uuid", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tbl_usuarios.uuid", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("fields", postgresql.JSONB(), nullable=False),
    )
    for column in ("occurred_at", "actor_uuid", "target_uuid"):
        op.create_index(
            f"ix_user_audit_events_{column}", "user_audit_events", [column]
        )


def downgrade() -> None:
    # Revertir restauraría cuentas eliminadas y descartaría su historial.
    raise RuntimeError(
        "Esta migración requiere una reversión de datos planificada"
    )
