from uuid import uuid4

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from database import Base
from tests.support import IntegrationCase


class MigrationTests(IntegrationCase):
    revision = "0001"

    async def legacy_user(self, email, cedula, role="master"):
        async with self.engine.begin() as connection:
            await connection.execute(text("""
                INSERT INTO tbl_usuarios
                    (uuid, cedula, name, email, hashed_psswd, rol, is_active)
                VALUES (:uuid, :cedula, 'Test', :email, 'unused', :role, true)
            """), {
                "uuid": uuid4(), "cedula": cedula,
                "email": email, "role": role,
            })

    async def test_upgrade_matches_models_and_preserves_legacy_history(self):
        await self.legacy_user("UPPER@example.com", "001")
        await self.upgrade()
        async with self.engine.connect() as connection:
            result = (await connection.execute(text("""
                SELECT email, cedula, is_deleted, auth_version, created_at
                FROM tbl_usuarios
            """))).one()
            self.assertEqual(
                tuple(result), ("upper@example.com", "001", False, 0, None)
            )
            differences = await connection.run_sync(
                lambda conn: compare_metadata(
                    MigrationContext.configure(conn), Base.metadata
                )
            )
        self.assertEqual(differences, [])

    async def test_case_collisions_abort_without_partial_schema_changes(self):
        await self.legacy_user("SAME@example.com", "1")
        await self.legacy_user("same@example.com", "2")
        with self.assertRaises(DBAPIError):
            await self.upgrade()
        async with self.engine.connect() as connection:
            columns = await connection.run_sync(
                lambda conn: inspect(conn).get_columns("tbl_usuarios")
            )
            version = await connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
        self.assertNotIn("is_deleted", {column["name"] for column in columns})
        self.assertEqual(version, "0001")

    async def test_unknown_legacy_roles_are_not_silently_promoted(self):
        await self.legacy_user("legacy@example.com", "1", "user")
        with self.assertRaises(DBAPIError):
            await self.upgrade()
