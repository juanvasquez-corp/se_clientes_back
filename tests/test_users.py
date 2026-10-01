import asyncio
from unittest.mock import AsyncMock, patch

from sqlalchemy import select

from models.audit import AuditModel
from services.errors import (
    AuthenticationError,
    Conflict,
    NotFound,
    PermissionDenied,
)
from tests.support import IntegrationCase, PASSWORD


class UserTests(IntegrationCase):
    async def test_master_updates_own_profile_without_changing_email(self):
        user = await self.account("master")
        principal = await self.principal(await self.login(user))
        async with self.services() as (_, service, _):
            updated = await service.update(
                principal, user.uuid,
                {"name": "Updated", "email": user.email, "last_name": None},
            )
        self.assertEqual(updated.name, "Updated")
        async with self.services() as (_, service, _):
            profile = await service.read(principal, user.uuid)
            self.assertEqual(profile.name, "Updated")

    async def test_non_admins_cannot_access_other_accounts_or_privileges(self):
        other = await self.account()
        for role in ("master", "visualizer"):
            user = await self.account(role)
            principal = await self.principal(await self.login(user))
            async with self.services() as (_, service, _):
                profile = await service.read(principal, user.uuid)
                self.assertEqual(profile.uuid, user.uuid)
            operations = (
                lambda service: service.read(principal, other.uuid),
                lambda service: service.search(principal, other.email),
                lambda service: service.list_users(principal, 1, 10),
                lambda service: service.delete(principal, user.uuid),
                lambda service: service.set_status(
                    principal, user.uuid, False
                ),
                lambda service: service.update(
                    principal, user.uuid, {"rol": "superadmin"}
                ),
                lambda service: service.update(
                    principal, user.uuid, {"cedula": "99"}
                ),
            )
            for operation in operations:
                with self.assertRaises(PermissionDenied):
                    async with self.services() as (_, service, _):
                        await operation(service)
            if role == "visualizer":
                with self.assertRaises(PermissionDenied):
                    async with self.services() as (_, service, _):
                        await service.update(
                            principal, user.uuid, {"name": "No"}
                        )

    async def test_admin_changes_other_identity_but_not_own_role(self):
        admin, target = await self.account(), await self.account("master")
        principal = await self.principal(await self.login(admin))
        old_pair = await self.login(target)
        async with self.services() as (_, service, _):
            updated = await service.update(
                principal, target.uuid,
                {"cedula": "0" * 20, "rol": "superadmin"},
                administrative=True,
            )
        self.assertEqual(updated.cedula, "0" * 20)
        self.assertEqual(updated.rol, "superadmin")
        with self.assertRaises(AuthenticationError):
            await self.principal(old_pair)
        for operation in (
            lambda service: service.update(
                principal, admin.uuid, {"rol": "master"}, administrative=True
            ),
            lambda service: service.delete(principal, admin.uuid),
            lambda service: service.set_status(principal, admin.uuid, False),
        ):
            with self.assertRaises(PermissionDenied):
                async with self.services() as (_, service, _):
                    await operation(service)

    async def test_admin_can_correct_own_cedula_as_administrative_exception(
        self,
    ):
        admin = await self.account()
        principal = await self.principal(await self.login(admin))
        changes = {
            "cedula": "0" * 20,
            "name": "Updated",
            "last_name": "Administrator",
            "phone_number": "1234567890",
            "email": "updated-admin@example.com",
        }
        async with self.services() as (_, service, _):
            updated = await service.update(
                principal, admin.uuid, changes, administrative=True
            )
        self.assertEqual(updated.cedula, changes["cedula"])
        self.assertEqual(updated.name, changes["name"])
        self.assertEqual(updated.last_name, changes["last_name"])
        self.assertEqual(updated.phone_number, changes["phone_number"])
        self.assertEqual(updated.email, changes["email"])
        self.assertEqual(updated.rol, "superadmin")
        async with self.services() as (_, _, repository):
            profile = await repository.get(admin.uuid)
        self.assertEqual(profile.cedula, changes["cedula"])
        self.assertEqual(profile.email, changes["email"])

    async def test_concurrent_admin_deletions_preserve_one_active_admin(self):
        first, second = await self.account(), await self.account()
        one = await self.principal(await self.login(first))
        two = await self.principal(await self.login(second))

        async def delete(actor, target):
            async with self.services() as (_, service, _):
                await service.delete(actor, target)

        results = await asyncio.gather(
            delete(one, second.uuid), delete(two, first.uuid),
            return_exceptions=True,
        )
        self.assertEqual(sum(result is None for result in results), 1)
        self.assertEqual(
            sum(isinstance(r, AuthenticationError) for r in results), 1
        )
        async with self.services() as (_, _, repository):
            self.assertEqual(await repository.count_admins(), 1)

    async def test_reactivation_does_not_restore_old_session(self):
        admin, target = await self.account(), await self.account("master")
        principal = await self.principal(await self.login(admin))
        pair = await self.login(target)
        for active in (False, True):
            async with self.services() as (_, service, _):
                await service.set_status(principal, target.uuid, active)
            with self.assertRaises(AuthenticationError):
                await self.principal(pair)

    async def test_soft_delete_preserves_identity_and_audit(self):
        admin, target = await self.account(), await self.account("master")
        principal = await self.principal(await self.login(admin))
        pair = await self.login(target)
        async with self.services() as (_, service, _):
            await service.delete(principal, target.uuid)
        with self.assertRaises(AuthenticationError):
            await self.principal(pair)
        async with self.services() as (_, _, repository):
            deleted = await repository.get(target.uuid)
            self.assertTrue(deleted.is_deleted)
            self.assertFalse(deleted.is_active)
            self.assertEqual(deleted.email, target.email)
            self.assertIsNotNone(deleted.deleted_at)
        for changes in (
            {"email": target.email.upper(), "cedula": "999"},
            {"email": "other@example.com", "cedula": target.cedula},
        ):
            with self.assertRaises(Conflict):
                async with self.services() as (_, service, _):
                    await service.create(
                        principal,
                        {"name": "Test", "rol": "master", **changes},
                        PASSWORD,
                    )
        async with self.services() as (_, service, _):
            with self.assertRaises(NotFound):
                await service.search(principal, target.email)
        async with self.factory() as session:
            event = (await session.execute(
                select(AuditModel).where(AuditModel.action == "user.deleted")
            )).scalar_one()
            self.assertEqual(event.actor_uuid, admin.uuid)
            self.assertEqual(event.target_uuid, target.uuid)
            self.assertEqual(event.fields, ["is_deleted", "is_active"])

    async def test_audit_failure_rolls_back_user_creation(self):
        admin = await self.account()
        principal = await self.principal(await self.login(admin))
        with self.assertRaises(RuntimeError):
            async with self.services() as (_, service, repository):
                with patch.object(
                    repository, "audit", AsyncMock(side_effect=RuntimeError)
                ):
                    await service.create(
                        principal,
                        {
                            "name": "Test", "email": "rollback@example.com",
                            "cedula": "2", "rol": "master",
                        },
                        PASSWORD,
                    )
        async with self.services() as (_, _, repository):
            account = await repository.find_email("rollback@example.com")
            self.assertIsNone(account)

    async def test_search_is_case_insensitive_and_pagination_is_numeric(self):
        admin = await self.account()
        principal = await self.principal(await self.login(admin))
        async with self.services() as (_, service, _):
            found = await service.search(principal, admin.email.upper())
            total, records = await service.list_users(principal, 1, 10)
        self.assertEqual(found.uuid, admin.uuid)
        self.assertEqual(total, 1)
        self.assertEqual(len(records), 1)
