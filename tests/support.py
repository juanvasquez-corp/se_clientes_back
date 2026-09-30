import os
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from config import Settings, settings
from repositories.sessions import RedisSessionStore
from repositories.users import SqlAlchemyUserRepository
from security import Security
from services.auth import AuthService
from services.contracts import UserAccount
from services.users import UserService

PASSWORD = "Synthetic password for tests"
ROOT = Path(__file__).resolve().parents[1]


def test_settings(**overrides) -> Settings:
    values = {
        "SECRET_KEY": "synthetic-signing-key-" * 3,
        "PEPPER": "synthetic-pepper-" * 3,
        "ENVIRONMENT": "test",
        "DATABASE_URL": "postgresql+asyncpg://unused@localhost/unused",
        "REDIS_URL": "redis://localhost:1/15",
        "JWT_ISSUER": "test-issuer",
        "JWT_AUDIENCE": "test-audience",
        "ACCESS_TOKEN_EXPIRE_MINUTES": 2,
        "REFRESH_TOKEN_EXPIRE_DAYS": 1,
        "FRONTEND_ORIGINS": [],
        "COOKIE_SAMESITE": "lax",
        "COOKIE_SECURE": False,
        "BOOTSTRAP_ADMIN_PASSWORD": None,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@unittest.skipUnless(
    os.environ.get("RUN_INTEGRATION_TESTS") == "1",
    "Requiere autorización explícita mediante RUN_INTEGRATION_TESTS=1",
)
class IntegrationCase(unittest.IsolatedAsyncioTestCase):
    revision = "head"

    async def asyncSetUp(self):
        self.schema = f"test_backend_{uuid4().hex}"
        url = os.environ.get("TEST_DATABASE_URL", settings.DATABASE_URL)
        self.maintenance = create_async_engine(url)
        async with self.maintenance.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{self.schema}"'))
        self.addAsyncCleanup(self.cleanup_schema)
        self.engine = create_async_engine(
            url, connect_args={"server_settings": {"search_path": self.schema}}
        )
        self.addAsyncCleanup(self.engine.dispose)
        self.factory = async_sessionmaker(self.engine, expire_on_commit=False)
        await self.upgrade(self.revision)
        # Este puerto corresponde exclusivamente al contenedor de pruebas.
        self.redis = Redis(
            host="127.0.0.1", port=16379, db=15,
            decode_responses=True, socket_connect_timeout=2, socket_timeout=2,
        )
        self.addAsyncCleanup(self.redis.aclose)
        await self.redis.ping()
        self.sessions = RedisSessionStore(self.redis)
        self.crypto = Security(test_settings())
        self.hashed = await self.crypto.hash_password(PASSWORD)

    async def cleanup_schema(self):
        try:
            async with self.maintenance.begin() as connection:
                await connection.execute(
                    text(f'DROP SCHEMA "{self.schema}" CASCADE')
                )
        finally:
            await self.maintenance.dispose()

    async def upgrade(self, revision="head"):
        config = Config(str(ROOT / "alembic.ini"))

        def migrate(connection):
            config.attributes["connection"] = connection
            command.upgrade(config, revision)

        async with self.engine.begin() as connection:
            await connection.run_sync(migrate)

    @asynccontextmanager
    async def services(self):
        async with self.factory() as session:
            repository = SqlAlchemyUserRepository(session)
            yield (
                AuthService(repository, self.sessions, self.crypto),
                UserService(repository, self.crypto),
                repository,
            )

    async def account(self, role="superadmin", **changes):
        identity = uuid4()
        attributes = {
            "uuid": identity,
            "cedula": str(identity.int % (10 ** 20)),
            "name": "Synthetic",
            "email": f"{identity.hex}@example.com",
            "hashed_psswd": self.hashed,
            "rol": role,
        }
        attributes.update(changes)
        user = UserAccount(**attributes)
        async with self.services() as (_, _, repository):
            await repository.create(user)
            await repository.commit()
        return user

    async def login(self, user, password=PASSWORD):
        async with self.services() as (auth, _, _):
            return await auth.login(user.email, password, str(user.uuid))

    async def principal(self, pair):
        async with self.services() as (auth, _, _):
            return await auth.authenticate(pair.access_token)
