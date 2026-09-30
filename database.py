from collections.abc import AsyncIterator

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.DATABASE_URL, echo=False, pool_pre_ping=True
)
async_session = async_sessionmaker(engine, expire_on_commit=False)
redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=3,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with async_session() as session:
        try:
            yield session
        finally:
            # También libera bloqueos cuando una petición se cancela.
            if session.in_transaction():
                await session.rollback()
