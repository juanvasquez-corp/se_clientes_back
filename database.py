import redis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False)
asynnc_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

redis_client = redis.from_url(settings.REDIS_URL, decode_response=True)


async def get_db():
    
    #Aislar sesión por petición
    async with asynnc_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise