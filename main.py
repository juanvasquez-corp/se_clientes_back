from argon2 import PasswordHasher
from fastapi import FastAPI
from config import settings
from database import Base, async_session, engine
from models.user import UserModel
from routers import auth, users
from sqlalchemy import select

app = FastAPI(title="Sistema de gestión de usuarios")
app.include_router(auth.router)
app.include_router(users.router)

ph = PasswordHasher(memory_cost=12288, time_cost=3, parallelism=1)


@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed automático para el primer superadmin del sistema
    async with async_session() as session:
        result = await session.execute(select(UserModel))
        if not result.scalars().first():
            print("Base de datos vacía, se generará el superadmin...")
            psswd_bytes = f"Admin123.Aliar{settings.PEPPER}".encode("utf-8")
            seed_admin = UserModel(
                cedula="1234567890",
                name="admin",
                last_name="system",
                email="superadmin.system@aliar.com",
                hashed_psswd=ph.hash(psswd_bytes),
                phone_number="3050082154",
                rol="superadmin"
            )
            session.add(seed_admin)
            await session.commit()
            print("superadmin semilla creado exitosamente.")