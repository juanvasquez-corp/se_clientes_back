from uuid import UUID
from datetime import datetime, timedelta, timezone
import time
from typing import Optional
from argon2 import PasswordHasher
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from config import settings
from database import get_db, redis_client
from models.user import UserModel
from schemas.user import LoginRequest

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

ALGORITHM = "HS256"

# Convención OWASP para hasheo de contraseñas
# 12 MiB - 3 iteraciones - 1 hilo
ph = PasswordHasher(memory_cost=12288, time_cost=3, parallelism=1)


def verify_password_with_pepper(hashed_psswd: str, plain_psswd: str) -> bool:
    try:

        # Conversión de forma segura a bytes UTF-8 combinado con el Pepper oculto
        psswd_bytes = f"{plain_psswd}{settings.PEPPER}".encode("utf-8")
        return ph.verify(hashed_psswd, psswd_bytes)
    except Exception:
        return False


def create_access_token(user_uuid: UUID, email: str, rol: str) -> str:

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    # Implementación de convención OWASP REST:
    # Inlcusión estrcita de Claims de validación cruzada
    payload ={
        "sub": str(user_uuid),
        "email": email,
        "rol": rol,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": expire
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: int, user_uuid: UUID) -> str:
    jti = f"ref_{int(time.time())}_{user_id}"
    ttl_seconds = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    redis_client.setex(
        name=f"refresh_token:{jti}",
        time=ttl_seconds,
        value=str(user_id)
    )

    payload = {
        "jti": jti,
        "sub": str(user_uuid),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

@router.post("/login")
async def login(
    login_data: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    content_type: str = Header(None)
):
    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="Se requiere application/json"
        )

    result = await db.execute(
        select(UserModel).where(UserModel.email == login_data.email)
    )
    user = result.scalars().first()

    if (not user or
            not verify_password_with_pepper(user.hashed_psswd,
                                            login_data.psswd) or
            not user.is_active):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    access_token = create_access_token(user.uuid, user.email, user.rol)
    refresh_token = create_refresh_token(user.id, user.uuid)

    es_produccion = settings.ENVIRONMENT == "production"

    # OWASP REST: Cabeceras de protección de memoria en cliente
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=es_produccion,
        samesite="strict" if es_produccion else "lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(
    response: Response,
    refresh_token: Optional[str] = Cookie(None)
):
    if refresh_token:
        try:
            payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
                algorithms=[ALGORITHM]
            )
            redis_client.delete(f"refresh_token:{payload.get('jti')}")
        except jwt.PyJWTError:
            pass
        
        response.delete_cookie("refresh_token")
        return {"detail": "Sesión finalizada"}


