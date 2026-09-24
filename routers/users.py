from uuid import uuid4
from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from config import settings
from database import get_db, redis_client
from models.user import UserModel
from schemas.user import UserRegister, UserResponse

router = APIRouter(prefix="/api/users", tags=["Gestión de Usuarios"])

ALGORITHM = "HS256"

ph = PasswordHasher(memory_cost=12288, time_cost=3, parallelism=1)
security_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
) -> dict:
    try:
        token = credentials.credentials

        #OWASP REST: Verificación cruzada forzada de Issuer y Audience
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            algorithms=[ALGORITHM]
        )
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Procedencia o destino de token no confiable"
        )


class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: dict = Depends(get_current_user)):
        if current_user.get("rol") not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acceso denegado: Se requieren privilegios de Superadmin"
            )
        return current_user


@router.post("/create",
            response_model=UserResponse,
            status_code=201,
            dependencies=[Depends(RoleChecker(["superadmin"]))])
async def create_new_user(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    # Registro de usuarios solo para el superadmin

    # Validación semántica previa de cédula
    stmt_cedula = select(UserModel).where(UserModel.cedula == user_data.cedula)
    cedula_existente = await db.execute(stmt_cedula)
    if cedula_existente.scalars().first():
        raise HTTPException(
            status_code=400,
            detail="La cédula ingresada ya se encuentra registrada"
        )
    
    # Validación semántica previa de correo
    stmt_email = select(UserModel).where(UserModel.email == user_data.email)
    email_existente = await db.execute(stmt_email)
    if email_existente.scalars().first():
        raise HTTPException(
            status_code=400,
            detail="El correo electrónico ingresado ya se encuentra registrado"
        )

    # Conversión de forma segura a bytes UTF-8 combinado con el Pepper oculto
    psswd_bytes = f"{user_data.psswd}{settings.PEPPER}".encode("utf-8")

    new_user = UserModel(
        cedula=user_data.cedula,
        name=user_data.name,
        last_name=user_data.last_name,
        phone_number=user_data.phone_number,
        email=user_data.email,
        hashed_psswd=ph.hash(psswd_bytes),
        rol=user_data.rol
    )
    db.add(new_user)

    # Defensa ante condiciones de carrera (Race Conditions)
    try:
        # Confirmación explícita de la transacción realizada satisfactoriamente
        await db.commit()

        # Sincronización de llaves auto-generadas
        await db.refresh(new_user)

        return new_user
    except IntegrityError:
        # Ante colisión se vuelve al punto anterior
        await db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Error de integridad: Las credenciales ya fueron registradas"
        )


@router.delete("/{user_uuid}",
                dependencies = [Depends(RoleChecker(["superadmin"]))])
async def delete_user(user_uuid: UUID, db: AsyncSession = Depends(get_db)):

    # Eliminar al usuario usando el UUID público
    result = await db.execute(
        select(UserModel).where(UserMode.uuid == user_uuid)
    )

    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado"
        )
    
    try:
        # Extracción del id numérico interno antes de borrar el registro
        target_id = user.id

        await db.delete(user)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error transaccional al borrar usuario"
        )

    # Invalidación en la memoria Redis
    for key in redis_client.scan_iter(match="refresh_token:*"):
        if redis_client.get(key) == str(target_id):
            redis_client.delete(key)

    return {"detail": "Usuario eliminado de forma exitosa"}
