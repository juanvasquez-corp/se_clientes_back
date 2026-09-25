from uuid import UUID
from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from math import ceil 
from config import settings
from database import get_db, redis_client
from models.user import UserModel
from schemas.user import (
    UserRegister, 
    UserResponse, 
    PaginatedUserResponse,
    UserStatusUpdate,
    UserUpdate
    )

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
        select(UserModel).where(UserModel.uuid == user_uuid)
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


@router.get("",
            response_model=PaginatedUserResponse,
            dependencies=[Depends(RoleChecker(["superadmin"]))])
async def list_all_users_paginated(
    page: int = 1,
    size: int = 10,
    db: AsyncSession = Depends(get_db)
):
    # Convención para listar usuarios con paginación estricta
    # El objetivo es limitar el tamaño máximo por página.

    # OWASP: Sanitizar parámetros query para avitar abuso de recursos 
    if page < 1:
        page = 1
    if size < 1 or size > 50:
        size = 10
    
    # Consulta para obtener conteo total existente en BD
    total_stmt = select(func.count()).select_from(UserModel)
    total_result = await db.execute(total_stmt)
    total_records = total_result.scalars() or 0

    # Calcular Offset para la paginación en la BD
    offset_value = (page - 1) * size
    total_pages = ceil(total_records / size) if total_records > 0 else 1

    # Ejecución de la consulta limitada por rango
    stmt = select(UserModel).order_by(UserModel.id).offset(offset_value).limit(size)
    result = await db.execute(stmt)
    users_list = result.scalars().all()

    return {
        "total_records" : total_records,
        "current_page" : page,
        "total_pages" : total_pages,
        "page_size" : size,
        "data" : users_list
    } 

@router.get("/{user_uuid}",
            response_model=UserResponse,
            dependencies=[Depends(RoleChecker(["superadmin"]))])
async def get_user_by_uuid(user_uuid: UUID, db: AsyncSession = Depends(get_db)):
    # Usar uuid público para buscar y retornar el perfil del usuario

    stmt = selec(UserModel).where(UserModel.uuid == user_uuid)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="El usuario que buscas no existe en los registros"
        )
    
    return user

@router.put("/{user_uuid}"
            response_model=UserResponse,
            dependencies=[Depends(RoleChecker(["superadmin"]))])
async def update_user_profile(
    user_uuid: UUID,
    update_data: UserUpdate,
    db: AsyncSession = Depends(get_db)
):
    # Actualiza la información básica de un usuario.
    # Se usan conevciones de ciberseguridad para prevenir Mass Assigment

    stmt = select(UserModel).where(UserModel.uuid == user_uuid)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Validar semántica cruzada para evitar colisión de correos duplicados
    if update_data.email != user.email:
        email_check = await db.execute(
            select(UserModel).where(UserModel.email == update_data.email)
        )
        if email_check.scalars().first():
            raise HTTPException(
                status_code=400,
                detail="El nuevo correo electrónico ya está en uso"
            )
        
        # Mapeo controlado de atributos permitidos
        user.name = update_data.name
        user.last_name = update_data.last_name
        user.phone_number = update_data.phone_number
        user.email = update_data.email

        try:
            await db.commit()
            await db.refresh(user)
            return user
        except Exception:
            await db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Error transaccional al actualizar el perfil"
            )

@router.patch("/{user_uuid}/status",
            dependencies=[Depends(RoleChecker(["superadmin"]))])
async def toggle_user_activation(
    user_uuid: UUID,
    status_data: UserStatusUpdate,
    db: AsyncSession = Depends(get_db)
):
    # Activar o desactivar la cuenta de un usuario.
    # Si se desactiva, purgar inmediatamente sesiones activas en Redis.

    stmt = select(UserModel).where(UserModel.uuid == user_uuid)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Usuario no encontrado"
        )
    
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Error al procesar el cambio de estado"
        )
    
    # Expulsar al usuario del sistema al ser desactivado
    if not status_data.is_active:
        target_id = user.id
        for key in redis_client.scan_iter(match="refresh_token:*"):
            if redis_client.get(key) == str(target_id):
                redis_client.delete(key)

    estado_str = "activado" if status_data.is_active else "desactivado"
    return {"detail" : f"El usuario ha sido {estado_str} exitosamente."}
