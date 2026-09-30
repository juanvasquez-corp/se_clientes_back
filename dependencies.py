from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db, redis_client
from repositories.sessions import RedisSessionStore
from repositories.users import SqlAlchemyUserRepository
from security import Security
from services.auth import AuthService
from services.contracts import Principal
from services.errors import AuthenticationError, PermissionDenied
from services.users import UserService

security = Security(settings)
bearer = HTTPBearer(auto_error=False)
DatabaseDep = Annotated[AsyncSession, Depends(get_db)]


def get_user_service(db: DatabaseDep) -> UserService:
    return UserService(SqlAlchemyUserRepository(db), security)


def get_auth_service(db: DatabaseDep) -> AuthService:
    return AuthService(
        SqlAlchemyUserRepository(db),
        RedisSessionStore(redis_client),
        security,
        access_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        session_seconds=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


UserServiceDep = Annotated[UserService, Depends(get_user_service)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


async def get_current_user(
    auth: AuthServiceDep,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer)
    ],
) -> Principal:
    if credentials is None:
        raise AuthenticationError()
    return await auth.authenticate(credentials.credentials)


CurrentUserDep = Annotated[Principal, Depends(get_current_user)]


def require_browser_intent(
    request: Request,
    requested_with: Annotated[
        str | None,
        Header(
            alias="X-Requested-With",
            description="Usa XMLHttpRequest en los endpoints de autenticación",
        ),
    ] = None,
) -> None:
    origin = request.headers.get("origin")
    if origin is not None and origin not in settings.FRONTEND_ORIGINS:
        raise PermissionDenied("Origen no permitido")
    # Una página externa no puede enviar esta cabecera sin superar preflight.
    if requested_with != "XMLHttpRequest":
        raise PermissionDenied("Se requiere X-Requested-With: XMLHttpRequest")
