import logging
from contextlib import asynccontextmanager
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from config import settings
from database import async_session, engine, redis_client
from dependencies import security
from repositories.users import SqlAlchemyUserRepository
from routers import auth, users
from services.errors import ServiceError
from services.users import UserService

logger = logging.getLogger(__name__)


class ApiGuard:
    """Aplica límites antes de que FastAPI analice el cuerpo de la petición."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])

        async def protected_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                protected = {b"cache-control", b"x-content-type-options"}
                message["headers"] = [
                    (key, value) for key, value in message.get("headers", [])
                    if key.lower() not in protected
                ] + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        path, method = scope["path"], scope["method"]
        requires_json = (
            path.rstrip("/") == "/api/auth/login" and method == "POST"
        ) or (
            path.startswith("/api/users")
            and method in {"POST", "PUT", "PATCH"}
        )
        media_type = headers.get(b"content-type", b"").split(b";", 1)[0]
        if requires_json and media_type.strip().lower() != b"application/json":
            await JSONResponse(
                {"detail": "Se requiere application/json"}, status_code=415
            )(scope, receive, protected_send)
            return
        try:
            length = int(headers.get(b"content-length", b"0"))
            if length < 0:
                raise ValueError
        except ValueError:
            await JSONResponse(
                {"detail": "Content-Length inválido"}, status_code=400
            )(scope, receive, protected_send)
            return
        if length > settings.MAX_REQUEST_BYTES:
            await JSONResponse(
                {"detail": "Cuerpo demasiado grande"}, status_code=413
            )(scope, receive, protected_send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > settings.MAX_REQUEST_BYTES:
                    raise HTTPException(413, "Cuerpo demasiado grande")
            return message

        await self.app(scope, limited_receive, protected_send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        configuration = Config(str(Path(__file__).with_name("alembic.ini")))
        expected = set(ScriptDirectory.from_config(configuration).get_heads())
        async with engine.connect() as connection:
            actual = await connection.run_sync(
                lambda conn: set(
                    MigrationContext.configure(conn).get_current_heads()
                )
            )
        if actual != expected:
            raise RuntimeError(
                "Ejecuta las migraciones Alembic antes de iniciar"
            )
        await redis_client.ping()
        await security.dummy_verify("startup-check")
        password = settings.BOOTSTRAP_ADMIN_PASSWORD
        async with async_session() as session:
            service = UserService(SqlAlchemyUserRepository(session), security)
            await service.bootstrap(
                password.get_secret_value() if password else None
            )
        yield
    finally:
        try:
            await redis_client.aclose()
        finally:
            await engine.dispose()


app = FastAPI(title="Sistema de gestión de usuarios", lifespan=lifespan)
app.add_middleware(ApiGuard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"
    ],
)


@app.exception_handler(ServiceError)
async def service_error_handler(
    request: Request, error: ServiceError
) -> JSONResponse:
    headers = {}
    if error.status_code == 401:
        headers["WWW-Authenticate"] = "Bearer"
    if error.status_code == 429:
        headers["Retry-After"] = "300"
    # El tipo de evento permite monitorear fallos sin registrar entradas.
    logger.warning("Solicitud rechazada: %s", type(error).__name__)
    return JSONResponse(
        {"detail": str(error)}, status_code=error.status_code, headers=headers
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    allowed = {
        "body", "query", "path", "header", "cookie", "name", "last_name",
        "phone_number", "email", "cedula", "rol", "psswd", "is_active",
        "page", "size", "user_uuid",
    }
    details = [
        {
            "loc": [
                part if part in allowed else "field" for part in item["loc"]
            ],
            "type": item["type"],
            "msg": "Entrada inválida",
        }
        for item in error.errors()
    ]
    return JSONResponse({"detail": details}, status_code=422)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(
    request: Request, error: SQLAlchemyError
) -> JSONResponse:
    logger.error("Fallo de persistencia: %s", type(error).__name__)
    return JSONResponse(
        {"detail": "Servicio temporalmente no disponible"}, status_code=503
    )


app.include_router(auth.router)
app.include_router(users.router)
