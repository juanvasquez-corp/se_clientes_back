import time
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, Request, Response

from config import settings
from dependencies import AuthServiceDep, require_browser_intent
from schemas.user import (
    CsrfResponse,
    LoginRequest,
    MessageResponse,
    TokenResponse,
)
from services.auth import TokenPair
from services.errors import AuthenticationError

router = APIRouter(
    prefix="/api/auth",
    tags=["Autenticación"],
    dependencies=[Depends(require_browser_intent)],
)

RefreshCookie = Annotated[str | None, Cookie(alias="refresh_token")]
CsrfHeader = Annotated[str | None, Header(alias="X-CSRF-Token")]
COOKIE_PATH = "/api/auth"


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        "refresh_token", path=COOKIE_PATH,
        secure=settings.secure_cookies, httponly=True,
        samesite=settings.COOKIE_SAMESITE,
    )
    # Limpia también la cookie raíz emitida por versiones anteriores.
    response.delete_cookie("refresh_token", path="/")


def token_response(response: Response, pair: TokenPair) -> TokenResponse:
    response.delete_cookie("refresh_token", path="/")
    response.set_cookie(
        "refresh_token", pair.refresh_token,
        httponly=True, secure=settings.secure_cookies,
        samesite=settings.COOKIE_SAMESITE, path=COOKIE_PATH,
        max_age=max(0, pair.session_expires_at - int(time.time())),
    )
    return TokenResponse(
        access_token=pair.access_token, expires_in=pair.expires_in,
        csrf_token=pair.csrf_token,
    )


@router.post("/login")
async def login(
    login_data: LoginRequest, request: Request,
    response: Response, auth: AuthServiceDep,
) -> TokenResponse:
    pair = await auth.login(
        str(login_data.email), login_data.psswd.get_secret_value(),
        request.client.host if request.client else "unknown",
    )
    return token_response(response, pair)


@router.post("/refresh")
async def refresh(
    response: Response, auth: AuthServiceDep,
    refresh_token: RefreshCookie = None, csrf_token: CsrfHeader = None,
) -> TokenResponse:
    if not refresh_token:
        raise AuthenticationError()
    return token_response(
        response, await auth.refresh(refresh_token, csrf_token)
    )


@router.get("/csrf")
async def csrf(
    auth: AuthServiceDep, refresh_token: RefreshCookie = None,
) -> CsrfResponse:
    if not refresh_token:
        raise AuthenticationError()
    return CsrfResponse(csrf_token=await auth.csrf(refresh_token))


@router.post("/logout")
async def logout(
    response: Response, auth: AuthServiceDep,
    refresh_token: RefreshCookie = None, csrf_token: CsrfHeader = None,
) -> MessageResponse:
    if refresh_token:
        try:
            await auth.logout(refresh_token, csrf_token)
        except AuthenticationError:
            # Cerrar una sesión ya finalizada también limpia el navegador.
            pass
    clear_refresh_cookie(response)
    return MessageResponse(detail="Sesión finalizada")
