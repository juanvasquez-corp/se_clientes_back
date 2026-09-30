from math import ceil
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from dependencies import CurrentUserDep, UserServiceDep
from schemas.user import (
    AdminUserUpdate,
    MessageResponse,
    PaginatedUserResponse,
    UserRegister,
    UserResponse,
    UserSearch,
    UserStatusUpdate,
    UserUpdate,
)
from services.contracts import UserAccount

router = APIRouter(prefix="/api/users", tags=["Gestión de usuarios"])


@router.post("/create", response_model=UserResponse, status_code=201)
async def create_user(
    data: UserRegister, principal: CurrentUserDep, service: UserServiceDep,
) -> UserAccount:
    return await service.create(
        principal,
        data.model_dump(exclude={"psswd"}),
        data.psswd.get_secret_value(),
    )


@router.get("/me", response_model=UserResponse)
async def read_my_profile(
    principal: CurrentUserDep, service: UserServiceDep
) -> UserAccount:
    return await service.read(principal, principal.user_uuid)


@router.put("/me", response_model=UserResponse)
async def update_my_profile(
    data: UserUpdate, principal: CurrentUserDep, service: UserServiceDep,
) -> UserAccount:
    return await service.update(
        principal, principal.user_uuid, data.model_dump()
    )


@router.post("/search", response_model=UserResponse)
async def search_user(
    data: UserSearch, principal: CurrentUserDep, service: UserServiceDep,
) -> UserAccount:
    return await service.search(principal, str(data.email))


@router.get("")
async def list_users(
    principal: CurrentUserDep,
    service: UserServiceDep,
    page: Annotated[int, Query(le=100000)] = 1,
    size: int = 10,
) -> PaginatedUserResponse:
    page, size = max(1, page), min(50, max(1, size))
    total, users = await service.list_users(principal, page, size)
    return PaginatedUserResponse(
        total_records=total, current_page=page,
        total_pages=max(1, ceil(total / size)), page_size=size,
        data=[UserResponse.model_validate(user) for user in users],
    )


@router.get("/{user_uuid}", response_model=UserResponse)
async def read_user(
    user_uuid: UUID, principal: CurrentUserDep, service: UserServiceDep,
) -> UserAccount:
    return await service.read(principal, user_uuid)


@router.put("/{user_uuid}", response_model=UserResponse)
async def update_user(
    user_uuid: UUID, data: AdminUserUpdate,
    principal: CurrentUserDep, service: UserServiceDep,
) -> UserAccount:
    changes = data.model_dump(exclude={"cedula", "rol"})
    for field in ("cedula", "rol"):
        if field in data.model_fields_set:
            changes[field] = getattr(data, field)
    return await service.update(
        principal, user_uuid, changes, administrative=True
    )


@router.patch("/{user_uuid}/status")
async def change_status(
    user_uuid: UUID, data: UserStatusUpdate,
    principal: CurrentUserDep, service: UserServiceDep,
) -> MessageResponse:
    await service.set_status(principal, user_uuid, data.is_active)
    return MessageResponse(detail="Estado actualizado")


@router.delete("/{user_uuid}")
async def delete_user(
    user_uuid: UUID, principal: CurrentUserDep, service: UserServiceDep,
) -> MessageResponse:
    await service.delete(principal, user_uuid)
    return MessageResponse(detail="Usuario eliminado")
