from typing import Annotated
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    StrictBool,
    StringConstraints,
    field_validator,
)

from services.contracts import UserRole

Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=50)
]
Phone = Annotated[str, StringConstraints(min_length=7, max_length=20)]
Cedula = Annotated[
    str, StringConstraints(min_length=1, max_length=20, pattern=r"^[0-9]+$")
]
NormalizedEmail = Annotated[
    EmailStr, AfterValidator(lambda value: value.lower())
]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class UserRegister(InputModel):
    cedula: Cedula
    name: Name
    last_name: Name | None = None
    email: NormalizedEmail
    phone_number: Phone | None = None
    psswd: SecretStr = Field(min_length=15, max_length=128)
    rol: UserRole


class UserResponse(BaseModel):
    # La lista explícita impide filtrar identificadores internos y secretos.
    uuid: UUID
    name: str
    last_name: str | None
    email: EmailStr
    phone_number: str | None
    rol: UserRole
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(InputModel):
    email: NormalizedEmail
    psswd: SecretStr = Field(min_length=1, max_length=128)


class UserUpdate(InputModel):
    name: Name
    last_name: Name | None = None
    phone_number: Phone | None = None
    email: NormalizedEmail


class AdminUserUpdate(UserUpdate):
    cedula: Cedula | None = None
    rol: UserRole | None = None

    @field_validator("cedula", "rol")
    @classmethod
    def reject_explicit_null(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("Omite el campo si no deseas modificarlo")
        return value


class UserStatusUpdate(InputModel):
    is_active: StrictBool


class UserSearch(InputModel):
    email: NormalizedEmail


class PaginatedUserResponse(BaseModel):
    total_records: int
    current_page: int
    total_pages: int
    page_size: int
    data: list[UserResponse]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    csrf_token: str


class CsrfResponse(BaseModel):
    csrf_token: str


class MessageResponse(BaseModel):
    detail: str
