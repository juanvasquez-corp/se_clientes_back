from typing import List
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

class UserRegister(BaseModel):
    # El superadmin debe ingresar la cc de forma explícita en la gestión
    cedula: str = Field(..., description="Cédula del usuario")
    name: str
    last_name: str
    email: EmailStr
    phone_number: str
    psswd: str
    rol: str = "user"

class UserResponse(BaseModel):
    # Expone el UUID público, protegiendo así el id interno
    uuid: UUID
    cedula: str
    name: str
    last_name: str
    email: EmailStr
    phone_number: str
    rol: str
    is_active: bool

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    psswd: str

class UserUpdate(BaseModel):
    # Campos que el administrador actualiza sin problema
    name : str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    phone_number: str = Field(..., min_length=7, max_length=15)
    email : EmailStr

class UserStatusUpdate(BaseModel):
    # Exclusivo para activar o desactivar una cuenta
    is_active : bool

class PaginatedUserResponse(BaseModel):
    # Estructura estándarizada para las respuestas paginadas
    total_records: int
    current_page: int
    total_pages: int
    page_size: int
    data: List[UserResponse]
