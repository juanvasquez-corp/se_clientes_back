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