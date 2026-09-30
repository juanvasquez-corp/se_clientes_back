from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SECRET_KEY: SecretStr
    PEPPER: SecretStr
    ENVIRONMENT: Literal["development", "test", "production"] = "production"
    DATABASE_URL: str
    REDIS_URL: str
    JWT_ISSUER: str = Field(min_length=1)
    JWT_AUDIENCE: str = Field(min_length=1)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=2, ge=1, le=2)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=1, ge=1, le=1)
    FRONTEND_ORIGINS: list[str] = Field(default_factory=list)
    COOKIE_SAMESITE: Literal["strict", "lax", "none"] = "lax"
    COOKIE_SECURE: bool | None = None
    BOOTSTRAP_ADMIN_PASSWORD: SecretStr | None = None
    MAX_REQUEST_BYTES: int = Field(default=16384, ge=1024, le=1048576)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        hide_input_in_errors=True,
    )

    @field_validator("SECRET_KEY", "PEPPER")
    @classmethod
    def validate_secret(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode("utf-8")) < 32:
            raise ValueError("El secreto debe tener al menos 32 bytes")
        return value

    @field_validator("BOOTSTRAP_ADMIN_PASSWORD", mode="before")
    @classmethod
    def empty_bootstrap_password(cls, value: object) -> object:
        return None if value == "" else value

    @field_validator("FRONTEND_ORIGINS")
    @classmethod
    def validate_origins(cls, values: list[str]) -> list[str]:
        for origin in values:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or "*" in parsed.hostname
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise ValueError("Usa orígenes explícitos sin ruta ni comodín")
        return values

    @property
    def secure_cookies(self) -> bool:
        if self.ENVIRONMENT == "production":
            return True
        return bool(self.COOKIE_SECURE)

    @model_validator(mode="after")
    def validate_cookies(self) -> Self:
        if self.COOKIE_SAMESITE == "none" and not self.secure_cookies:
            raise ValueError("SameSite=None requiere cookies Secure y HTTPS")
        if self.ENVIRONMENT == "production" and any(
            not origin.startswith("https://")
            for origin in self.FRONTEND_ORIGINS
        ):
            raise ValueError("Los orígenes de producción requieren HTTPS")
        return self


settings = Settings()
