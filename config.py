from pydantic_settings import BaseSettings, SettingsConfigDict

class Setting(BaseSettings):
    SECREY_KEY: str
    PEPPER: str
    ENVIRONMENT: str = "production"
    DATABASE_URL: str
    REDIS_URL: str
    JWT_ISSUER: str
    JWT_AUDIENCE: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = SettingsConfigDict(
        env_file = ".env",
        env_file_encoding = "utf-8"
    )

settings = Settings()