"""
Application configuration settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""

    # Application
    app_name: str = "AuthX"
    app_version: str = "0.1.0"
    debug: bool = False

    # Database
    database_url: str = Field(..., description="PostgreSQL database URL")
    database_url_sync: str = Field(..., description="Sync PostgreSQL database URL for Alembic")

    # Security
    secret_key: str = Field(..., description="Secret key for JWT tokens")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    reset_password_token_expire_minutes: int = 15

    # Redis
    redis_url: str = Field(default="redis://localhost:6379", description="Redis URL")

    # Email
    smtp_host: str = Field(default="localhost", description="SMTP host")
    smtp_port: int = Field(default=587, description="SMTP port")
    smtp_username: Optional[str] = Field(default=None, description="SMTP username")
    smtp_password: Optional[str] = Field(default=None, description="SMTP password")
    smtp_use_tls: bool = True
    email_from: str = Field(default="noreply@authx.com", description="From email address")

    # Pagination
    default_page_size: int = 20
    max_page_size: int = 100

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
