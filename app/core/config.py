"""
Core configuration module for the AuthX service.
This module manages loading environment variables and other configuration settings.
"""
import os
from typing import Any, Dict, List, Optional, Union
from pydantic import AnyHttpUrl, validator
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings class that loads configuration from environment variables."""

    # Application settings
    APP_NAME: str = "AuthX"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    PROJECT_NAME: str = "AuthX"
    DEBUG: bool = False

    # API settings
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "development_secret_key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    ALGORITHM: str = "HS256"

    # CORS settings
    ALLOWED_ORIGINS: Union[List[str], List[AnyHttpUrl]] = ["http://localhost:3000", "http://localhost:8000"]
    CORS_ORIGINS: Union[List[str], List[AnyHttpUrl]] = ["*"]

    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    @validator("ALLOWED_ORIGINS", pre=True)
    def assemble_allowed_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database settings
    DATABASE_URI: str = os.getenv("DATABASE_URI", "postgresql://postgres:postgres@localhost:5432/authx")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/authx")
    DATABASE_POOL_SIZE: int = int(os.getenv("DATABASE_POOL_SIZE", "5"))
    DATABASE_MAX_OVERFLOW: int = int(os.getenv("DATABASE_MAX_OVERFLOW", "10"))
    DATABASE_POOL_TIMEOUT: int = int(os.getenv("DATABASE_POOL_TIMEOUT", "30"))

    # Redis settings
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", "")
    REDIS_CACHE_EXPIRATION: int = int(os.getenv("REDIS_CACHE_EXPIRATION", "3600"))
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Email settings
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "your-email@gmail.com")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "noreply@yourcompany.com")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "AuthX Security")

    # Legacy email settings
    SMTP_TLS: bool = os.getenv("SMTP_TLS", "True").lower() == "true"
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST", "")
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER", "")
    EMAILS_FROM_EMAIL: Optional[str] = os.getenv("EMAILS_FROM_EMAIL", "")
    EMAILS_FROM_NAME: Optional[str] = os.getenv("EMAILS_FROM_NAME", "")

    # Security settings
    PASSWORD_HASH_ALGORITHM: str = os.getenv("PASSWORD_HASH_ALGORITHM", "bcrypt")
    MIN_PASSWORD_LENGTH: int = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))
    BRUTE_FORCE_MAX_ATTEMPTS: int = int(os.getenv("BRUTE_FORCE_MAX_ATTEMPTS", "5"))
    BRUTE_FORCE_WINDOW_MINUTES: int = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "15"))
    MFA_ENABLED: bool = os.getenv("MFA_ENABLED", "True").lower() == "true"
    DEFAULT_MFA_TYPE: str = os.getenv("DEFAULT_MFA_TYPE", "totp")

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_DEFAULT: str = os.getenv("RATE_LIMIT_DEFAULT", "60/minute")
    RATE_LIMIT_AUTH: str = os.getenv("RATE_LIMIT_AUTH", "10/minute")

    # Metrics and monitoring
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "True").lower() == "true"
    METRICS_ENDPOINT_ENABLED: bool = os.getenv("METRICS_ENDPOINT_ENABLED", "True").lower() == "true"
    PROMETHEUS_MULTIPROC_DIR: str = os.getenv("PROMETHEUS_MULTIPROC_DIR", "/tmp")

    # File storage
    STORAGE_TYPE: str = os.getenv("STORAGE_TYPE", "local")
    STORAGE_LOCAL_PATH: str = os.getenv("STORAGE_LOCAL_PATH", "./storage")
    S3_BUCKET: str = os.getenv("S3_BUCKET", "authx-storage")
    S3_ACCESS_KEY: str = os.getenv("S3_ACCESS_KEY", "your-s3-access-key")
    S3_SECRET_KEY: str = os.getenv("S3_SECRET_KEY", "your-s3-secret-key")
    S3_REGION: str = os.getenv("S3_REGION", "us-east-1")

    # AI Integration
    AI_ENABLED: bool = os.getenv("AI_ENABLED", "False").lower() == "true"
    AI_SERVICE_URL: str = os.getenv("AI_SERVICE_URL", "http://localhost:5000/api")
    AI_API_KEY: str = os.getenv("AI_API_KEY", "your-ai-api-key")

    # External services
    GEOLOCATION_API_URL: str = os.getenv("GEOLOCATION_API_URL", "https://ipgeolocation.example.com/api")
    GEOLOCATION_API_KEY: str = os.getenv("GEOLOCATION_API_KEY", "your-geolocation-api-key")

    # Super Admin initial setup
    INITIAL_SUPERADMIN_EMAIL: str = os.getenv("INITIAL_SUPERADMIN_EMAIL", "admin@example.com")
    INITIAL_SUPERADMIN_PASSWORD: str = os.getenv("INITIAL_SUPERADMIN_PASSWORD", "change-me-immediately")

    # Logging settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings object
settings = Settings()
