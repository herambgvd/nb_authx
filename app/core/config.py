"""
Core configuration module for the AuthX service.
This module manages loading environment variables and other configuration settings.
"""
from typing import List, Optional, Any, Union
from pydantic import validator, Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os  # Added import for os module

# Load environment variables from .env file
load_dotenv()

# Debug: Print environment variables related to database
print(f"Environment DB URL: {os.getenv('DATABASE_URL')}")
print(f"Current directory: {os.getcwd()}")

class Settings(BaseSettings):
    """Application settings class that loads configuration from environment variables."""

    # Application settings
    APP_NAME: str = Field(default="AuthX")
    VERSION: str = Field(default="0.1.0")
    ENVIRONMENT: str = Field(default="development")
    PROJECT_NAME: str = Field(default="AuthX")
    DEBUG: bool = Field(default=False)

    # API settings
    API_V1_PREFIX: str = Field(default="/api/v1")
    SECRET_KEY: str = Field(default="development_secret_key_change_in_production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    ALGORITHM: str = Field(default="HS256")

    # CORS settings - using List[str] fields with string defaults
    ALLOWED_ORIGINS_STR: List[str] = Field(default=["http://localhost:3000", "http://localhost:8000"])
    CORS_ORIGINS_STR: List[str] = Field(default=["*"])

    # Database settings
    DATABASE_URL: str = Field(default="postgresql://postgres:varanasi@localhost:5432/nb_auth")
    DATABASE_POOL_SIZE: int = Field(default=5)
    DATABASE_MAX_OVERFLOW: int = Field(default=10)
    DATABASE_ECHO: bool = Field(default=False)

    # Redis settings for caching and sessions
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_DB: int = Field(default=0)
    REDIS_PASSWORD: Optional[str] = Field(default=None)

    # Email settings
    SMTP_HOST: str = Field(default="localhost")
    SMTP_PORT: int = Field(default=587)
    SMTP_USER: Optional[str] = Field(default=None)
    SMTP_PASSWORD: Optional[str] = Field(default=None)
    SMTP_TLS: bool = Field(default=True)
    SMTP_SSL: bool = Field(default=False)
    FROM_EMAIL: str = Field(default="noreply@authx.com")
    FROM_NAME: str = Field(default="AuthX")

    # Security settings
    PASSWORD_MIN_LENGTH: int = Field(default=8)
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True)
    PASSWORD_REQUIRE_DIGITS: bool = Field(default=True)
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True)

    # Session settings
    SESSION_EXPIRE_MINUTES: int = Field(default=60)
    REMEMBER_ME_EXPIRE_DAYS: int = Field(default=30)

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=5)

    # File upload settings
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024)  # 10MB
    ALLOWED_FILE_TYPES: str = Field(default="image/jpeg,image/png,image/gif,application/pdf")

    # Logging settings
    LOG_LEVEL: str = Field(default="INFO")
    LOG_FILE: Optional[str] = Field(default=None)

    # External service settings
    GOOGLE_CLIENT_ID: Optional[str] = Field(default=None)
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_ID: Optional[str] = Field(default=None)
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(default=None)

    # MFA settings
    MFA_ISSUER: str = Field(default="AuthX")
    MFA_CODE_EXPIRE_MINUTES: int = Field(default=5)

    # Audit settings
    ENABLE_AUDIT_LOGGING: bool = Field(default=True)
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=90)

    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"

    @validator("REDIS_PASSWORD", pre=True)
    def parse_redis_password(cls, v: Any) -> Optional[str]:
        """Handle Redis password, converting empty strings to None."""
        if v is None or v == "" or v == "null":
            return None
        return str(v)

    @validator("SMTP_USER", pre=True)
    def parse_smtp_user(cls, v: Any) -> Optional[str]:
        """Handle SMTP user, converting empty strings to None."""
        if v is None or v == "" or v == "null":
            return None
        return str(v)

    @validator("SMTP_PASSWORD", pre=True)
    def parse_smtp_password(cls, v: Any) -> Optional[str]:
        """Handle SMTP password, converting empty strings to None."""
        if v is None or v == "" or v == "null":
            return None
        return str(v)

    @validator("LOG_FILE", pre=True)
    def parse_log_file(cls, v: Any) -> Optional[str]:
        """Handle log file path, converting empty strings to None."""
        if v is None or v == "" or v == "null":
            return None
        return str(v)

    @validator("CORS_ORIGINS_STR", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if origin]
        return v

    @validator("ALLOWED_ORIGINS_STR", pre=True)
    def assemble_allowed_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse allowed origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if origin]
        return v

    @property
    def allowed_file_types_list(self) -> List[str]:
        """Get allowed file types as list."""
        return [ft.strip() for ft in self.ALLOWED_FILE_TYPES.split(",") if ft.strip()]

    def get_database_url(self, async_mode: bool = False) -> str:
        """Get database URL with optional async driver."""
        if async_mode:
            # Convert PostgreSQL URL to async version
            if self.DATABASE_URL.startswith("postgresql://"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif self.DATABASE_URL.startswith("postgresql+psycopg2://"):
                return self.DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
        return self.DATABASE_URL

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT.lower() == "development"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.ENVIRONMENT.lower() == "testing"

# Create global settings instance
settings = Settings()

# Export settings for easy import
__all__ = ["settings", "Settings"]
