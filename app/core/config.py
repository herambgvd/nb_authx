"""
Configuration settings for AuthX application.
Manages environment variables, database settings, security configuration, and feature flags.
"""
from typing import List, Optional, Dict
from pydantic import Field
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Basic Application Settings
    PROJECT_NAME: str = "AuthX"
    VERSION: str = Field(default="1.0.0", env="VERSION")
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    API_V1_PREFIX: str = "/api/v1"

    # Documentation Settings
    DOCS_ENABLED: bool = Field(default=True, env="DOCS_ENABLED")
    DOCS_URL: str = Field(default="/docs", env="DOCS_URL")

    # Security Settings
    SECRET_KEY: str = Field(env="SECRET_KEY", default="your-super-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_EXPIRE_MINUTES: int = Field(default=60, env="SESSION_EXPIRE_MINUTES")
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 24

    # Password Policy Settings
    PASSWORD_MIN_LENGTH: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    PASSWORD_REQUIRE_DIGITS: bool = Field(default=True, env="PASSWORD_REQUIRE_DIGITS")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")

    # Database Settings
    DATABASE_URL: str = Field(env="DATABASE_URL", default="postgresql+asyncpg://postgres:varanasi@localhost:5432/nb_auth")
    ALEMBIC_DATABASE_URL: str = Field(env="ALEMBIC_DATABASE_URL", default="postgresql://postgres:varanasi@localhost:5432/nb_auth")
    DATABASE_POOL_SIZE: int = 10
    DATABASE_POOL_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_ECHO: bool = Field(default=False, env="DATABASE_ECHO")

    # Redis Settings
    REDIS_URL: str = Field(env="REDIS_URL", default="redis://localhost:6379/0")
    REDIS_ENABLED: bool = Field(default=True, env="REDIS_ENABLED")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")

    # CORS Settings
    ALLOWED_HOSTS: List[str] = Field(default=["*"])

    # Email Settings (Enhanced SMTP Configuration)
    SMTP_SERVER: str = Field(default="localhost", env="SMTP_SERVER")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USERNAME: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    SMTP_USE_TLS: bool = Field(default=True, env="SMTP_USE_TLS")
    SMTP_USE_SSL: bool = Field(default=False, env="SMTP_USE_SSL")
    EMAIL_FROM: str = Field(default="noreply@authx.com", env="EMAIL_FROM")
    EMAIL_FROM_NAME: str = Field(default="AuthX", env="EMAIL_FROM_NAME")
    EMAIL_TEMPLATES_DIR: str = Field(default="app/templates/emails", env="EMAIL_TEMPLATES_DIR")

    # Google API Settings
    GOOGLE_MAPS_API_KEY: str = Field(env="GOOGLE_MAPS_API_KEY", default="")
    GOOGLE_PLACES_API_KEY: str = Field(env="GOOGLE_PLACES_API_KEY", default="")
    GOOGLE_GEOCODING_API_KEY: str = Field(env="GOOGLE_GEOCODING_API_KEY", default="")
    GOOGLE_API_TIMEOUT: int = Field(default=30, env="GOOGLE_API_TIMEOUT")
    GOOGLE_API_RETRY_ATTEMPTS: int = Field(default=3, env="GOOGLE_API_RETRY_ATTEMPTS")

    # System Monitoring Settings
    MONITORING_ENABLED: bool = Field(default=True, env="MONITORING_ENABLED")
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    HEALTH_CHECK_INTERVAL: int = Field(default=60, env="HEALTH_CHECK_INTERVAL")
    PERFORMANCE_MONITORING: bool = Field(default=True, env="PERFORMANCE_MONITORING")

    # Prometheus/Grafana Integration
    PROMETHEUS_ENABLED: bool = Field(default=True, env="PROMETHEUS_ENABLED")
    PROMETHEUS_PORT: int = Field(default=8001, env="PROMETHEUS_PORT")
    GRAFANA_URL: Optional[str] = Field(default=None, env="GRAFANA_URL")

    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(default="json", env="LOG_FORMAT")  # json or text
    LOG_FILE: Optional[str] = Field(default=None, env="LOG_FILE")
    LOG_FILE_PATH: Optional[str] = Field(default=None, env="LOG_FILE_PATH")
    LOG_ROTATION_SIZE: str = Field(default="100 MB", env="LOG_ROTATION_SIZE")
    LOG_RETENTION_DAYS: int = Field(default=30, env="LOG_RETENTION_DAYS")

    # Structured Logging for ELK Stack
    ELK_ENABLED: bool = Field(default=False, env="ELK_ENABLED")
    ELASTICSEARCH_URL: Optional[str] = Field(default=None, env="ELASTICSEARCH_URL")
    LOGSTASH_HOST: Optional[str] = Field(default=None, env="LOGSTASH_HOST")
    LOGSTASH_PORT: int = Field(default=5000, env="LOGSTASH_PORT")

    # Rate Limiting Settings
    RATE_LIMIT_ENABLED: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")  # seconds

    # Security Features
    BRUTE_FORCE_PROTECTION: bool = Field(default=True, env="BRUTE_FORCE_PROTECTION")
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")
    LOCKOUT_DURATION_MINUTES: int = Field(default=15, env="LOCKOUT_DURATION_MINUTES")

    # Audit and Logging
    AUDIT_LOG_ENABLED: bool = Field(default=True, env="AUDIT_LOG_ENABLED")
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=90, env="AUDIT_LOG_RETENTION_DAYS")

    # File Upload Settings
    UPLOAD_MAX_SIZE: int = Field(default=10 * 1024 * 1024, env="UPLOAD_MAX_SIZE")  # 10MB
    UPLOAD_ALLOWED_TYPES: List[str] = Field(default=["image/jpeg", "image/png", "application/pdf"])
    UPLOAD_DIR: str = Field(default="uploads", env="UPLOAD_DIR")

    # Organization Settings (Enhanced for Enterprise)
    DEFAULT_ORGANIZATION_TIER: str = Field(default="free", env="DEFAULT_ORGANIZATION_TIER")
    MAX_USERS_FREE_TIER: int = Field(default=10, env="MAX_USERS_FREE_TIER")
    MAX_USERS_BASIC_TIER: int = Field(default=50, env="MAX_USERS_BASIC_TIER")
    MAX_USERS_PROFESSIONAL_TIER: int = Field(default=200, env="MAX_USERS_PROFESSIONAL_TIER")
    MAX_USERS_ENTERPRISE_TIER: int = Field(default=1000, env="MAX_USERS_ENTERPRISE_TIER")

    # Super Admin Settings
    SUPER_ADMIN_EMAIL: str = Field(env="SUPER_ADMIN_EMAIL", default="admin@authx.com")
    SUPER_ADMIN_PASSWORD: str = Field(env="SUPER_ADMIN_PASSWORD", default="SuperSecurePassword123!")
    ORGANIZATION_APPROVAL_REQUIRED: bool = Field(default=True, env="ORGANIZATION_APPROVAL_REQUIRED")

    # Feature Flags (Enhanced)
    FEATURES: Dict[str, bool] = Field(default={
        "user_registration": True,
        "password_reset": True,
        "email_verification": True,
        "social_login": False,
        "api_access": True,
        "audit_logging": True,
        "advanced_analytics": True,
        "location_management": True,
        "organization_management": True,
        "role_based_access": True,
        "super_admin_panel": True,
        "system_monitoring": True,
        "google_maps_integration": True,
        "advanced_email_service": True
    })

    # Celery Settings (for background tasks)
    CELERY_BROKER_URL: str = Field(env="CELERY_BROKER_URL", default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(env="CELERY_RESULT_BACKEND", default="redis://localhost:6379/1")
    CELERY_TASK_SERIALIZER: str = Field(default="json", env="CELERY_TASK_SERIALIZER")
    CELERY_RESULT_SERIALIZER: str = Field(default="json", env="CELERY_RESULT_SERIALIZER")
    CELERY_TIMEZONE: str = Field(default="UTC", env="CELERY_TIMEZONE")

    # Microservices Communication
    SERVICE_DISCOVERY_ENABLED: bool = Field(default=False, env="SERVICE_DISCOVERY_ENABLED")
    SERVICE_REGISTRY_URL: Optional[str] = Field(default=None, env="SERVICE_REGISTRY_URL")
    SERVICE_NAME: str = Field(default="authx", env="SERVICE_NAME")
    SERVICE_VERSION: str = Field(default="1.0.0", env="SERVICE_VERSION")

    # API Gateway Settings
    API_GATEWAY_URL: Optional[str] = Field(default=None, env="API_GATEWAY_URL")
    API_GATEWAY_AUTH_TOKEN: Optional[str] = Field(default=None, env="API_GATEWAY_AUTH_TOKEN")

    # External Service URLs (for microservices communication)
    USER_SERVICE_URL: Optional[str] = Field(default=None, env="USER_SERVICE_URL")
    NOTIFICATION_SERVICE_URL: Optional[str] = Field(default=None, env="NOTIFICATION_SERVICE_URL")
    ANALYTICS_SERVICE_URL: Optional[str] = Field(default=None, env="ANALYTICS_SERVICE_URL")

    # Circuit Breaker Settings
    CIRCUIT_BREAKER_ENABLED: bool = Field(default=True, env="CIRCUIT_BREAKER_ENABLED")
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=5, env="CIRCUIT_BREAKER_FAILURE_THRESHOLD")
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=60, env="CIRCUIT_BREAKER_RECOVERY_TIMEOUT")

    # Database Connection Pool Settings (Enhanced)
    DATABASE_MIN_CONNECTIONS: int = Field(default=5, env="DATABASE_MIN_CONNECTIONS")
    DATABASE_MAX_CONNECTIONS: int = Field(default=50, env="DATABASE_MAX_CONNECTIONS")
    DATABASE_CONNECTION_TIMEOUT: int = Field(default=30, env="DATABASE_CONNECTION_TIMEOUT")
    DATABASE_QUERY_TIMEOUT: int = Field(default=30, env="DATABASE_QUERY_TIMEOUT")

    # Backup and Recovery Settings
    BACKUP_ENABLED: bool = Field(default=True, env="BACKUP_ENABLED")
    BACKUP_SCHEDULE: str = Field(default="0 2 * * *", env="BACKUP_SCHEDULE")  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = Field(default=30, env="BACKUP_RETENTION_DAYS")
    BACKUP_STORAGE_PATH: str = Field(default="/backups", env="BACKUP_STORAGE_PATH")

    class Config:
        env_file = ".env"
        case_sensitive = True

        # Allow environment variables to override file settings
        env_prefix = ""

    def get_database_url_for_env(self) -> str:
        """Get database URL based on environment."""
        if self.ENVIRONMENT == "testing":
            return "postgresql+asyncpg://postgres:varanasi@localhost:5432/nb_auth_test"
        return self.DATABASE_URL

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.ENVIRONMENT == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.ENVIRONMENT == "testing"

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

# Global settings instance
settings = get_settings()
