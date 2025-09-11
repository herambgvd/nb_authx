"""
Configuration settings for AuthX application.
Manages environment variables, database settings, security configuration, and feature flags.
"""
from typing import List, Optional, Dict, Any
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
    DATABASE_URL: str = Field(env="DATABASE_URL", default="postgresql+asyncpg://postgres:postgres@localhost:5432/nb_auth")
    ALEMBIC_DATABASE_URL: str = Field(env="ALEMBIC_DATABASE_URL", default="postgresql://postgres:postgres@localhost:5432/nb_auth")
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

    # Enhanced Email Service Provider Settings
    MAILGUN_API_KEY: Optional[str] = Field(default=None, env="MAILGUN_API_KEY")
    MAILGUN_DOMAIN: Optional[str] = Field(default=None, env="MAILGUN_DOMAIN")
    MAILGUN_BASE_URL: str = Field(default="https://api.mailgun.net/v3", env="MAILGUN_BASE_URL")

    SENDGRID_API_KEY: Optional[str] = Field(default=None, env="SENDGRID_API_KEY")

    # Email Service Selection and Fallback
    EMAIL_PROVIDER_PRIORITY: List[str] = Field(default=["smtp", "mailgun", "sendgrid"], env="EMAIL_PROVIDER_PRIORITY")
    EMAIL_FALLBACK_ENABLED: bool = Field(default=True, env="EMAIL_FALLBACK_ENABLED")
    EMAIL_RETRY_ATTEMPTS: int = Field(default=3, env="EMAIL_RETRY_ATTEMPTS")

    # Production Email Cost Optimization
    EMAIL_RATE_LIMIT_PER_HOUR: int = Field(default=1000, env="EMAIL_RATE_LIMIT_PER_HOUR")
    EMAIL_BATCH_SIZE: int = Field(default=100, env="EMAIL_BATCH_SIZE")
    EMAIL_QUEUE_ENABLED: bool = Field(default=True, env="EMAIL_QUEUE_ENABLED")

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

    # Development Settings - Added missing fields
    DEV_AUTO_MIGRATIONS: bool = Field(default=True, env="DEV_AUTO_MIGRATIONS")
    DEV_SEED_DATA: bool = Field(default=True, env="DEV_SEED_DATA")
    DEV_DEBUG_QUERIES: bool = Field(default=False, env="DEV_DEBUG_QUERIES")
    DEV_MOCK_EXTERNAL_SERVICES: bool = Field(default=False, env="DEV_MOCK_EXTERNAL_SERVICES")

    # Production Settings - Added missing fields
    PROD_ENABLE_GZIP: bool = Field(default=True, env="PROD_ENABLE_GZIP")
    PROD_STATIC_FILE_CACHING: bool = Field(default=True, env="PROD_STATIC_FILE_CACHING")
    PROD_DATABASE_CONNECTION_POOLING: bool = Field(default=True, env="PROD_DATABASE_CONNECTION_POOLING")
    PROD_REDIS_CLUSTERING: bool = Field(default=False, env="PROD_REDIS_CLUSTERING")

    # Container Settings - Added missing fields
    CONTAINER_PORT: int = Field(default=8000, env="CONTAINER_PORT")
    CONTAINER_WORKERS: int = Field(default=4, env="CONTAINER_WORKERS")
    CONTAINER_TIMEOUT: int = Field(default=30, env="CONTAINER_TIMEOUT")
    CONTAINER_MAX_REQUESTS: int = Field(default=1000, env="CONTAINER_MAX_REQUESTS")
    CONTAINER_MAX_REQUESTS_JITTER: int = Field(default=100, env="CONTAINER_MAX_REQUESTS_JITTER")

    # Health Check Settings - Added missing fields
    HEALTH_CHECK_PATH: str = Field(default="/health", env="HEALTH_CHECK_PATH")
    READINESS_CHECK_PATH: str = Field(default="/health/readiness", env="READINESS_CHECK_PATH")
    LIVENESS_CHECK_PATH: str = Field(default="/health/liveness", env="LIVENESS_CHECK_PATH")

    # SSL/TLS Settings - Added missing fields
    USE_HTTPS: bool = Field(default=False, env="USE_HTTPS")
    SSL_CERT_PATH: Optional[str] = Field(default=None, env="SSL_CERT_PATH")
    SSL_KEY_PATH: Optional[str] = Field(default=None, env="SSL_KEY_PATH")
    SSL_CA_BUNDLE_PATH: Optional[str] = Field(default=None, env="SSL_CA_BUNDLE_PATH")

    # Additional Configuration - Added missing fields
    DEFAULT_TIMEZONE: str = Field(default="UTC", env="DEFAULT_TIMEZONE")
    DEFAULT_PAGE_SIZE: int = Field(default=50, env="DEFAULT_PAGE_SIZE")
    MAX_PAGE_SIZE: int = Field(default=1000, env="MAX_PAGE_SIZE")

    # Cache Settings - Added missing fields
    CACHE_DEFAULT_TTL: int = Field(default=3600, env="CACHE_DEFAULT_TTL")
    CACHE_AUTH_TTL: int = Field(default=1800, env="CACHE_AUTH_TTL")
    CACHE_USER_TTL: int = Field(default=600, env="CACHE_USER_TTL")

    # Session Settings - Added missing fields
    SESSION_COOKIE_NAME: str = Field(default="authx_session", env="SESSION_COOKIE_NAME")
    SESSION_COOKIE_SECURE: bool = Field(default=False, env="SESSION_COOKIE_SECURE")
    SESSION_COOKIE_HTTPONLY: bool = Field(default=True, env="SESSION_COOKIE_HTTPONLY")
    SESSION_COOKIE_SAMESITE: str = Field(default="lax", env="SESSION_COOKIE_SAMESITE")

    # Email Template Settings - Added missing fields
    EMAIL_TEMPLATE_WELCOME_SUBJECT: str = Field(default="Welcome to AuthX!", env="EMAIL_TEMPLATE_WELCOME_SUBJECT")
    EMAIL_TEMPLATE_PASSWORD_RESET_SUBJECT: str = Field(default="Password Reset Request", env="EMAIL_TEMPLATE_PASSWORD_RESET_SUBJECT")
    EMAIL_TEMPLATE_VERIFICATION_SUBJECT: str = Field(default="Verify Your Email Address", env="EMAIL_TEMPLATE_VERIFICATION_SUBJECT")
    EMAIL_TEMPLATE_SECURITY_ALERT_SUBJECT: str = Field(default="Security Alert", env="EMAIL_TEMPLATE_SECURITY_ALERT_SUBJECT")

    # Rate Limit Settings - Added missing fields
    RATE_LIMIT_LOGIN: str = Field(default="5_per_minute", env="RATE_LIMIT_LOGIN")
    RATE_LIMIT_REGISTER: str = Field(default="3_per_minute", env="RATE_LIMIT_REGISTER")
    RATE_LIMIT_PASSWORD_RESET: str = Field(default="2_per_minute", env="RATE_LIMIT_PASSWORD_RESET")
    RATE_LIMIT_EMAIL_VERIFICATION: str = Field(default="3_per_minute", env="RATE_LIMIT_EMAIL_VERIFICATION")

    # Webhook Settings - Added missing fields
    WEBHOOK_USER_CREATED_URL: Optional[str] = Field(default=None, env="WEBHOOK_USER_CREATED_URL")
    WEBHOOK_USER_UPDATED_URL: Optional[str] = Field(default=None, env="WEBHOOK_USER_UPDATED_URL")
    WEBHOOK_ORGANIZATION_CREATED_URL: Optional[str] = Field(default=None, env="WEBHOOK_ORGANIZATION_CREATED_URL")
    WEBHOOK_SECURITY_ALERT_URL: Optional[str] = Field(default=None, env="WEBHOOK_SECURITY_ALERT_URL")
    WEBHOOK_SECRET_KEY: str = Field(default="your-webhook-secret-key", env="WEBHOOK_SECRET_KEY")
    WEBHOOK_TIMEOUT: int = Field(default=30, env="WEBHOOK_TIMEOUT")
    WEBHOOK_RETRY_ATTEMPTS: int = Field(default=3, env="WEBHOOK_RETRY_ATTEMPTS")

    # APM Settings - Added missing fields
    APM_ENABLED: bool = Field(default=False, env="APM_ENABLED")
    APM_SERVICE_NAME: str = Field(default="authx", env="APM_SERVICE_NAME")
    APM_SERVICE_VERSION: str = Field(default="1.0.0", env="APM_SERVICE_VERSION")
    APM_ENVIRONMENT: str = Field(default="development", env="APM_ENVIRONMENT")

    # New Relic Settings - Added missing fields
    NEW_RELIC_LICENSE_KEY: Optional[str] = Field(default=None, env="NEW_RELIC_LICENSE_KEY")
    NEW_RELIC_APP_NAME: str = Field(default="AuthX", env="NEW_RELIC_APP_NAME")

    # Datadog Settings - Added missing fields
    DATADOG_API_KEY: Optional[str] = Field(default=None, env="DATADOG_API_KEY")
    DATADOG_APP_KEY: Optional[str] = Field(default=None, env="DATADOG_APP_KEY")

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

    # Feature Flags from .env - Added missing fields
    FEATURES_USER_REGISTRATION: bool = Field(default=True, env="FEATURES_USER_REGISTRATION")
    FEATURES_PASSWORD_RESET: bool = Field(default=True, env="FEATURES_PASSWORD_RESET")
    FEATURES_EMAIL_VERIFICATION: bool = Field(default=True, env="FEATURES_EMAIL_VERIFICATION")
    FEATURES_SOCIAL_LOGIN: bool = Field(default=False, env="FEATURES_SOCIAL_LOGIN")
    FEATURES_API_ACCESS: bool = Field(default=True, env="FEATURES_API_ACCESS")
    FEATURES_AUDIT_LOGGING: bool = Field(default=True, env="FEATURES_AUDIT_LOGGING")
    FEATURES_ADVANCED_ANALYTICS: bool = Field(default=True, env="FEATURES_ADVANCED_ANALYTICS")
    FEATURES_LOCATION_MANAGEMENT: bool = Field(default=True, env="FEATURES_LOCATION_MANAGEMENT")
    FEATURES_ORGANIZATION_MANAGEMENT: bool = Field(default=True, env="FEATURES_ORGANIZATION_MANAGEMENT")
    FEATURES_ROLE_BASED_ACCESS: bool = Field(default=True, env="FEATURES_ROLE_BASED_ACCESS")
    FEATURES_SUPER_ADMIN_PANEL: bool = Field(default=True, env="FEATURES_SUPER_ADMIN_PANEL")
    FEATURES_SYSTEM_MONITORING: bool = Field(default=True, env="FEATURES_SYSTEM_MONITORING")
    FEATURES_GOOGLE_MAPS_INTEGRATION: bool = Field(default=True, env="FEATURES_GOOGLE_MAPS_INTEGRATION")
    FEATURES_ADVANCED_EMAIL_SERVICE: bool = Field(default=True, env="FEATURES_ADVANCED_EMAIL_SERVICE")

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
        # Allow extra fields to prevent validation errors
        extra = "allow"
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

    def validate_configuration(self) -> Dict[str, Any]:
        """Validate critical configuration settings."""
        issues = []
        warnings = []

        # Check for default/insecure values
        if self.SECRET_KEY == "your-super-secret-key-change-in-production":
            issues.append("SECRET_KEY is using default value - CRITICAL SECURITY RISK")

        if len(self.SECRET_KEY) < 32:
            issues.append("SECRET_KEY should be at least 32 characters long")

        if self.SUPER_ADMIN_PASSWORD == "SuperSecurePassword123!":
            issues.append("SUPER_ADMIN_PASSWORD is using default value - SECURITY RISK")

        # Database configuration checks
        if "localhost" in self.DATABASE_URL and self.ENVIRONMENT == "production":
            warnings.append("Using localhost database in production environment")

        # Email configuration validation
        if not self.SMTP_USERNAME and not self.MAILGUN_API_KEY and not self.SENDGRID_API_KEY:
            issues.append("No email service configured - email functionality will fail")

        # Redis configuration
        if "localhost" in self.REDIS_URL and self.ENVIRONMENT == "production":
            warnings.append("Using localhost Redis in production environment")

        return {
            "status": "valid" if not issues else "invalid",
            "critical_issues": issues,
            "warnings": warnings
        }

    @property
    def email_service_configured(self) -> bool:
        """Check if at least one email service is configured."""
        return bool(
            (self.SMTP_USERNAME and self.SMTP_PASSWORD) or
            (self.MAILGUN_API_KEY and self.MAILGUN_DOMAIN) or
            self.SENDGRID_API_KEY
        )

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

# Global settings instance
settings = get_settings()
