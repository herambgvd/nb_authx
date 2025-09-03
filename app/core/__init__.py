"""
Core module for AuthX service.
This module provides central configuration, infrastructure services, and security utilities.
"""

from .config import Settings
from .infrastructure import (
    # Caching functions
    get_from_cache,
    set_cache,
    delete_from_cache,
    clear_cache_pattern,
    cache_key_generator,

    # Rate limiting
    check_rate_limit,

    # Health checks and monitoring
    check_redis_health,
    get_system_metrics,
    get_metrics,

    # Redis availability
    REDIS_AVAILABLE
)

from .security import (
    # Brute force protection
    check_brute_force,
    record_failed_login,
    reset_brute_force_counter,

    # Risk scoring
    calculate_login_risk_score,
    check_ip_risk,

    # Device fingerprinting
    generate_device_fingerprint,

    # User agent analysis
    is_suspicious_user_agent,

    # Geolocation
    get_country_from_ip,

    # Anomaly detection
    detect_anomalies,

    # Fraud detection
    detect_fraud,

    # Bot detection
    detect_bot
)

from .utils import (
    # Logging
    setup_logging,
    logger,

    # Validation
    validate_password,
    is_valid_email,

    # File handling
    sanitize_filename,
    format_file_size,

    # Request handling
    get_client_info,
    generate_correlation_id,

    # Data processing
    mask_sensitive_data,
    truncate_string,

    # Environment
    get_environment_info
)

__all__ = [
    # Configuration
    "Settings",

    # Infrastructure - Caching
    "get_from_cache",
    "set_cache",
    "delete_from_cache",
    "clear_cache_pattern",
    "cache_key_generator",

    # Infrastructure - Rate limiting
    "check_rate_limit",

    # Infrastructure - Health checks and monitoring
    "check_redis_health",
    "get_system_metrics",
    "get_metrics",

    # Infrastructure - Redis
    "REDIS_AVAILABLE",

    # Security - Brute force protection
    "check_brute_force",
    "record_failed_login",
    "reset_brute_force_counter",

    # Security - Risk scoring
    "calculate_login_risk_score",
    "check_ip_risk",

    # Security - Device analysis
    "generate_device_fingerprint",
    "is_suspicious_user_agent",

    # Security - Geolocation
    "get_country_from_ip",

    # Security - Detection systems
    "detect_anomalies",
    "detect_fraud",
    "detect_bot",

    # Utils - Logging
    "setup_logging",
    "logger",

    # Utils - Validation
    "validate_password",
    "is_valid_email",

    # Utils - File handling
    "sanitize_filename",
    "format_file_size",

    # Utils - Request handling
    "get_client_info",
    "generate_correlation_id",

    # Utils - Data processing
    "mask_sensitive_data",
    "truncate_string",

    # Utils - Environment
    "get_environment_info"
]
