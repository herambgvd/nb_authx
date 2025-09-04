"""
Utils package initialization for AuthX.
Imports all utility functions and classes.
"""

# Security utilities
from .security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    generate_password_reset_token,
    verify_password_reset_token,
    generate_email_verification_token,
    verify_email_verification_token,
    generate_secure_token,
    generate_api_key,
    generate_secret_key,
    generate_totp_secret,
    generate_totp_qr_code,
    verify_totp_token,
    hash_api_key,
    verify_hmac_signature,
    generate_hmac_signature,
    is_strong_password
)

# Helper utilities
from .helpers import (
    generate_slug,
    parse_datetime,
    format_datetime,
    sanitize_input,
    mask_sensitive_data
)

# Validation utilities
from .validation import (
    validate_email,
    validate_username,
    validate_password,
    validate_phone,
    validate_url
)

# Export all utility functions
__all__ = [
    # Security
    "create_access_token",
    "create_refresh_token",
    "verify_password",
    "get_password_hash",
    "generate_password_reset_token",
    "verify_password_reset_token",
    "generate_email_verification_token",
    "verify_email_verification_token",
    "generate_secure_token",
    "generate_api_key",
    "generate_secret_key",
    "generate_totp_secret",
    "generate_totp_qr_code",
    "verify_totp_token",
    "hash_api_key",
    "verify_hmac_signature",
    "generate_hmac_signature",
    "is_strong_password",

    # Helpers
    "generate_slug",
    "parse_datetime",
    "format_datetime",
    "sanitize_input",
    "mask_sensitive_data",

    # Validation
    "validate_email",
    "validate_username",
    "validate_password",
    "validate_phone",
    "validate_url"
]
