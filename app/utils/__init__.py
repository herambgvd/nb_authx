"""
Utils package initialization for AuthX.
Imports all utility functions and classes.
"""

# Security utilities
from .security import (
    create_access_token,
    create_refresh_token,
    verify_token,
    verify_password,
    get_password_hash,
    generate_password,
    generate_secure_token,
    generate_mfa_secret,
    generate_mfa_qr_code,
    verify_mfa_token,
    hash_api_key,
    verify_api_key,
    create_csrf_token,
    verify_csrf_token,
    generate_verification_code,
    create_signature,
    verify_signature,
)

# Validation utilities
from .validation import (
    validate_password,
    validate_email_address,
    validate_phone_number,
    validate_url,
    validate_ip_address,
    sanitize_string,
    validate_slug,
    validate_username,
    validate_color_hex,
    validate_json_data,
)

# Helper utilities
from .helpers import (
    generate_correlation_id,
    to_camel_case,
    to_snake_case,
    safe_json_loads,
    safe_json_dumps,
    format_datetime,
    parse_datetime,
    utc_now,
    deep_merge_dicts,
    flatten_dict,
    chunk_list,
    remove_none_values,
    mask_sensitive_value,
    retry_async,
    batch_process,
    calculate_pagination,
    normalize_search_term,
    extract_domain_from_email,
    is_valid_uuid,
    format_file_size,
    truncate_text,
    get_client_info,
    clean_dict_for_logging,
)

__all__ = [
    # Security
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "verify_password",
    "get_password_hash",
    "generate_password",
    "generate_secure_token",
    "generate_mfa_secret",
    "generate_mfa_qr_code",
    "verify_mfa_token",
    "hash_api_key",
    "verify_api_key",
    "create_csrf_token",
    "verify_csrf_token",
    "generate_verification_code",
    "create_signature",
    "verify_signature",

    # Validation
    "validate_password",
    "validate_email_address",
    "validate_phone_number",
    "validate_url",
    "validate_ip_address",
    "sanitize_string",
    "validate_slug",
    "validate_username",
    "validate_color_hex",
    "validate_json_data",

    # Helpers
    "generate_correlation_id",
    "to_camel_case",
    "to_snake_case",
    "safe_json_loads",
    "safe_json_dumps",
    "format_datetime",
    "parse_datetime",
    "utc_now",
    "deep_merge_dicts",
    "flatten_dict",
    "chunk_list",
    "remove_none_values",
    "mask_sensitive_value",
    "retry_async",
    "batch_process",
    "calculate_pagination",
    "normalize_search_term",
    "extract_domain_from_email",
    "is_valid_uuid",
    "format_file_size",
    "truncate_text",
    "get_client_info",
    "clean_dict_for_logging",
]
