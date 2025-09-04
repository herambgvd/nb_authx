"""
Helper utilities for AuthX.
Provides common helper functions for data processing, formatting, and operations.
"""
import uuid
import json
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Callable
from functools import wraps
import logging
from fastapi import Request

logger = logging.getLogger(__name__)

def generate_correlation_id() -> str:
    """Generate a unique correlation ID for request tracking."""
    return str(uuid.uuid4())

def to_camel_case(snake_str: str) -> str:
    """Convert snake_case to camelCase."""
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])

def to_snake_case(camel_str: str) -> str:
    """Convert camelCase to snake_case."""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel_str)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string with default fallback."""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default

def safe_json_dumps(obj: Any, default: Any = None) -> str:
    """Safely serialize object to JSON string."""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default or "{}"

def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string."""
    if not dt:
        return ""
    return dt.strftime(format_str)

def parse_datetime(date_str: str) -> Optional[datetime]:
    """Parse datetime from ISO string."""
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None

def get_client_info(request: Request) -> Dict[str, Any]:
    """
    Extract client information from request for security analysis.

    Args:
        request: FastAPI Request object

    Returns:
        Dictionary containing client information
    """
    # Get client IP address
    ip_address = "unknown"
    if request.client:
        ip_address = request.client.host

    # Check for forwarded headers (for proxy/load balancer scenarios)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP in the chain
        ip_address = forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        ip_address = real_ip

    # Extract other useful information
    user_agent = request.headers.get("user-agent", "unknown")
    accept_language = request.headers.get("accept-language", "")
    referer = request.headers.get("referer", "")

    return {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "accept_language": accept_language,
        "referer": referer,
        "method": request.method,
        "url": str(request.url),
        "timestamp": datetime.utcnow().isoformat()
    }

def mask_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """
    Mask sensitive data in dictionary for logging/audit purposes.

    Args:
        data: Dictionary to mask
        sensitive_keys: List of keys to mask (default: common sensitive keys)

    Returns:
        Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = [
            "password", "token", "secret", "key", "credential",
            "authorization", "cookie", "session"
        ]

    masked_data = data.copy()

    for key, value in masked_data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            if isinstance(value, str) and len(value) > 4:
                masked_data[key] = value[:2] + "*" * (len(value) - 4) + value[-2:]
            else:
                masked_data[key] = "***"

    return masked_data

def validate_uuid(uuid_string: str) -> bool:
    """
    Validate if string is a valid UUID.

    Args:
        uuid_string: String to validate

    Returns:
        True if valid UUID
    """
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def truncate_string(text: str, max_length: int = 255, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix

def retry_async(max_attempts: int = 3, delay: float = 1.0):
    """
    Decorator for retrying async functions.

    Args:
        max_attempts: Maximum number of attempts
        delay: Delay between attempts in seconds
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay * (attempt + 1))
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}")
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}: {e}")

            raise last_exception

        return wrapper
    return decorator

def paginate_query_params(
    page: int = 1,
    size: int = 20,
    max_size: int = 100
) -> Dict[str, int]:
    """
    Validate and normalize pagination parameters.

    Args:
        page: Page number (1-based)
        size: Page size
        max_size: Maximum allowed page size

    Returns:
        Dictionary with normalized pagination parameters
    """
    # Validate and normalize page
    page = max(1, page)

    # Validate and normalize size
    size = max(1, min(size, max_size))

    # Calculate offset
    offset = (page - 1) * size

    return {
        "page": page,
        "size": size,
        "offset": offset,
        "limit": size
    }

def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.utcnow()

def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.

    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)

    Returns:
        Merged dictionary
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value

    return result

def flatten_dict(nested_dict: Dict[str, Any], separator: str = '_') -> Dict[str, Any]:
    """
    Flatten a nested dictionary.

    Args:
        nested_dict: Dictionary to flatten
        separator: Separator for nested keys

    Returns:
        Flattened dictionary
    """
    def _flatten(obj, parent_key='', sep=separator):
        items = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(_flatten(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
        return dict(items)

    return _flatten(nested_dict)

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.

    Args:
        lst: List to chunk
        chunk_size: Size of each chunk

    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def remove_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove None values from dictionary.

    Args:
        data: Dictionary to clean

    Returns:
        Dictionary without None values
    """
    return {k: v for k, v in data.items() if v is not None}

def mask_sensitive_value(value: str, show_chars: int = 4) -> str:
    """
    Mask a sensitive value showing only first and last characters.

    Args:
        value: Value to mask
        show_chars: Number of characters to show at start/end

    Returns:
        Masked value
    """
    if not value or len(value) <= show_chars * 2:
        return "*" * len(value) if value else ""

    return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]

def batch_process(items: List[Any], batch_size: int = 100) -> List[List[Any]]:
    """
    Process items in batches.

    Args:
        items: Items to process
        batch_size: Size of each batch

    Returns:
        List of batches
    """
    return chunk_list(items, batch_size)

def calculate_pagination(total: int, page: int = 1, size: int = 20) -> Dict[str, Any]:
    """
    Calculate pagination metadata.

    Args:
        total: Total number of items
        page: Current page number
        size: Items per page

    Returns:
        Pagination metadata
    """
    total_pages = max(1, (total + size - 1) // size)
    has_next = page < total_pages
    has_prev = page > 1

    return {
        "total": total,
        "page": page,
        "size": size,
        "total_pages": total_pages,
        "has_next": has_next,
        "has_prev": has_prev,
        "offset": (page - 1) * size
    }

def normalize_search_term(term: str) -> str:
    """
    Normalize search term for consistent searching.

    Args:
        term: Search term to normalize

    Returns:
        Normalized search term
    """
    if not term:
        return ""

    return term.strip().lower()

def extract_domain_from_email(email: str) -> str:
    """
    Extract domain from email address.

    Args:
        email: Email address

    Returns:
        Domain part of email
    """
    if not email or "@" not in email:
        return ""

    return email.split("@")[-1].lower()

def is_valid_uuid(uuid_string: str) -> bool:
    """
    Check if string is a valid UUID (alias for validate_uuid).

    Args:
        uuid_string: String to validate

    Returns:
        True if valid UUID
    """
    return validate_uuid(uuid_string)

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted file size string
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.1f} {size_names[i]}"

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to maximum length (alias for truncate_string).

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated text
    """
    return truncate_string(text, max_length, suffix)

def clean_dict_for_logging(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean dictionary for safe logging (alias for mask_sensitive_data).

    Args:
        data: Dictionary to clean

    Returns:
        Dictionary with sensitive data masked
    """
    return mask_sensitive_data(data)

# Export all helper functions
__all__ = [
    "generate_correlation_id",
    "to_camel_case",
    "to_snake_case",
    "safe_json_loads",
    "safe_json_dumps",
    "format_datetime",
    "parse_datetime",
    "get_client_info",
    "mask_sensitive_data",
    "validate_uuid",
    "truncate_string",
    "retry_async",
    "paginate_query_params",
    "utc_now",
    "deep_merge_dicts",
    "flatten_dict",
    "chunk_list",
    "remove_none_values",
    "mask_sensitive_value",
    "batch_process",
    "calculate_pagination",
    "normalize_search_term",
    "extract_domain_from_email",
    "is_valid_uuid",
    "format_file_size",
    "truncate_text",
    "clean_dict_for_logging"
]
