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
    if not date_str:
        return None

    try:
        # Try parsing ISO format with timezone
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except ValueError:
        try:
            # Try parsing without timezone
            return datetime.fromisoformat(date_str)
        except ValueError:
            try:
                # Try parsing standard format
                return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                logger.warning(f"Could not parse datetime: {date_str}")
                return None

def get_utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)

# Fixed function name reference
def utc_now() -> datetime:
    """Alias for get_utc_now for backward compatibility."""
    return get_utc_now()

def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result

def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def remove_none_values(d: Dict) -> Dict:
    """Remove None values from dictionary."""
    return {k: v for k, v in d.items() if v is not None}

def mask_sensitive_value(value: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive values for logging."""
    if not value or len(value) <= visible_chars:
        return mask_char * len(value) if value else ""

    return value[:visible_chars] + mask_char * (len(value) - visible_chars)

def retry_async(max_attempts: int = 3, delay: float = 1.0, backoff_factor: float = 2.0):
    """Decorator for retrying async functions with exponential backoff."""
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
                        wait_time = delay * (backoff_factor ** attempt)
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"All {max_attempts} attempts failed for {func.__name__}")

            raise last_exception
        return wrapper
    return decorator

def batch_process(items: List, batch_size: int = 100):
    """Process items in batches."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]

def calculate_pagination(total: int, page: int, page_size: int) -> Dict[str, Any]:
    """Calculate pagination metadata."""
    total_pages = (total + page_size - 1) // page_size
    has_prev = page > 1
    has_next = page < total_pages

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "prev_page": page - 1 if has_prev else None,
        "next_page": page + 1 if has_next else None
    }

def normalize_search_term(term: str) -> str:
    """Normalize search term for consistent searching."""
    return term.strip().lower() if term else ""

def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address."""
    try:
        return email.split('@')[1].lower()
    except (IndexError, AttributeError):
        return ""

def is_valid_uuid(uuid_string: str) -> bool:
    """Check if string is a valid UUID."""
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format."""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to specified length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def get_client_info(request) -> Dict[str, Any]:
    """Extract client information from request."""
    headers = dict(request.headers)

    return {
        "ip_address": getattr(request.client, 'host', 'unknown') if request.client else 'unknown',
        "user_agent": headers.get("user-agent", ""),
        "accept_language": headers.get("accept-language", ""),
        "referer": headers.get("referer", ""),
        "x_forwarded_for": headers.get("x-forwarded-for", ""),
        "x_real_ip": headers.get("x-real-ip", ""),
        "timestamp": get_utc_now().isoformat()
    }

def clean_dict_for_logging(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """Clean dictionary for safe logging by masking sensitive data."""
    if sensitive_keys is None:
        sensitive_keys = ["password", "token", "secret", "key", "authorization"]

    cleaned = {}
    for key, value in data.items():
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
            cleaned[key] = mask_sensitive_value(str(value)) if value else None
        elif isinstance(value, dict):
            cleaned[key] = clean_dict_for_logging(value, sensitive_keys)
        else:
            cleaned[key] = value

    return cleaned

def is_valid_email(email: str) -> bool:
    """Check if email format is valid."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def is_valid_phone(phone: str) -> bool:
    """Check if phone number format is valid."""
    import re
    # Basic phone validation - digits, spaces, dashes, parentheses, plus
    pattern = r'^\+?[\d\s\-\(\)]{10,}$'
    return bool(re.match(pattern, phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')))

def sanitize_string(value: str, max_length: int = None) -> str:
    """Sanitize string input by removing dangerous characters."""
    if not value:
        return ""

    # Remove null bytes and other dangerous characters
    sanitized = value.replace('\x00', '').replace('\r', '').replace('\n', ' ')

    # Trim whitespace
    sanitized = sanitized.strip()

    # Limit length if specified
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized

def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """Mask sensitive data leaving only specified number of characters visible."""
    if not data or len(data) <= visible_chars:
        return "*" * len(data) if data else ""

    return data[:visible_chars] + "*" * (len(data) - visible_chars)

def paginate_query_params(page: int = 1, size: int = 10, max_size: int = 100) -> Dict[str, int]:
    """Calculate pagination parameters."""
    page = max(1, page)
    size = max(1, min(size, max_size))
    offset = (page - 1) * size

    return {
        "page": page,
        "size": size,
        "offset": offset,
        "limit": size
    }

def create_pagination_response(items: List[Any], total: int, page: int, size: int) -> Dict[str, Any]:
    """Create standardized pagination response."""
    total_pages = (total + size - 1) // size  # Ceiling division

    return {
        "items": items,
        "pagination": {
            "page": page,
            "size": size,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1
        }
    }

def validate_password_strength(password: str) -> Dict[str, Any]:
    """Validate password strength against requirements."""
    from app.core.config import settings

    issues = []
    score = 0

    # Length check
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        issues.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
    else:
        score += 1

    # Uppercase check
    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    else:
        score += 1

    # Lowercase check
    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    else:
        score += 1

    # Digit check
    if settings.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one number")
    else:
        score += 1

    # Special character check
    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            issues.append("Password must contain at least one special character")
        else:
            score += 1

    strength_levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
    strength = strength_levels[min(score, len(strength_levels) - 1)]

    return {
        "is_valid": len(issues) == 0,
        "issues": issues,
        "strength": strength,
        "score": score
    }

def generate_random_string(length: int = 32, include_special: bool = False) -> str:
    """Generate a random string of specified length."""
    import random
    import string

    chars = string.ascii_letters + string.digits
    if include_special:
        chars += "!@#$%^&*"

    return ''.join(random.choice(chars) for _ in range(length))

def hash_string(value: str, salt: str = "") -> str:
    """Hash a string with optional salt."""
    import hashlib
    return hashlib.sha256((value + salt).encode()).hexdigest()

def clean_dict(data: Dict[str, Any], remove_none: bool = True, remove_empty: bool = False) -> Dict[str, Any]:
    """Clean dictionary by removing None/empty values."""
    cleaned = {}

    for key, value in data.items():
        if remove_none and value is None:
            continue
        if remove_empty and value == "":
            continue
        if isinstance(value, dict):
            cleaned_value = clean_dict(value, remove_none, remove_empty)
            if cleaned_value:  # Only include non-empty dicts
                cleaned[key] = cleaned_value
        else:
            cleaned[key] = value

    return cleaned

def get_client_info(request) -> Dict[str, Any]:
    """Extract client information from request."""
    headers = dict(request.headers)

    return {
        "ip_address": getattr(request.client, 'host', 'unknown') if request.client else 'unknown',
        "user_agent": headers.get("user-agent", ""),
        "accept_language": headers.get("accept-language", ""),
        "referer": headers.get("referer", ""),
        "x_forwarded_for": headers.get("x-forwarded-for", ""),
        "x_real_ip": headers.get("x-real-ip", ""),
        "timestamp": get_utc_now().isoformat()
    }

# Export all helper functions
__all__ = [
    "generate_correlation_id",
    "to_camel_case",
    "to_snake_case",
    "safe_json_loads",
    "safe_json_dumps",
    "format_datetime",
    "parse_datetime",
    "get_utc_now",
    "utc_now",
    "is_valid_email",
    "is_valid_phone",
    "sanitize_string",
    "mask_sensitive_data",
    "paginate_query_params",
    "create_pagination_response",
    "retry_async",
    "format_file_size",
    "validate_password_strength",
    "generate_random_string",
    "hash_string",
    "deep_merge_dicts",
    "clean_dict",
    "get_client_info"
]
