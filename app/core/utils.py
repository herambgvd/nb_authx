"""
Core utility functions for the AuthX service.
This module provides common utilities for logging, validation, and other shared functionality.
"""
import logging
import sys
from typing import Any, Dict, Optional
from datetime import datetime
from pathlib import Path

from app.core.config import settings


def setup_logging() -> logging.Logger:
    """
    Set up application logging configuration.

    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("authx")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))

    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if settings.LOG_FILE:
        # Ensure log directory exists
        log_path = Path(settings.LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(settings.LOG_FILE)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def validate_password(password: str) -> Dict[str, Any]:
    """
    Validate password against security requirements.

    Args:
        password: The password to validate

    Returns:
        Dict with validation result and requirements
    """
    result = {
        "valid": True,
        "errors": [],
        "requirements": {
            "min_length": settings.PASSWORD_MIN_LENGTH,
            "require_uppercase": settings.PASSWORD_REQUIRE_UPPERCASE,
            "require_lowercase": settings.PASSWORD_REQUIRE_LOWERCASE,
            "require_digits": settings.PASSWORD_REQUIRE_DIGITS,
            "require_special": settings.PASSWORD_REQUIRE_SPECIAL
        }
    }

    # Check minimum length
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        result["valid"] = False
        result["errors"].append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")

    # Check for uppercase letters
    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one uppercase letter")

    # Check for lowercase letters
    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one lowercase letter")

    # Check for digits
    if settings.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one digit")

    # Check for special characters
    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            result["valid"] = False
            result["errors"].append("Password must contain at least one special character")

    return result


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe storage.

    Args:
        filename: The original filename

    Returns:
        Sanitized filename
    """
    import re

    # Remove or replace unsafe characters
    filename = re.sub(r'[^\w\-_\.]', '_', filename)

    # Ensure it doesn't start with a dot
    if filename.startswith('.'):
        filename = '_' + filename[1:]

    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        filename = name[:max_name_length] + ('.' + ext if ext else '')

    return filename


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def get_client_info(request) -> Dict[str, Any]:
    """
    Extract client information from request.

    Args:
        request: FastAPI request object

    Returns:
        Dict with client information
    """
    headers = dict(request.headers)

    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": headers.get("user-agent", ""),
        "accept_language": headers.get("accept-language", ""),
        "referer": headers.get("referer", ""),
        "x_forwarded_for": headers.get("x-forwarded-for", ""),
        "x_real_ip": headers.get("x-real-ip", ""),
        "timestamp": datetime.utcnow().isoformat()
    }


def mask_sensitive_data(data: str, mask_char: str = "*", show_last: int = 4) -> str:
    """
    Mask sensitive data for logging.

    Args:
        data: The sensitive data to mask
        mask_char: Character to use for masking
        show_last: Number of characters to show at the end

    Returns:
        Masked string
    """
    if not data or len(data) <= show_last:
        return mask_char * len(data) if data else ""

    masked_length = len(data) - show_last
    return mask_char * masked_length + data[-show_last:]


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID for request tracking.

    Returns:
        UUID string for correlation tracking
    """
    import uuid
    return str(uuid.uuid4())


def is_valid_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid email format, False otherwise
    """
    import re

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to specified length.

    Args:
        text: String to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to add when truncating

    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


def get_environment_info() -> Dict[str, Any]:
    """
    Get environment information for debugging.

    Returns:
        Dict with environment details
    """
    import platform
    import os

    return {
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "debug": settings.DEBUG,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "hostname": platform.node(),
        "pid": os.getpid(),
        "timestamp": datetime.utcnow().isoformat()
    }


# Initialize logger for the application
logger = setup_logging()
