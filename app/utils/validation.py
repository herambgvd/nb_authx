"""
Validation utilities for AuthX.
Provides data validation, sanitization, and formatting utilities.
"""
import re
import ipaddress
from typing import Dict, Any, List, Optional, Union
from email_validator import validate_email, EmailNotValidError
from urllib.parse import urlparse

from app.core.config import settings

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

def validate_email_address(email: str) -> Dict[str, Any]:
    """
    Validate email address format and domain.

    Args:
        email: Email address to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "normalized": None}

    try:
        validation = validate_email(email)
        result["normalized"] = validation.email
    except EmailNotValidError as e:
        result["valid"] = False
        result["errors"].append(str(e))

    return result

def validate_phone_number(phone: str) -> Dict[str, Any]:
    """
    Validate phone number format.

    Args:
        phone: Phone number to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "normalized": None}

    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', phone)

    # Check length (10-15 digits)
    if len(digits_only) < 10 or len(digits_only) > 15:
        result["valid"] = False
        result["errors"].append("Phone number must be between 10 and 15 digits")
    else:
        # Format as +1234567890
        result["normalized"] = f"+{digits_only}"

    return result

def validate_url(url: str) -> Dict[str, Any]:
    """
    Validate URL format.

    Args:
        url: URL to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "normalized": None}

    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            result["valid"] = False
            result["errors"].append("Invalid URL format")
        else:
            result["normalized"] = url.lower()
    except Exception as e:
        result["valid"] = False
        result["errors"].append(f"Invalid URL: {str(e)}")

    return result

def validate_ip_address(ip: str) -> Dict[str, Any]:
    """
    Validate IP address (IPv4 or IPv6).

    Args:
        ip: IP address to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "version": None, "is_private": None}

    try:
        ip_obj = ipaddress.ip_address(ip)
        result["version"] = ip_obj.version
        result["is_private"] = ip_obj.is_private
    except ValueError as e:
        result["valid"] = False
        result["errors"].append(f"Invalid IP address: {str(e)}")

    return result

def sanitize_string(value: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize string input by removing dangerous characters.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        return str(value)

    # Remove null bytes and control characters
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')

    # Strip whitespace
    sanitized = sanitized.strip()

    # Truncate if needed
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized

def validate_slug(slug: str) -> Dict[str, Any]:
    """
    Validate slug format (URL-friendly identifier).

    Args:
        slug: Slug to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    # Check format: lowercase letters, numbers, hyphens
    if not re.match(r'^[a-z0-9-]+$', slug):
        result["valid"] = False
        result["errors"].append("Slug must contain only lowercase letters, numbers, and hyphens")

    # Check length
    if len(slug) < 3 or len(slug) > 50:
        result["valid"] = False
        result["errors"].append("Slug must be between 3 and 50 characters")

    # Cannot start or end with hyphen
    if slug.startswith('-') or slug.endswith('-'):
        result["valid"] = False
        result["errors"].append("Slug cannot start or end with a hyphen")

    # Cannot have consecutive hyphens
    if '--' in slug:
        result["valid"] = False
        result["errors"].append("Slug cannot contain consecutive hyphens")

    return result

def validate_username(username: str) -> Dict[str, Any]:
    """
    Validate username format.

    Args:
        username: Username to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    # Check format: letters, numbers, underscores, dots
    if not re.match(r'^[a-zA-Z0-9._]+$', username):
        result["valid"] = False
        result["errors"].append("Username can only contain letters, numbers, dots, and underscores")

    # Check length
    if len(username) < 3 or len(username) > 30:
        result["valid"] = False
        result["errors"].append("Username must be between 3 and 30 characters")

    # Cannot start or end with dot or underscore
    if username.startswith('.') or username.startswith('_') or username.endswith('.') or username.endswith('_'):
        result["valid"] = False
        result["errors"].append("Username cannot start or end with a dot or underscore")

    # Cannot have consecutive dots or underscores
    if '..' in username or '__' in username:
        result["valid"] = False
        result["errors"].append("Username cannot contain consecutive dots or underscores")

    return result

def validate_color_hex(color: str) -> Dict[str, Any]:
    """
    Validate hex color format.

    Args:
        color: Hex color to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "normalized": None}

    # Check format: #RRGGBB
    if not re.match(r'^#[0-9A-Fa-f]{6}$', color):
        result["valid"] = False
        result["errors"].append("Color must be in hex format (#RRGGBB)")
    else:
        result["normalized"] = color.upper()

    return result

def validate_json_data(data: Any, max_depth: int = 10, max_items: int = 1000) -> Dict[str, Any]:
    """
    Validate JSON data structure for safety.

    Args:
        data: Data to validate
        max_depth: Maximum nesting depth
        max_items: Maximum number of items

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    def count_items(obj, depth=0):
        if depth > max_depth:
            result["valid"] = False
            result["errors"].append(f"JSON data exceeds maximum depth of {max_depth}")
            return 0

        count = 0
        if isinstance(obj, dict):
            count += len(obj)
            for value in obj.values():
                count += count_items(value, depth + 1)
        elif isinstance(obj, list):
            count += len(obj)
            for item in obj:
                count += count_items(item, depth + 1)
        else:
            count += 1

        return count

    total_items = count_items(data)
    if total_items > max_items:
        result["valid"] = False
        result["errors"].append(f"JSON data exceeds maximum items limit of {max_items}")

    return result
