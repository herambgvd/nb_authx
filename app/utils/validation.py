"""
Validation utilities for AuthX.
Provides data validation, sanitization, and formatting utilities.
"""
import re
import ipaddress
from typing import Dict, Any, List, Optional, Union
from email_validator import validate_email as email_validate, EmailNotValidError
from urllib.parse import urlparse
import uuid

def validate_email(email: str) -> Dict[str, Any]:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not email:
        result["valid"] = False
        result["errors"].append("Email is required")
        return result

    try:
        valid = email_validate(email)
        result["normalized_email"] = valid.email
    except EmailNotValidError as e:
        result["valid"] = False
        result["errors"].append(str(e))

    return result

def validate_username(username: str) -> Dict[str, Any]:
    """
    Validate username format and requirements.

    Args:
        username: Username to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not username:
        result["valid"] = False
        result["errors"].append("Username is required")
        return result

    # Check length
    if len(username) < 3:
        result["valid"] = False
        result["errors"].append("Username must be at least 3 characters long")

    if len(username) > 50:
        result["valid"] = False
        result["errors"].append("Username cannot be longer than 50 characters")

    # Check format - alphanumeric, underscore, hyphen allowed
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        result["valid"] = False
        result["errors"].append("Username can only contain letters, numbers, underscores, and hyphens")

    # Cannot start with number
    if username[0].isdigit():
        result["valid"] = False
        result["errors"].append("Username cannot start with a number")

    return result

def validate_password(password: str) -> Dict[str, Any]:
    """
    Validate password against security requirements.

    Args:
        password: The password to validate

    Returns:
        Dict with validation result and requirements
    """
    result = {"valid": True, "errors": []}

    if not password:
        result["valid"] = False
        result["errors"].append("Password is required")
        return result

    # Check minimum length
    if len(password) < 8:
        result["valid"] = False
        result["errors"].append("Password must be at least 8 characters long")

    # Check for uppercase letters
    if not any(c.isupper() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one uppercase letter")

    # Check for lowercase letters
    if not any(c.islower() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one lowercase letter")

    # Check for digits
    if not any(c.isdigit() for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one digit")

    # Check for special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        result["valid"] = False
        result["errors"].append("Password must contain at least one special character")

    return result

def validate_phone(phone: str) -> Dict[str, Any]:
    """
    Validate phone number format.

    Args:
        phone: Phone number to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not phone:
        result["valid"] = False
        result["errors"].append("Phone number is required")
        return result

    # Remove all non-digit characters for validation
    digits_only = re.sub(r'\D', '', phone)

    # Check if it's a valid length (10-15 digits)
    if len(digits_only) < 10:
        result["valid"] = False
        result["errors"].append("Phone number must have at least 10 digits")
    elif len(digits_only) > 15:
        result["valid"] = False
        result["errors"].append("Phone number cannot have more than 15 digits")

    # Check for valid phone pattern
    phone_pattern = r'^[\+]?[1-9]?[\d\s\-\(\)\.]{8,20}$'
    if not re.match(phone_pattern, phone):
        result["valid"] = False
        result["errors"].append("Invalid phone number format")

    return result

def validate_url(url: str) -> Dict[str, Any]:
    """
    Validate URL format.

    Args:
        url: URL to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not url:
        result["valid"] = False
        result["errors"].append("URL is required")
        return result

    try:
        parsed = urlparse(url)

        if not parsed.scheme:
            result["valid"] = False
            result["errors"].append("URL must include a scheme (http:// or https://)")

        if not parsed.netloc:
            result["valid"] = False
            result["errors"].append("URL must include a domain")

        if parsed.scheme not in ['http', 'https']:
            result["valid"] = False
            result["errors"].append("URL scheme must be http or https")

    except Exception as e:
        result["valid"] = False
        result["errors"].append(f"Invalid URL format: {str(e)}")

    return result

def validate_uuid(uuid_string: str) -> bool:
    """
    Validate UUID format.

    Args:
        uuid_string: String to validate as UUID

    Returns:
        True if valid UUID, False otherwise
    """
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def validate_ip_address(ip: str) -> Dict[str, Any]:
    """
    Validate IP address format.

    Args:
        ip: IP address to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": [], "type": None}

    if not ip:
        result["valid"] = False
        result["errors"].append("IP address is required")
        return result

    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            result["type"] = "ipv4"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            result["type"] = "ipv6"
    except ValueError as e:
        result["valid"] = False
        result["errors"].append(f"Invalid IP address: {str(e)}")

    return result

def validate_slug(slug: str) -> Dict[str, Any]:
    """
    Validate slug format for URLs.

    Args:
        slug: Slug to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not slug:
        result["valid"] = False
        result["errors"].append("Slug is required")
        return result

    # Check length
    if len(slug) < 3:
        result["valid"] = False
        result["errors"].append("Slug must be at least 3 characters long")

    if len(slug) > 100:
        result["valid"] = False
        result["errors"].append("Slug cannot be longer than 100 characters")

    # Check format - lowercase letters, numbers, and hyphens only
    if not re.match(r'^[a-z0-9-]+$', slug):
        result["valid"] = False
        result["errors"].append("Slug can only contain lowercase letters, numbers, and hyphens")

    # Cannot start or end with hyphen
    if slug.startswith('-') or slug.endswith('-'):
        result["valid"] = False
        result["errors"].append("Slug cannot start or end with a hyphen")

    return result

def sanitize_html(text: str) -> str:
    """
    Sanitize HTML content by removing dangerous tags.

    Args:
        text: HTML text to sanitize

    Returns:
        Sanitized HTML text
    """
    import html

    if not text:
        return ""

    # Escape HTML entities
    sanitized = html.escape(text)

    return sanitized

def validate_file_extension(filename: str, allowed_extensions: List[str]) -> Dict[str, Any]:
    """
    Validate file extension against allowed list.

    Args:
        filename: Name of the file
        allowed_extensions: List of allowed extensions

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not filename:
        result["valid"] = False
        result["errors"].append("Filename is required")
        return result

    # Extract file extension
    extension = filename.lower().split('.')[-1] if '.' in filename else ''

    if not extension:
        result["valid"] = False
        result["errors"].append("File must have an extension")
        return result

    if extension not in [ext.lower() for ext in allowed_extensions]:
        result["valid"] = False
        result["errors"].append(f"File extension '{extension}' is not allowed. Allowed: {', '.join(allowed_extensions)}")

    return result

def validate_date_range(start_date: str, end_date: str) -> Dict[str, Any]:
    """
    Validate date range.

    Args:
        start_date: Start date string
        end_date: End date string

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    try:
        from datetime import datetime

        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))

        if start >= end:
            result["valid"] = False
            result["errors"].append("Start date must be before end date")

    except ValueError as e:
        result["valid"] = False
        result["errors"].append(f"Invalid date format: {str(e)}")

    return result

def validate_organization_name(name: str) -> Dict[str, Any]:
    """
    Validate organization name.

    Args:
        name: Organization name to validate

    Returns:
        Dict with validation result
    """
    result = {"valid": True, "errors": []}

    if not name:
        result["valid"] = False
        result["errors"].append("Organization name is required")
        return result

    if len(name) < 2:
        result["valid"] = False
        result["errors"].append("Organization name must be at least 2 characters long")

    if len(name) > 100:
        result["valid"] = False
        result["errors"].append("Organization name cannot be longer than 100 characters")

    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9\s\-\.\_\&]+$', name):
        result["valid"] = False
        result["errors"].append("Organization name contains invalid characters")

    return result
