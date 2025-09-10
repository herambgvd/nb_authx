"""
AuthX Python SDK - Official SDK for AuthX Authentication Service
Provides easy integration for microservices and external applications.
"""

from .client import AuthXClient
from .models import (
    User, Organization, Role, Location,
    AuthResponse, TokenResponse, UserCreate, UserUpdate
)
from .exceptions import (
    AuthXException, AuthenticationError, AuthorizationError,
    ValidationError, RateLimitError, ServiceUnavailableError
)

__version__ = "1.0.0"
__author__ = "AuthX Team"

__all__ = [
    "AuthXClient",
    "User", "Organization", "Role", "Location",
    "AuthResponse", "TokenResponse", "UserCreate", "UserUpdate",
    "AuthXException", "AuthenticationError", "AuthorizationError",
    "ValidationError", "RateLimitError", "ServiceUnavailableError"
]
