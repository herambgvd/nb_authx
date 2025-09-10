"""
AuthX Python SDK - Exception classes for error handling.
"""

class AuthXException(Exception):
    """Base exception for all AuthX SDK errors."""
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

class AuthenticationError(AuthXException):
    """Raised when authentication fails."""
    pass

class AuthorizationError(AuthXException):
    """Raised when user doesn't have permission for the requested action."""
    pass

class ValidationError(AuthXException):
    """Raised when request validation fails."""
    pass

class RateLimitError(AuthXException):
    """Raised when rate limit is exceeded."""
    pass

class ServiceUnavailableError(AuthXException):
    """Raised when the AuthX service is unavailable."""
    pass

class TokenExpiredError(AuthenticationError):
    """Raised when authentication token has expired."""
    pass

class NetworkError(AuthXException):
    """Raised when network communication fails."""
    pass
