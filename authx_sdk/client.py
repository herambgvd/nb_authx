"""
AuthX Python SDK Client - Main client class for microservice integration.
Provides easy integration with AuthX authentication service.
"""
import asyncio
import logging
from typing import Optional, List, Dict, Any, Union
from urllib.parse import urljoin
import httpx
from datetime import datetime, timedelta

from .models import (
    User, Organization, Role, Location, TokenResponse,
    AuthResponse, UserCreate, UserUpdate, ApiResponse,
    PaginatedResponse, HealthCheck
)
from .exceptions import (
    AuthXException, AuthenticationError, AuthorizationError,
    ValidationError, RateLimitError, ServiceUnavailableError,
    TokenExpiredError, NetworkError
)

logger = logging.getLogger(__name__)

class AuthXClient:
    """
    AuthX SDK Client for microservice integration.

    Provides methods for authentication, user management, and authorization
    with automatic token management and error handling.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        retry_attempts: int = 3,
        auto_refresh_tokens: bool = True
    ):
        """
        Initialize AuthX client.

        Args:
            base_url: AuthX service base URL
            api_key: API key for service-to-service authentication
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts for failed requests
            auto_refresh_tokens: Automatically refresh expired tokens
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.auto_refresh_tokens = auto_refresh_tokens

        # Token management
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

        # HTTP client configuration
        self._client_kwargs = {
            'timeout': timeout,
            'follow_redirects': True,
            'headers': {
                'User-Agent': 'AuthX-SDK/1.0.0',
                'Content-Type': 'application/json'
            }
        }

        if api_key:
            self._client_kwargs['headers']['X-API-Key'] = api_key

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if hasattr(self, '_client') and self._client:
            await self._client.aclose()

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if not hasattr(self, '_client') or self._client is None:
            self._client = httpx.AsyncClient(**self._client_kwargs)
        return self._client

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        require_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Make HTTP request with error handling and retries.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request body data
            params: Query parameters
            headers: Additional headers
            require_auth: Whether authentication is required

        Returns:
            Response data as dictionary

        Raises:
            AuthXException: For various API errors
        """
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        client = self._get_client()

        # Prepare headers
        request_headers = dict(client.headers)
        if headers:
            request_headers.update(headers)

        # Add authentication if required and available
        if require_auth and self._access_token:
            if self._is_token_expired() and self.auto_refresh_tokens:
                await self.refresh_token()
            request_headers['Authorization'] = f'Bearer {self._access_token}'

        # Retry logic
        last_exception = None
        for attempt in range(self.retry_attempts):
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    headers=request_headers
                )

                # Handle different response status codes
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 201:
                    return response.json()
                elif response.status_code == 204:
                    return {"success": True}
                elif response.status_code == 400:
                    error_data = response.json() if response.content else {}
                    raise ValidationError(
                        error_data.get('detail', 'Validation error'),
                        error_code='validation_error',
                        details=error_data
                    )
                elif response.status_code == 401:
                    error_data = response.json() if response.content else {}
                    if self._access_token and self.auto_refresh_tokens:
                        try:
                            await self.refresh_token()
                            request_headers['Authorization'] = f'Bearer {self._access_token}'
                            continue  # Retry with new token
                        except Exception:
                            pass
                    raise AuthenticationError(
                        error_data.get('detail', 'Authentication failed'),
                        error_code='auth_error'
                    )
                elif response.status_code == 403:
                    error_data = response.json() if response.content else {}
                    raise AuthorizationError(
                        error_data.get('detail', 'Access denied'),
                        error_code='access_denied'
                    )
                elif response.status_code == 429:
                    error_data = response.json() if response.content else {}
                    raise RateLimitError(
                        error_data.get('detail', 'Rate limit exceeded'),
                        error_code='rate_limit'
                    )
                elif response.status_code >= 500:
                    error_data = response.json() if response.content else {}
                    raise ServiceUnavailableError(
                        error_data.get('detail', 'Service unavailable'),
                        error_code='service_error'
                    )
                else:
                    error_data = response.json() if response.content else {}
                    raise AuthXException(
                        f"Unexpected response: {response.status_code}",
                        error_code='unexpected_error',
                        details=error_data
                    )

            except httpx.RequestError as e:
                last_exception = NetworkError(f"Network error: {str(e)}")
                if attempt == self.retry_attempts - 1:
                    raise last_exception
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            except (AuthenticationError, AuthorizationError, ValidationError,
                    RateLimitError, ServiceUnavailableError):
                # Don't retry these errors
                raise
            except Exception as e:
                last_exception = AuthXException(f"Request failed: {str(e)}")
                if attempt == self.retry_attempts - 1:
                    raise last_exception
                await asyncio.sleep(2 ** attempt)

    def _is_token_expired(self) -> bool:
        """Check if current token is expired."""
        if not self._token_expires_at:
            return True
        return datetime.now() >= self._token_expires_at

    # Authentication Methods
    async def authenticate(self, username: str, password: str) -> AuthResponse:
        """
        Authenticate user with username/password.

        Args:
            username: User's username or email
            password: User's password

        Returns:
            Authentication response with user data and token
        """
        response_data = await self._make_request(
            'POST',
            '/api/v1/auth/login',
            data={'username': username, 'password': password},
            require_auth=False
        )

        # Store tokens
        token_data = response_data.get('token', {})
        self._access_token = token_data.get('access_token')
        self._refresh_token = token_data.get('refresh_token')

        if token_data.get('expires_in'):
            self._token_expires_at = datetime.now() + timedelta(
                seconds=token_data['expires_in']
            )

        return AuthResponse(**response_data)

    async def authenticate_with_token(self, token: str) -> AuthResponse:
        """
        Authenticate using an existing token.

        Args:
            token: Access token

        Returns:
            Authentication response
        """
        self._access_token = token

        # Verify token and get user info
        response_data = await self._make_request('GET', '/api/v1/auth/me')
        return AuthResponse(**response_data)

    async def refresh_token(self) -> TokenResponse:
        """
        Refresh access token using refresh token.

        Returns:
            New token response
        """
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available")

        response_data = await self._make_request(
            'POST',
            '/api/v1/auth/refresh',
            data={'refresh_token': self._refresh_token},
            require_auth=False
        )

        # Update tokens
        token_data = response_data.get('token', response_data)
        self._access_token = token_data.get('access_token')
        self._refresh_token = token_data.get('refresh_token', self._refresh_token)

        if token_data.get('expires_in'):
            self._token_expires_at = datetime.now() + timedelta(
                seconds=token_data['expires_in']
            )

        return TokenResponse(**token_data)

    async def logout(self) -> bool:
        """
        Logout current user and invalidate tokens.

        Returns:
            True if successful
        """
        try:
            await self._make_request('POST', '/api/v1/auth/logout')
        finally:
            # Clear tokens regardless of response
            self._access_token = None
            self._refresh_token = None
            self._token_expires_at = None

        return True

    # User Management Methods
    async def get_current_user(self) -> User:
        """Get current authenticated user."""
        response_data = await self._make_request('GET', '/api/v1/auth/me')
        return User(**response_data['user'])

    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        response_data = await self._make_request(
            'POST',
            '/api/v1/users',
            data=user_data.model_dump()
        )
        return User(**response_data['user'])

    async def get_user(self, user_id: str) -> User:
        """Get user by ID."""
        response_data = await self._make_request('GET', f'/api/v1/users/{user_id}')
        return User(**response_data['user'])

    async def update_user(self, user_id: str, user_data: UserUpdate) -> User:
        """Update user information."""
        response_data = await self._make_request(
            'PUT',
            f'/api/v1/users/{user_id}',
            data=user_data.model_dump(exclude_unset=True)
        )
        return User(**response_data['user'])

    async def delete_user(self, user_id: str) -> bool:
        """Delete user."""
        await self._make_request('DELETE', f'/api/v1/users/{user_id}')
        return True

    async def list_users(
        self,
        page: int = 1,
        size: int = 50,
        organization_id: Optional[str] = None
    ) -> PaginatedResponse:
        """List users with pagination."""
        params = {'page': page, 'size': size}
        if organization_id:
            params['organization_id'] = organization_id

        response_data = await self._make_request('GET', '/api/v1/users', params=params)

        # Convert user items
        items = [User(**item) for item in response_data['items']]
        response_data['items'] = items

        return PaginatedResponse(**response_data)

    # Authorization Methods
    async def check_permission(self, permission: str, resource_id: Optional[str] = None) -> bool:
        """
        Check if current user has specific permission.

        Args:
            permission: Permission name
            resource_id: Optional resource ID for resource-specific permissions

        Returns:
            True if user has permission
        """
        params = {'permission': permission}
        if resource_id:
            params['resource_id'] = resource_id

        try:
            response_data = await self._make_request(
                'GET',
                '/api/v1/auth/check-permission',
                params=params
            )
            return response_data.get('has_permission', False)
        except AuthorizationError:
            return False

    async def get_user_permissions(self, user_id: Optional[str] = None) -> List[str]:
        """Get permissions for user (current user if no ID provided)."""
        endpoint = '/api/v1/auth/permissions'
        if user_id:
            endpoint = f'/api/v1/users/{user_id}/permissions'

        response_data = await self._make_request('GET', endpoint)
        return response_data.get('permissions', [])

    # Health Check Methods
    async def health_check(self) -> HealthCheck:
        """Get service health status."""
        response_data = await self._make_request(
            'GET',
            '/health',
            require_auth=False
        )
        return HealthCheck(**response_data)

    async def detailed_health_check(self) -> HealthCheck:
        """Get detailed service health status."""
        response_data = await self._make_request(
            'GET',
            '/health/detailed',
            require_auth=False
        )
        return HealthCheck(**response_data)

    # Utility Methods
    def is_authenticated(self) -> bool:
        """Check if client has valid authentication."""
        return bool(self._access_token and not self._is_token_expired())

    def set_token(self, access_token: str, refresh_token: Optional[str] = None, expires_in: Optional[int] = None):
        """Manually set authentication tokens."""
        self._access_token = access_token
        self._refresh_token = refresh_token

        if expires_in:
            self._token_expires_at = datetime.now() + timedelta(seconds=expires_in)

    def clear_tokens(self):
        """Clear all stored tokens."""
        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = None
