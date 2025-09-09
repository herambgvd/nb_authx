"""
Dependency injection functions for AuthX API.
Provides authentication, authorization, and other common dependencies.
"""
import logging
from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from app.db.session import get_async_db
from app.core.config import settings
from app.models.user import User
from app.models.organization import Organization
from app.models.admin import Admin
from app.services.user_service import user_service
from app.services.admin_management_service import admin_management_service

logger = logging.getLogger(__name__)

# OAuth2 scheme for token authentication
oauth2_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db)
) -> Optional[User]:
    """
    Get current authenticated user from JWT token.
    Returns None if no valid token is provided.
    """
    if not credentials:
        return None

    try:
        token = credentials.credentials
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None

    user = await user_service.get_user_by_id(db, user_id)
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user, raise exception if not authenticated or inactive.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    return current_user

async def get_current_super_admin(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current user and verify they are a super admin.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )

    return current_user

async def get_current_organization_admin(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current user and verify they are an organization admin or super admin.
    """
    if not (current_user.is_organization_admin or current_user.is_superuser):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin access required"
        )

    return current_user

async def get_current_admin_with_org_scope(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
) -> tuple[User, Admin]:
    """
    Get current user and their admin record with organization scope verification.
    """
    admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)

    if not admin or not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return current_user, admin

async def verify_organization_access(
    organization_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """
    Verify that the current user has access to the specified organization.
    """
    if current_user.is_superuser:
        return current_user

    if not current_user.organization_id or str(current_user.organization_id) != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this organization is not authorized"
        )

    return current_user

def get_request_context(request: Request) -> Dict[str, Any]:
    """
    Extract request context information for audit logging and security.
    """
    return {
        "ip_address": getattr(request.client, 'host', '127.0.0.1'),
        "user_agent": request.headers.get("user-agent", "Unknown"),
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers)
    }

async def verify_api_key(
    request: Request,
    api_key: Optional[str] = None
) -> bool:
    """
    Verify API key for service-to-service communication.
    """
    # Get API key from header or query parameter
    if not api_key:
        api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )

    # Verify API key (implement your API key validation logic)
    valid_api_keys = getattr(settings, 'VALID_API_KEYS', [])
    if api_key not in valid_api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return True

def require_permissions(permissions: list):
    """
    Decorator factory for requiring specific permissions.
    """
    def permission_dependency(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Check if user has required permissions
        user_permissions = getattr(current_user, 'permissions', [])

        for permission in permissions:
            if permission not in user_permissions and not current_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission required: {permission}"
                )

        return current_user

    return permission_dependency

async def get_pagination_params(
    page: int = 1,
    limit: int = 20,
    max_limit: int = 100
) -> Dict[str, int]:
    """
    Get and validate pagination parameters.
    """
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page must be >= 1"
        )

    if limit < 1 or limit > max_limit:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Limit must be between 1 and {max_limit}"
        )

    return {
        "page": page,
        "limit": limit,
        "offset": (page - 1) * limit
    }
