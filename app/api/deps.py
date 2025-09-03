"""
Dependency injection for FastAPI endpoints.
This module provides common dependencies for authentication, authorization,
database sessions, and request context.
"""
from typing import Generator, Optional, Dict, Any, Tuple
from fastapi import Depends, HTTPException, status, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy import select
from jose import JWTError, jwt
import uuid

from app.db.session import AsyncSessionLocal, SessionLocal
from app.core.config import settings
from app.models.user import User
from app.models.organization import Organization
from app.models.role import Role

# Security scheme
security = HTTPBearer()

# Database Dependencies
async def get_async_db() -> Generator[AsyncSession, None, None]:
    """Get async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

def get_db() -> Generator[Session, None, None]:
    """Get sync database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Request Context Dependencies
def get_request_context(request: Request) -> Dict[str, Any]:
    """Get request context information."""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "correlation_id": getattr(request.state, 'correlation_id', None)
    }

# Authentication Dependencies
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Get user from database
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (not disabled)."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user (email verified)."""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not verified"
        )
    return current_user

# Superuser Dependencies
async def get_current_superuser(
    current_user: User = Depends(get_current_verified_user)
) -> User:
    """Require superuser privileges."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser privileges required"
        )
    return current_user

# Authorization Dependencies
async def require_admin(
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Require admin privileges."""
    if not current_user.is_superuser:
        # Check if user has admin role
        result = await db.execute(
            select(Role).join(User.roles).where(
                User.id == current_user.id,
                Role.name == "admin"
            )
        )
        admin_role = result.scalar_one_or_none()

        if not admin_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )

    return current_user

async def require_organization_access(
    organization_id: uuid.UUID,
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> Tuple[User, Organization]:
    """Require access to specific organization."""
    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check if user has access to organization
    if current_user.organization_id != organization_id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to access this organization"
        )

    return current_user, organization

# Permission-based Dependencies
async def require_user_read(
    current_user: User = Depends(get_current_verified_user)
) -> User:
    """Require user read permissions."""
    # For now, any verified user can read users in their organization
    return current_user

async def require_user_write(
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Require user write permissions."""
    if current_user.is_superuser:
        return current_user

    # Check if user has admin or user_admin role
    result = await db.execute(
        select(Role).join(User.roles).where(
            User.id == current_user.id,
            Role.name.in_(["admin", "user_admin"])
        )
    )
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to create/modify users"
        )

    return current_user

async def require_user_delete(
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Require user delete permissions."""
    if current_user.is_superuser:
        return current_user

    # Check if user has admin role
    result = await db.execute(
        select(Role).join(User.roles).where(
            User.id == current_user.id,
            Role.name == "admin"
        )
    )
    admin_role = result.scalar_one_or_none()

    if not admin_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to delete users"
        )

    return current_user

# Organization Dependencies
async def get_current_organization(
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> Optional[Organization]:
    """Get current user's organization."""
    if not current_user.organization_id:
        return None

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    )
    return result.scalar_one_or_none()

async def require_organization(
    organization: Optional[Organization] = Depends(get_current_organization)
) -> Organization:
    """Require user to belong to an organization."""
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )
    return organization

# Organization Admin Dependencies
async def get_organization_admin(
    current_user: User = Depends(get_current_verified_user),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Require organization admin privileges."""
    if current_user.is_superuser:
        return current_user

    # Check if user has org_admin role for their organization
    result = await db.execute(
        select(Role).join(User.roles).where(
            User.id == current_user.id,
            Role.name.in_(["admin", "org_admin"])
        )
    )
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin privileges required"
        )

    return current_user

# Pagination Dependencies
def get_pagination_params(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page")
) -> Tuple[int, int]:
    """Get pagination parameters."""
    return page, page_size

def get_search_params(
    search: Optional[str] = Query(None, description="Search term"),
    sort_by: Optional[str] = Query("created_at", description="Sort field"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$", description="Sort order")
) -> Dict[str, Any]:
    """Get search and sorting parameters."""
    return {
        "search": search,
        "sort_by": sort_by,
        "sort_order": sort_order
    }

# Optional authentication (for public endpoints that can benefit from user context)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_async_db)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None

    # Get user from database
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    return result.scalar_one_or_none()

# Rate Limiting Dependencies
async def check_rate_limit(
    request: Request,
    limit: int = 60,
    window: int = 60
) -> bool:
    """Check rate limit for request."""
    from app.core.infrastructure import check_rate_limit as check_limit

    client_ip = request.client.host if request.client else "unknown"
    rate_check = await check_limit(client_ip, limit, window)

    if not rate_check["allowed"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(rate_check["remaining"]),
                "X-RateLimit-Reset": str(int(rate_check["reset_time"]))
            }
        )

    return True

# Export all dependencies
__all__ = [
    "get_async_db",
    "get_db",
    "get_request_context",
    "get_current_user",
    "get_current_active_user",
    "get_current_verified_user",
    "get_current_superuser",
    "require_admin",
    "require_organization_access",
    "require_user_read",
    "require_user_write",
    "require_user_delete",
    "get_current_organization",
    "get_organization_admin",
    "require_organization",
    "get_pagination_params",
    "get_search_params",
    "get_current_user_optional",
    "check_rate_limit"
]
