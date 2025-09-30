"""
Authentication dependencies for FastAPI
"""
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from app.database import get_async_session
from app.models import User, Organization
from app.schemas import TokenPayload
from app.security import verify_token
import logging

logger = logging.getLogger(__name__)

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_async_session)
) -> User:
    """Get current authenticated user"""

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify token
    token_payload = verify_token(credentials.credentials)
    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user from database
    stmt = select(User).where(User.id == token_payload.sub)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (redundant check for clarity)"""
    return current_user


async def get_current_super_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user if they are a super admin"""
    if not current_user.is_super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    return current_user


async def get_current_org_user(
    current_user: User = Depends(get_current_user)
) -> tuple[User, Organization]:
    """Get current user with their organization"""
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership required"
        )

    if not current_user.organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    if not current_user.organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization is inactive"
        )

    return current_user, current_user.organization


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_async_session)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""

    if not credentials:
        return None

    try:
        token_payload = verify_token(credentials.credentials)
        if not token_payload:
            return None

        stmt = select(User).where(User.id == token_payload.sub)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            return None

        return user
    except Exception as e:
        logger.warning(f"Optional authentication failed: {e}")
        return None


def require_permissions(*required_permissions: str):
    """Decorator factory for permission-based access control"""

    async def permission_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_async_session)
    ) -> User:
        # Super admin has all permissions
        if current_user.is_super_admin:
            return current_user

        # Check if user has required permissions through their roles
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership required"
            )

        # Get user permissions through roles
        user_permissions = await get_user_permissions(db, current_user.id)

        # Check if user has all required permissions
        missing_permissions = set(required_permissions) - set(user_permissions)
        if missing_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {', '.join(missing_permissions)}"
            )

        return current_user

    return permission_checker


async def get_user_permissions(db: AsyncSession, user_id: str) -> list[str]:
    """Get all permissions for a user through their roles"""
    from app.models import Permission, RolePermission, UserRole

    # Query to get all permissions for the user through their roles
    stmt = (
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(UserRole, RolePermission.role_id == UserRole.role_id)
        .where(UserRole.user_id == user_id)
        .distinct()
    )

    result = await db.execute(stmt)
    permissions = result.scalars().all()
    return list(permissions)


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    # Check for forwarded headers first (for proxy/load balancer setups)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fallback to direct connection IP
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request"""
    return request.headers.get("User-Agent", "unknown")


async def get_current_org_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user if they are an organization admin or super admin"""
    if not current_user.is_super_admin and not current_user.is_org_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin or super admin access required"
        )
    
    # Organization admins must belong to an organization
    if current_user.is_org_admin and not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization admin must belong to an organization"
        )
    
    return current_user


async def get_super_admin_or_org_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user if they are super admin or belong to an organization"""
    if not current_user.is_super_admin and not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access or organization membership required"
        )
    return current_user
