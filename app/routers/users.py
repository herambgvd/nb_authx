"""
User management API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from app.database import get_async_session
from app.schemas import (
    UserCreate, UserUpdate, UserResponse, UserWithRoles, UserRoleAssign,
    PaginatedResponse, MessageResponse
)
from app.services.user_service import UserService
from app.dependencies import get_current_user, get_current_super_admin, get_current_org_admin
from app.models import User
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["User Management"])


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Create a new user with access control:
    - Super Admin: Can create users in any organization
    - Organization Admin: Can create users in their organization only
    """
    user_service = UserService(db)

    # Check permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership required to create users"
            )
        # Force organization_id to current user's organization
        organization_id = current_user.organization_id
    else:
        # Super admin can specify organization or default to their own
        organization_id = user_data.organization_id or current_user.organization_id

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is required"
        )

    user = await user_service.create_user(user_data, organization_id, current_user.id)
    return user


@router.get("", response_model=PaginatedResponse[UserResponse])
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    search: Optional[str] = Query(None, description="Search by email, username, or name"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    List users with access control:
    - Super Admin: Can see all users across organizations
    - Organization User: Can only see users in their organization
    """
    user_service = UserService(db)

    users, total = await user_service.list_users_with_access_control(
        page=page,
        size=size,
        is_active=is_active,
        search=search,
        organization_id=organization_id if current_user.is_super_admin else None,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    return PaginatedResponse(
        items=users,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user's profile"""
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_my_profile(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """Update current user's profile"""
    user_service = UserService(db)

    # Users can only update their own basic info, not admin fields
    allowed_fields = {"username", "first_name", "last_name"}
    update_data = UserUpdate(**{
        k: v for k, v in user_data.model_dump(exclude_unset=True).items()
        if k in allowed_fields
    })

    user = await user_service.update_user(current_user.id, update_data, current_user.id)
    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get user by ID with access control:
    - Super Admin: Can access any user
    - Organization User: Can only access users in their organization
    """
    user_service = UserService(db)

    user = await user_service.get_user_with_access_control(
        user_id=user_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or access denied"
        )

    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Update user with access control:
    - Super Admin: Can update any user
    - Organization Admin: Can update users in their organization
    """
    user_service = UserService(db)

    # Check if user can manage the target user
    can_manage = await user_service.can_user_manage_user(
        target_user_id=user_id,
        manager_user_id=current_user.id,
        manager_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only update users in your organization."
        )

    user = await user_service.update_user(
        user_id=user_id,
        user_data=user_data,
        updated_by_user_id=current_user.id,
        organization_id=current_user.organization_id if not current_user.is_super_admin else None
    )

    return user


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Delete user with access control:
    - Super Admin: Can delete any user
    - Organization Admin: Can delete users in their organization
    """
    user_service = UserService(db)

    # Check if user can manage the target user
    can_manage = await user_service.can_user_manage_user(
        target_user_id=user_id,
        manager_user_id=current_user.id,
        manager_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only delete users in your organization."
        )

    success = await user_service.delete_user(
        user_id=user_id,
        deleted_by_user_id=current_user.id,
        organization_id=current_user.organization_id if not current_user.is_super_admin else None
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return MessageResponse(message="User deleted successfully")


@router.post("/{user_id}/roles", response_model=List[str])
async def assign_roles_to_user(
    user_id: str,
    role_assignment: UserRoleAssign,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Assign roles to user with access control:
    - Super Admin: Can assign any roles to any user
    - Organization Admin: Can assign roles in their organization to users in their organization
    """
    user_service = UserService(db)

    # Check if user can manage the target user
    can_manage = await user_service.can_user_manage_user(
        target_user_id=user_id,
        manager_user_id=current_user.id,
        manager_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only assign roles to users in your organization."
        )

    roles = await user_service.assign_roles_to_user(
        user_id=user_id,
        role_assignment=role_assignment,
        assigned_by_user_id=current_user.id,
        organization_id=current_user.organization_id if not current_user.is_super_admin else None
    )

    return [role.id for role in roles]


@router.get("/{user_id}/roles", response_model=List[str])
async def get_user_roles(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get user roles with access control:
    - Super Admin: Can see any user's roles
    - Organization User: Can see roles of users in their organization
    """
    user_service = UserService(db)

    # Check if user can access the target user
    user = await user_service.get_user_with_access_control(
        user_id=user_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or access denied"
        )

    roles = await user_service.get_user_roles(user_id)
    return [role.id for role in roles]
