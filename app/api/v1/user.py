"""
User management API endpoints for AuthX.
Provides comprehensive user CRUD operations and management functionality.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID

from app.db.session import get_async_db
from app.models.user import User
from app.schemas.user import (
    UserCreate, UserUpdate, UserResponse,
    UserListResponse, UserDeviceResponse, UserPasswordUpdate,
    UserMFASetup, UserMFAVerify
)
from app.services.user_service import user_service
from app.api.deps import (
    get_current_active_user, require_user_read,
    require_user_write, require_user_delete, get_pagination_params,
    get_search_params, get_current_organization, require_organization
)
from app.utils.helpers import calculate_pagination

router = APIRouter()

@router.post("/", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_write),
    organization = Depends(require_organization)
):
    """Create a new user."""
    # Set organization for new user
    if not user_data.organization_id:
        user_data.organization_id = organization.id

    user = await user_service.create_user(db, user_data, current_user.id)
    return UserResponse.from_orm(user)

@router.get("/", response_model=UserListResponse)
async def list_users(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_read),
    pagination: dict = Depends(get_pagination_params),
    search: dict = Depends(get_search_params),
    organization = Depends(get_current_organization),
    is_active: Optional[bool] = Query(None)
):
    """List users with filtering and pagination."""
    org_id = organization.id if organization else None

    users, total = await user_service.list_users(
        db=db,
        organization_id=org_id,
        skip=pagination["skip"],
        limit=pagination["page_size"],
        search=search["search"],
        is_active=is_active
    )

    pagination_info = calculate_pagination(
        total, pagination["page"], pagination["page_size"]
    )

    return UserListResponse(
        users=[UserResponse.from_orm(user) for user in users],
        **pagination_info
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user information."""
    return UserResponse.from_orm(current_user)

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_read)
):
    """Get user by ID."""
    user = await user_service.get_user_by_id(db, user_id, include_organization=True)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check access permissions
    if (not current_user.is_superuser and
        current_user.organization_id != user.organization_id and
        current_user.id != user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    return UserResponse.from_orm(user)

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_write)
):
    """Update user information."""
    user = await user_service.update_user(db, user_id, user_data, current_user.id)
    return UserResponse.from_orm(user)

@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_delete)
):
    """Delete (deactivate) user."""
    success = await user_service.delete_user(db, user_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return {"message": "User deleted successfully"}

@router.post("/{user_id}/activate", response_model=UserResponse)
async def activate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_write)
):
    """Activate user account."""
    user = await user_service.activate_user(db, user_id, current_user.id)
    return UserResponse.from_orm(user)

@router.post("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_write)
):
    """Deactivate user account."""
    user = await user_service.deactivate_user(db, user_id, current_user.id)
    return UserResponse.from_orm(user)

@router.put("/me/password")
async def change_my_password(
    password_data: UserPasswordUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Change current user's password."""
    from app.services.auth_service import auth_service

    success = await auth_service.change_password(
        db, current_user.id,
        password_data.current_password,
        password_data.new_password
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid current password"
        )

    return {"message": "Password changed successfully"}

@router.post("/me/mfa/setup")
async def setup_mfa(
    mfa_data: UserMFASetup,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Set up MFA for current user."""
    from app.services.auth_service import auth_service

    result = await auth_service.setup_mfa(db, current_user.id, mfa_data.mfa_type)
    return result

@router.post("/me/mfa/enable")
async def enable_mfa(
    mfa_data: UserMFAVerify,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Enable MFA after verifying setup code."""
    from app.services.auth_service import auth_service

    is_valid = await auth_service.verify_mfa_code(
        db, current_user.id, mfa_data.code
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )

    # Enable MFA for user
    user = await user_service.get_user_by_id(db, current_user.id)
    user.mfa_enabled = True
    await db.commit()

    return {"message": "MFA enabled successfully"}

@router.delete("/me/mfa")
async def disable_mfa(
    mfa_data: UserMFAVerify,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Disable MFA for current user."""
    from app.services.auth_service import auth_service

    is_valid = await auth_service.verify_mfa_code(
        db, current_user.id, mfa_data.code
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )

    # Disable MFA for user
    user = await user_service.get_user_by_id(db, current_user.id)
    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()

    return {"message": "MFA disabled successfully"}

@router.get("/me/devices", response_model=List[UserDeviceResponse])
async def get_my_devices(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get current user's devices."""
    devices = await user_service.get_user_devices(db, current_user.id)
    return [UserDeviceResponse.from_orm(device) for device in devices]

@router.delete("/me/devices/{device_id}")
async def revoke_my_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Revoke a device for current user."""
    success = await user_service.revoke_user_device(db, current_user.id, device_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    return {"message": "Device revoked successfully"}

@router.get("/statistics")
async def get_user_statistics(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(require_user_read),
    organization = Depends(get_current_organization)
):
    """Get user statistics for organization."""
    org_id = organization.id if organization else None
    stats = await user_service.get_user_statistics(db, org_id)
    return stats
