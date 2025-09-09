"""
User management API endpoints for AuthX.
Provides comprehensive user CRUD operations and management functionality with full async support.
All endpoints are organization-scoped for proper multi-tenant access control.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.models.user import User
from app.schemas.user import UserResponse
from app.schemas.auth import RegisterRequest
from app.services.user_service import user_service
from app.api.deps import get_current_active_user, get_current_organization_admin

logger = logging.getLogger(__name__)
router = APIRouter()

def _check_organization_access(current_user: User, target_organization_id: UUID) -> bool:
    """Check if current user can access resources in the target organization."""
    if current_user.is_superuser:
        return True

    # Organization admins and users can only access their own organization
    return current_user.organization_id == target_organization_id

@router.post("/{organization_id}/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    organization_id: UUID,
    user_data: RegisterRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Create a new user within the specified organization."""
    logger.info(f"Creating new user: {user_data.email} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users in this organization"
        )

    try:
        # Create user with organization_id
        user = await user_service.create_user(
            db,
            user_data,
            organization_id=organization_id,
            created_by=current_user.id
        )

        logger.info(f"User created successfully: {user.id} in organization: {organization_id}")
        return UserResponse.from_orm(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

@router.get("/{organization_id}/users", response_model=List[UserResponse])
async def list_users(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None)
):
    """List users within the specified organization."""
    logger.info(f"Listing users for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access users in this organization"
        )

    try:
        users, total = await user_service.list_users(
            db,
            skip=skip,
            limit=limit,
            search=search,
            organization_id=organization_id
        )

        logger.info(f"Retrieved {len(users)} users out of {total} total")
        return [UserResponse.from_orm(user) for user in users]

    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user profile."""
    logger.info(f"Retrieving current user profile: {current_user.id}")
    return UserResponse.from_orm(current_user)

@router.patch("/me", response_model=UserResponse)
async def update_current_user(
    user_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update current user profile."""
    logger.info(f"Updating current user profile: {current_user.id}")

    try:
        # Users can only update their own profile
        updated_user = await user_service.update_user(db, current_user.id, user_update)
        logger.info(f"User profile updated successfully: {current_user.id}")
        return UserResponse.from_orm(updated_user)
    except Exception as e:
        logger.error(f"Failed to update user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update user profile"
        )

@router.get("/{organization_id}/users/{user_id}", response_model=UserResponse)
async def get_user(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific user by ID within the organization."""
    logger.info(f"Getting user {user_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access users in this organization"
        )

    try:
        user = await user_service.get_user(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Verify user belongs to the specified organization
        if user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        # Check if current user can access this specific user
        if not current_user.is_superuser and not current_user.is_organization_admin:
            if current_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to access this user"
                )

        return UserResponse.from_orm(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )

@router.put("/{organization_id}/users/{user_id}", response_model=UserResponse)
async def update_user(
    organization_id: UUID,
    user_id: UUID,
    user_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Update a user within the organization."""
    logger.info(f"Updating user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update users in this organization"
        )

    try:
        # Get user to verify they belong to the organization
        user = await user_service.get_user(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        updated_user = await user_service.update_user(db, user_id, user_update)
        logger.info(f"User updated successfully: {user_id}")
        return UserResponse.from_orm(updated_user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@router.post("/{organization_id}/users/{user_id}/activate")
async def activate_user(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Activate a user within the organization."""
    logger.info(f"Activating user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to activate users in this organization"
        )

    try:
        # Verify user belongs to organization
        user = await user_service.get_user(db, user_id)
        if not user or user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        await user_service.activate_user(db, user_id)
        logger.info(f"User activated successfully: {user_id}")
        return {"message": "User activated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User activation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user"
        )

@router.post("/{organization_id}/users/{user_id}/deactivate")
async def deactivate_user(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Deactivate a user within the organization."""
    logger.info(f"Deactivating user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to deactivate users in this organization"
        )

    try:
        # Verify user belongs to organization
        user = await user_service.get_user(db, user_id)
        if not user or user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        await user_service.deactivate_user(db, user_id)
        logger.info(f"User deactivated successfully: {user_id}")
        return {"message": "User deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User deactivation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user"
        )

@router.delete("/{organization_id}/users/{user_id}")
async def delete_user(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Soft delete a user within the organization."""
    logger.info(f"Deleting user {user_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete users in this organization"
        )

    try:
        # Verify user belongs to organization
        user = await user_service.get_user(db, user_id)
        if not user or user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        await user_service.delete_user(db, user_id)
        logger.info(f"User deleted successfully: {user_id}")
        return {"message": "User deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

@router.get("/{organization_id}/users/{user_id}/devices")
async def get_user_devices(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get devices for a specific user within the organization."""
    logger.info(f"Getting devices for user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access users in this organization"
        )

    try:
        # Verify user belongs to organization
        user = await user_service.get_user(db, user_id)
        if not user or user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        # Check if current user can access this specific user's devices
        if not current_user.is_superuser and not current_user.is_organization_admin:
            if current_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to access this user's devices"
                )

        devices = await user_service.get_user_devices(db, user_id)
        return {"devices": devices}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user devices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user devices"
        )

@router.delete("/{organization_id}/users/{user_id}/devices/{device_id}")
async def delete_user_device(
    organization_id: UUID,
    user_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a specific device for a user within the organization."""
    logger.info(f"Deleting device {device_id} for user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access users in this organization"
        )

    try:
        # Verify user belongs to organization
        user = await user_service.get_user(db, user_id)
        if not user or user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in this organization"
            )

        # Check permissions for device deletion
        if not current_user.is_superuser and not current_user.is_organization_admin:
            if current_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not authorized to delete this user's devices"
                )

        await user_service.delete_user_device(db, user_id, device_id)
        logger.info(f"Device deleted successfully: {device_id}")
        return {"message": "Device deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device"
        )
