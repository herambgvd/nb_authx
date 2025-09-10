"""
User management API endpoints for AuthX.
Provides comprehensive user CRUD operations and management functionality with full async support.
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
from app.api.deps import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: RegisterRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: Optional[User] = Depends(get_current_active_user)
):
    """Create a new user with comprehensive validation."""
    logger.info(f"Creating new user: {user_data.email}")

    try:
        created_by = current_user.id if current_user else None
        user = await user_service.create_user(db, user_data, created_by)

        logger.info(f"User created successfully: {user.id}")
        return UserResponse.from_orm(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

@router.get("/", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    organization_id: Optional[UUID] = Query(None)
):
    """List users with filtering and pagination."""
    logger.info(f"Listing users - skip: {skip}, limit: {limit}, search: {search}")

    try:
        users, total = await user_service.list_users(
            db, skip=skip, limit=limit, search=search, organization_id=organization_id
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

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user by ID."""
    logger.info(f"Retrieving user: {user_id}")

    try:
        user = await user_service.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User retrieved successfully: {user.email}")
        return UserResponse.from_orm(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update user information."""
    logger.info(f"Updating user: {user_id}")

    try:
        # Check if user can update this profile
        if str(user_id) != str(current_user.id) and not current_user.is_superuser:
            logger.warning(f"Unauthorized update attempt by {current_user.id} for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this user"
            )

        updated_user = await user_service.update_user(
            db, user_id, user_update, current_user.id
        )

        if not updated_user:
            logger.warning(f"User not found for update: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User updated successfully: {user_id}")
        return UserResponse.from_orm(updated_user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@router.post("/{user_id}/change-password")
async def change_password(
    user_id: UUID,
    password_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Change user password."""
    logger.info(f"Password change request for user: {user_id}")

    try:
        # Check if user can change this password
        if str(user_id) != str(current_user.id) and not current_user.is_superuser:
            logger.warning(f"Unauthorized password change attempt by {current_user.id} for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to change this password"
            )

        current_password = password_data.get("current_password")
        new_password = password_data.get("new_password")

        if not current_password or not new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password and new password are required"
            )

        success = await user_service.change_password(
            db, user_id, current_password, new_password
        )

        if not success:
            logger.warning(f"Password change failed for user: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        logger.info(f"Password changed successfully for user: {user_id}")
        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to change password for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )

@router.post("/{user_id}/activate")
async def activate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Activate user account."""
    logger.info(f"Activating user: {user_id}")

    try:
        if not current_user.is_superuser:
            logger.warning(f"Unauthorized activation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to activate users"
            )

        success = await user_service.activate_user(db, user_id)
        if not success:
            logger.warning(f"User not found for activation: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User activated successfully: {user_id}")
        return {"message": "User activated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user"
        )

@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Deactivate user account."""
    logger.info(f"Deactivating user: {user_id}")

    try:
        if not current_user.is_superuser:
            logger.warning(f"Unauthorized deactivation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to deactivate users"
            )

        success = await user_service.deactivate_user(db, user_id)
        if not success:
            logger.warning(f"User not found for deactivation: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User deactivated successfully: {user_id}")
        return {"message": "User deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user"
        )

@router.delete("/{user_id}")
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete user account permanently."""
    logger.info(f"Deleting user: {user_id}")

    try:
        if not current_user.is_superuser:
            logger.warning(f"Unauthorized deletion attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete users"
            )

        user = await user_service.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for deletion: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        await db.delete(user)
        await db.commit()

        logger.info(f"User deleted successfully: {user_id}")
        return {"message": "User deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

@router.get("/{user_id}/devices")
async def get_user_devices(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user devices/sessions."""
    logger.info(f"Retrieving devices for user: {user_id}")

    try:
        # Check if user can view these devices
        if str(user_id) != str(current_user.id) and not current_user.is_superuser:
            logger.warning(f"Unauthorized device access attempt by {current_user.id} for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view these devices"
            )

        devices = await user_service.get_user_devices(db, user_id)

        logger.info(f"Retrieved {len(devices)} devices for user: {user_id}")
        return {
            "devices": [
                {
                    "id": str(device.id),
                    "device_name": device.device_name,
                    "device_fingerprint": device.device_fingerprint,
                    "ip_address": device.ip_address,
                    "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                    "is_trusted": device.is_trusted,
                    "created_at": device.created_at.isoformat() if device.created_at else None
                }
                for device in devices
            ]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve devices for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve devices"
        )

@router.delete("/{user_id}/devices/{device_id}")
async def revoke_user_device(
    user_id: UUID,
    device_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Revoke/remove a user device."""
    logger.info(f"Revoking device {device_id} for user {user_id}")

    try:
        # Check if user can revoke this device
        if str(user_id) != str(current_user.id) and not current_user.is_superuser:
            logger.warning(f"Unauthorized device revocation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to revoke this device"
            )

        success = await user_service.revoke_user_device(db, user_id, device_id)
        if not success:
            logger.warning(f"Device not found for revocation: {device_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        logger.info(f"Device revoked successfully: {device_id}")
        return {"message": "Device revoked successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke device {device_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke device"
        )
