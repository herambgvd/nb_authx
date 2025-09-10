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
from app.schemas.user import (
    UserResponse, UserCreate, UserUpdate, UserListResponse,
    UserSearchRequest, UserBulkAction, UserPasswordUpdate, UserProfile
)
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
    user_data: UserCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Create a new user within the specified organization."""
    logger.info(f"Creating new user: {user_data.email} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized user creation in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users in this organization"
        )

    try:
        # Set organization_id from path parameter
        user_data.organization_id = organization_id

        # Create user with proper error handling
        user = await user_service.create_user(
            db,
            user_data,
            created_by=current_user.id
        )

        logger.info(f"User created successfully: {user.id} in organization: {organization_id}")
        return UserResponse.model_validate(user)

    except ValueError as e:
        logger.error(f"Validation error during user creation: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

@router.get("/{organization_id}/users", response_model=UserListResponse)
async def list_users(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query")
):
    """List users within the specified organization with pagination."""
    logger.info(f"Listing users for organization: {organization_id}, page: {page}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized user list access in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access users in this organization"
        )

    try:
        # Calculate skip value from page
        skip = (page - 1) * per_page

        users, total = await user_service.list_users(
            db,
            skip=skip,
            limit=per_page,
            search=search,
            organization_id=organization_id
        )

        # Calculate pagination info
        total_pages = (total + per_page - 1) // per_page

        logger.info(f"Retrieved {len(users)} users out of {total} total")

        return UserListResponse(
            users=[UserResponse.model_validate(user) for user in users],
            total=total,
            page=page,
            per_page=per_page,
            total_pages=total_pages
        )

    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.get("/me", response_model=UserProfile)
async def get_current_user(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user profile."""
    try:
        logger.info(f"Retrieving current user profile: {current_user.id}")
        return UserProfile.model_validate(current_user)
    except Exception as e:
        logger.error(f"Failed to get current user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user profile"
        )

@router.patch("/me", response_model=UserProfile)
async def update_current_user(
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update current user profile."""
    logger.info(f"Updating current user profile: {current_user.id}")

    try:
        # Users can only update their own profile
        updated_user = await user_service.update_user(
            db,
            current_user.id,
            user_update.model_dump(exclude_unset=True)
        )

        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User profile updated successfully: {current_user.id}")
        return UserProfile.model_validate(updated_user)

    except ValueError as e:
        logger.error(f"Validation error during user update: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to update user profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user profile"
        )

@router.put("/me/password", status_code=status.HTTP_200_OK)
async def update_current_user_password(
    password_data: UserPasswordUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update current user password."""
    logger.info(f"Password update request for user: {current_user.id}")

    # Validate password confirmation
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match"
        )

    try:
        success = await user_service.change_password(
            db,
            current_user.id,
            password_data.current_password,
            password_data.new_password
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )

        logger.info(f"Password updated successfully for user: {current_user.id}")
        return {"message": "Password updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
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
        logger.warning(f"User {current_user.id} attempted unauthorized user access in org {organization_id}")
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
            logger.warning(f"User {user_id} not found in organization {organization_id}")
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

        return UserResponse.model_validate(user)

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
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Update a user within the organization."""
    logger.info(f"Updating user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized user update in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update users in this organization"
        )

    try:
        # First verify the user exists and belongs to the organization
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

        # Update user
        updated_user = await user_service.update_user(
            db,
            user_id,
            user_update.model_dump(exclude_unset=True)
        )

        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User {user_id} updated successfully")
        return UserResponse.model_validate(updated_user)

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error during user update: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to update user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@router.delete("/{organization_id}/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Delete a user within the organization."""
    logger.info(f"Deleting user {user_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized user deletion in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete users in this organization"
        )

    # Prevent self-deletion
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    try:
        # First verify the user exists and belongs to the organization
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

        # Delete user
        success = await user_service.delete_user(db, user_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        logger.info(f"User {user_id} deleted successfully")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

@router.post("/{organization_id}/users/bulk-action", status_code=status.HTTP_200_OK)
async def bulk_user_action(
    organization_id: UUID,
    bulk_action: UserBulkAction,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Perform bulk actions on users."""
    logger.info(f"Bulk action {bulk_action.action} on {len(bulk_action.user_ids)} users in org {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized bulk action in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform bulk actions in this organization"
        )

    try:
        success_count = await user_service.bulk_user_action(
            db,
            bulk_action.user_ids,
            bulk_action.action,
            organization_id=organization_id,
            current_user_id=current_user.id
        )

        logger.info(f"Bulk action completed: {success_count}/{len(bulk_action.user_ids)} users processed")

        return {
            "message": f"Bulk action completed",
            "processed": success_count,
            "total": len(bulk_action.user_ids)
        }

    except Exception as e:
        logger.error(f"Bulk action failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk action failed"
        )
