"""
Role management API endpoints for AuthX.
Provides comprehensive role and permission management functionality with full async support.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.models.user import User
from app.services.role_service import role_service
from app.api.deps import get_current_active_user, get_current_organization_admin
from app.schemas.role import (
    RoleCreate, RoleUpdate, RoleResponse, RoleListResponse,
    PermissionCreate, PermissionUpdate, PermissionResponse,
    RoleBulkAction, UserRoleAssignment
)

logger = logging.getLogger(__name__)
router = APIRouter()

def _check_organization_access(current_user: User, target_organization_id: UUID) -> bool:
    """Check if current user can access resources in the target organization."""
    if current_user.is_superuser:
        return True
    return current_user.organization_id == target_organization_id

# =======================
# ROLE MANAGEMENT ENDPOINTS
# =======================

@router.post("/{organization_id}/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    organization_id: UUID,
    role_data: RoleCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Create a new role within the specified organization."""
    logger.info(f"Creating role: {role_data.name} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role creation in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create roles in this organization"
        )

    try:
        # Set organization_id from path parameter
        role_data.organization_id = organization_id

        role = await role_service.create_role(
            db, role_data, created_by=current_user.id
        )

        if not role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create role"
            )

        logger.info(f"Role created successfully: {role.id}")
        return RoleResponse.model_validate(role)

    except ValueError as e:
        logger.error(f"Validation error during role creation: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role"
        )

@router.get("/{organization_id}/roles", response_model=RoleListResponse)
async def list_roles(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    is_system: Optional[bool] = Query(None, description="Filter by system roles")
):
    """List roles within the specified organization."""
    logger.info(f"Listing roles for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role list access in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access roles in this organization"
        )

    try:
        # Calculate skip from page
        skip = (page - 1) * per_page

        roles, total = await role_service.list_roles(
            db,
            organization_id=organization_id,
            skip=skip,
            limit=per_page,
            search=search,
            is_system=is_system
        )

        # Calculate pagination info
        total_pages = (total + per_page - 1) // per_page

        logger.info(f"Retrieved {len(roles)} roles out of {total} total")

        return RoleListResponse(
            roles=[RoleResponse.model_validate(role) for role in roles],
            total=total,
            page=page,
            per_page=per_page,
            total_pages=total_pages
        )

    except Exception as e:
        logger.error(f"Failed to list roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve roles"
        )

@router.get("/{organization_id}/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    organization_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific role by ID."""
    logger.info(f"Getting role {role_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role access in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access roles in this organization"
        )

    try:
        role = await role_service.get_role(db, role_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Verify role belongs to the specified organization
        if role.organization_id != organization_id:
            logger.warning(f"Role {role_id} not found in organization {organization_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        return RoleResponse.model_validate(role)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role"
        )

@router.put("/{organization_id}/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    organization_id: UUID,
    role_id: UUID,
    role_update: RoleUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Update a role within the organization."""
    logger.info(f"Updating role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role update in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update roles in this organization"
        )

    try:
        # First verify the role exists and belongs to the organization
        role = await role_service.get_role(db, role_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        if role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        # Update role
        updated_role = await role_service.update_role(
            db,
            role_id,
            role_update.model_dump(exclude_unset=True)
        )

        if not updated_role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        logger.info(f"Role {role_id} updated successfully")
        return RoleResponse.model_validate(updated_role)

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error during role update: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to update role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )

@router.delete("/{organization_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    organization_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Delete a role within the organization."""
    logger.info(f"Deleting role {role_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role deletion in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete roles in this organization"
        )

    try:
        # First verify the role exists and belongs to the organization
        role = await role_service.get_role(db, role_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        if role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        # Check if role is system role (cannot be deleted)
        if role.is_system:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete system roles"
            )

        # Delete role
        success = await role_service.delete_role(db, role_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        logger.info(f"Role {role_id} deleted successfully")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )

# =======================
# PERMISSION MANAGEMENT ENDPOINTS
# =======================

@router.get("/{organization_id}/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all available permissions for the organization."""
    logger.info(f"Listing permissions for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized permission list access in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access permissions in this organization"
        )

    try:
        permissions = await role_service.get_available_permissions(db, organization_id)
        return [PermissionResponse.model_validate(perm) for perm in permissions]

    except Exception as e:
        logger.error(f"Failed to list permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve permissions"
        )

@router.post("/{organization_id}/users/{user_id}/roles", status_code=status.HTTP_200_OK)
async def assign_user_role(
    organization_id: UUID,
    user_id: UUID,
    role_assignment: UserRoleAssignment,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Assign a role to a user."""
    logger.info(f"Assigning role {role_assignment.role_id} to user {user_id} in org {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role assignment in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign roles in this organization"
        )

    try:
        success = await role_service.assign_user_role(
            db,
            user_id=user_id,
            role_id=role_assignment.role_id,
            organization_id=organization_id,
            assigned_by=current_user.id
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to assign role to user"
            )

        logger.info(f"Role assigned successfully")
        return {"message": "Role assigned successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign role"
        )

@router.delete("/{organization_id}/users/{user_id}/roles/{role_id}", status_code=status.HTTP_200_OK)
async def unassign_user_role(
    organization_id: UUID,
    user_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Remove a role from a user."""
    logger.info(f"Removing role {role_id} from user {user_id} in org {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        logger.warning(f"User {current_user.id} attempted unauthorized role removal in org {organization_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to remove roles in this organization"
        )

    try:
        success = await role_service.unassign_user_role(
            db,
            user_id=user_id,
            role_id=role_id,
            organization_id=organization_id
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to remove role from user"
            )

        logger.info(f"Role removed successfully")
        return {"message": "Role removed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove role"
        )

