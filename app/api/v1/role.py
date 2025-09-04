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
from app.api.deps import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new role with comprehensive validation."""
    logger.info(f"Creating role: {role_data.get('name')}")

    # Check if user has permission to create roles
    if not current_user.is_superuser:
        # Check if user has role management permission
        has_permission = await role_service.check_permission(
            db, current_user.id, 'roles', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized role creation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create roles"
            )

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization to create roles"
            )

        role = await role_service.create_role(
            db, role_data, organization_id, current_user.id
        )

        logger.info(f"Role created successfully: {role.id}")
        return {
            "id": str(role.id),
            "name": role.name,
            "slug": role.slug,
            "description": role.description,
            "is_default": role.is_default,
            "is_system": role.is_system,
            "is_active": role.is_active,
            "priority": role.priority,
            "permissions_config": role.permissions_config,
            "organization_id": str(role.organization_id),
            "created_at": role.created_at.isoformat() if role.created_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role"
        )

@router.get("/")
async def list_roles(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None)
):
    """List roles with filtering and pagination."""
    logger.info(f"Listing roles - skip: {skip}, limit: {limit}")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        roles, total = await role_service.list_roles(
            db, organization_id, skip=skip, limit=limit, search=search, is_active=is_active
        )

        logger.info(f"Retrieved {len(roles)} roles out of {total} total")
        return {
            "roles": [
                {
                    "id": str(role.id),
                    "name": role.name,
                    "slug": role.slug,
                    "description": role.description,
                    "is_default": role.is_default,
                    "is_system": role.is_system,
                    "is_active": role.is_active,
                    "priority": role.priority,
                    "permissions_config": role.permissions_config,
                    "created_at": role.created_at.isoformat() if role.created_at else None
                }
                for role in roles
            ],
            "total": total,
            "skip": skip,
            "limit": limit
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve roles"
        )

@router.get("/{role_id}")
async def get_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get role by ID."""
    logger.info(f"Retrieving role: {role_id}")

    try:
        role = await role_service.get_role_by_id(db, role_id)
        if not role:
            logger.warning(f"Role not found: {role_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Check if user can access this role
        if (not current_user.is_superuser and
            str(role.organization_id) != str(current_user.organization_id)):
            logger.warning(f"Unauthorized role access attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this role"
            )

        logger.info(f"Role retrieved successfully: {role.name}")
        return {
            "id": str(role.id),
            "name": role.name,
            "slug": role.slug,
            "description": role.description,
            "is_default": role.is_default,
            "is_system": role.is_system,
            "is_active": role.is_active,
            "priority": role.priority,
            "permissions_config": role.permissions_config,
            "organization_id": str(role.organization_id),
            "created_at": role.created_at.isoformat() if role.created_at else None,
            "updated_at": role.updated_at.isoformat() if role.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve role {role_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role"
        )

@router.put("/{role_id}")
async def update_role(
    role_id: UUID,
    role_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update role information."""
    logger.info(f"Updating role: {role_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'roles', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized role update attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update roles"
            )

    try:
        updated_role = await role_service.update_role(
            db, role_id, role_update, current_user.id
        )

        if not updated_role:
            logger.warning(f"Role not found for update: {role_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        logger.info(f"Role updated successfully: {role_id}")
        return {
            "id": str(updated_role.id),
            "name": updated_role.name,
            "slug": updated_role.slug,
            "description": updated_role.description,
            "is_active": updated_role.is_active,
            "priority": updated_role.priority,
            "permissions_config": updated_role.permissions_config,
            "updated_at": updated_role.updated_at.isoformat() if updated_role.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update role {role_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )

@router.delete("/{role_id}")
async def delete_role(
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete role."""
    logger.info(f"Deleting role: {role_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'roles', 'delete'
        )
        if not has_permission:
            logger.warning(f"Unauthorized role deletion attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete roles"
            )

    try:
        success = await role_service.delete_role(db, role_id)
        if not success:
            logger.warning(f"Role not found for deletion: {role_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        logger.info(f"Role deleted successfully: {role_id}")
        return {"message": "Role deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete role {role_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )

@router.post("/{role_id}/assign/{user_id}")
async def assign_role_to_user(
    role_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Assign role to user."""
    logger.info(f"Assigning role {role_id} to user {user_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'roles', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized role assignment attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to assign roles"
            )

    try:
        success = await role_service.assign_role_to_user(
            db, user_id, role_id, current_user.id
        )

        if not success:
            logger.warning(f"Failed to assign role {role_id} to user {user_id}")
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

@router.delete("/{role_id}/unassign/{user_id}")
async def remove_role_from_user(
    role_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Remove role from user."""
    logger.info(f"Removing role {role_id} from user {user_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'roles', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized role removal attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to remove roles"
            )

    try:
        success = await role_service.remove_role_from_user(db, user_id, role_id)

        if not success:
            logger.warning(f"Failed to remove role {role_id} from user {user_id}")
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

@router.get("/user/{user_id}")
async def get_user_roles(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all roles assigned to a user."""
    logger.info(f"Getting roles for user: {user_id}")

    # Check if user can access these roles
    if (not current_user.is_superuser and
        str(user_id) != str(current_user.id)):
        logger.warning(f"Unauthorized user roles access attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view these roles"
        )

    try:
        roles = await role_service.get_user_roles(db, user_id)

        logger.info(f"Retrieved {len(roles)} roles for user")
        return {
            "roles": [
                {
                    "id": str(role.id),
                    "name": role.name,
                    "slug": role.slug,
                    "description": role.description,
                    "priority": role.priority,
                    "permissions_config": role.permissions_config
                }
                for role in roles
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get user roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user roles"
        )

@router.post("/check-permission")
async def check_permission(
    permission_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Check if current user has specific permission."""
    logger.info(f"Checking permission for user: {current_user.id}")

    try:
        resource = permission_data.get('resource')
        action = permission_data.get('action')

        if not resource or not action:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resource and action are required"
            )

        has_permission = await role_service.check_permission(
            db, current_user.id, resource, action
        )

        return {
            "has_permission": has_permission,
            "resource": resource,
            "action": action
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check permission"
        )
