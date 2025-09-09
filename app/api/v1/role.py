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
    PermissionCreate, PermissionUpdate, PermissionResponse
)

logger = logging.getLogger(__name__)
router = APIRouter()

def _check_organization_access(current_user: User, target_organization_id: UUID) -> bool:
    """Check if current user can access resources in the target organization."""
    if current_user.is_superuser:
        return True

    # Organization admins and users can only access their own organization
    return current_user.organization_id == target_organization_id

# =======================
# ROLE MANAGEMENT ENDPOINTS
# =======================

@router.post("/{organization_id}/roles", status_code=status.HTTP_201_CREATED)
async def create_role(
    organization_id: UUID,
    role_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Create a new role within the specified organization."""
    logger.info(f"Creating role: {role_data.get('name')} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create roles in this organization"
        )

    try:
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

@router.get("/{organization_id}/roles", response_model=list)
async def list_roles(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    is_system: Optional[bool] = Query(None)
):
    """List roles within the specified organization."""
    logger.info(f"Listing roles for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access roles in this organization"
        )

    try:
        roles = await role_service.list_roles(
            db, organization_id=organization_id, skip=skip, limit=limit,
            search=search, is_system=is_system
        )

        logger.info(f"Retrieved {len(roles)} roles")
        return [
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
                "organization_id": str(role.organization_id),
                "created_at": role.created_at.isoformat() if role.created_at else None
            }
            for role in roles
        ]

    except Exception as e:
        logger.error(f"Failed to list roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve roles"
        )

@router.get("/{organization_id}/roles/{role_id}")
async def get_role(
    organization_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific role by ID within the organization."""
    logger.info(f"Getting role {role_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
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
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

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
        logger.error(f"Failed to get role: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role"
        )

@router.put("/{organization_id}/roles/{role_id}")
async def update_role(
    organization_id: UUID,
    role_id: UUID,
    role_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Update a role within the organization."""
    logger.info(f"Updating role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update roles in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        updated_role = await role_service.update_role(db, role_id, role_update)
        logger.info(f"Role updated successfully: {role_id}")

        return {
            "id": str(updated_role.id),
            "name": updated_role.name,
            "slug": updated_role.slug,
            "description": updated_role.description,
            "is_default": updated_role.is_default,
            "is_system": updated_role.is_system,
            "is_active": updated_role.is_active,
            "priority": updated_role.priority,
            "permissions_config": updated_role.permissions_config,
            "organization_id": str(updated_role.organization_id),
            "updated_at": updated_role.updated_at.isoformat() if updated_role.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )

@router.delete("/{organization_id}/roles/{role_id}")
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete roles in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        await role_service.delete_role(db, role_id)
        logger.info(f"Role deleted successfully: {role_id}")
        return {"message": "Role deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )

@router.post("/{organization_id}/roles/{role_id}/assign/{user_id}")
async def assign_role_to_user(
    organization_id: UUID,
    role_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Assign a role to a user within the organization."""
    logger.info(f"Assigning role {role_id} to user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign roles in this organization"
        )

    try:
        # Verify both role and user belong to the organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        # Note: You may need to add user verification here as well
        await role_service.assign_role_to_user(db, role_id, user_id)
        logger.info(f"Role assigned successfully: {role_id} to user {user_id}")
        return {"message": "Role assigned successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role assignment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign role"
        )

@router.delete("/{organization_id}/roles/{role_id}/unassign/{user_id}")
async def unassign_role_from_user(
    organization_id: UUID,
    role_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Unassign a role from a user within the organization."""
    logger.info(f"Unassigning role {role_id} from user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to unassign roles in this organization"
        )

    try:
        # Verify role belongs to the organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        await role_service.unassign_role_from_user(db, role_id, user_id)
        logger.info(f"Role unassigned successfully: {role_id} from user {user_id}")
        return {"message": "Role unassigned successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role unassignment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unassign role"
        )

@router.get("/{organization_id}/users/{user_id}/roles")
async def get_user_roles(
    organization_id: UUID,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all roles assigned to a specific user within the organization."""
    logger.info(f"Getting roles for user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access user roles in this organization"
        )

    try:
        roles = await role_service.get_user_roles(db, user_id, organization_id)
        logger.info(f"Retrieved {len(roles)} roles for user {user_id}")

        return [
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
                "organization_id": str(role.organization_id)
            }
            for role in roles
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user roles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user roles"
        )

@router.post("/{organization_id}/check-permission")
async def check_permission(
    organization_id: UUID,
    permission_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Check if a user has a specific permission within the organization."""
    logger.info(f"Checking permission in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to check permissions in this organization"
        )

    try:
        user_id = permission_data.get("user_id", current_user.id)
        resource = permission_data.get("resource")
        action = permission_data.get("action")

        if not resource or not action:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resource and action are required"
            )

        has_permission = await role_service.check_permission(
            db, user_id, resource, action, organization_id
        )

        return {"has_permission": has_permission}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check permission"
        )

# =======================
# PERMISSION MANAGEMENT ENDPOINTS (Organization-scoped)
# =======================

@router.post("/{organization_id}/permissions", status_code=status.HTTP_201_CREATED, response_model=PermissionResponse)
async def create_permission(
    organization_id: UUID,
    permission_data: PermissionCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Create a new permission within the specified organization."""
    logger.info(f"Creating permission: {permission_data.name} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create permissions in this organization"
        )

    try:
        # Add organization context to permission data
        permission_dict = permission_data.model_dump()
        permission = await role_service.create_permission(db, permission_dict, organization_id)
        logger.info(f"Permission created successfully: {permission.id}")
        return PermissionResponse.model_validate(permission)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create permission"
        )

@router.get("/{organization_id}/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    is_system: Optional[bool] = Query(None)
):
    """List all permissions within the specified organization."""
    logger.info(f"Listing permissions for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access permissions in this organization"
        )

    try:
        permissions = await role_service.list_permissions(
            db, organization_id=organization_id, skip=skip, limit=limit,
            search=search, resource=resource, is_system=is_system
        )

        logger.info(f"Retrieved {len(permissions)} permissions")
        return [PermissionResponse.model_validate(perm) for perm in permissions]

    except Exception as e:
        logger.error(f"Failed to list permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve permissions"
        )

@router.get("/{organization_id}/permissions/{permission_id}", response_model=PermissionResponse)
async def get_permission(
    organization_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific permission by ID within the organization."""
    logger.info(f"Getting permission {permission_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access permissions in this organization"
        )

    try:
        permission = await role_service.get_permission(db, permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )

        # Verify permission belongs to organization (if organization-scoped)
        # Note: System permissions are global, so we allow access to them
        if hasattr(permission, 'organization_id') and permission.organization_id:
            if permission.organization_id != organization_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Permission not found in this organization"
                )

        return PermissionResponse.model_validate(permission)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve permission"
        )

@router.put("/{organization_id}/permissions/{permission_id}", response_model=PermissionResponse)
async def update_permission(
    organization_id: UUID,
    permission_id: UUID,
    permission_update: PermissionUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Update a permission within the organization."""
    logger.info(f"Updating permission {permission_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update permissions in this organization"
        )

    try:
        permission = await role_service.get_permission(db, permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )

        # Check if permission is system permission
        if permission.is_system:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot modify system permissions"
            )

        # Verify permission belongs to organization (if organization-scoped)
        if hasattr(permission, 'organization_id') and permission.organization_id:
            if permission.organization_id != organization_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Permission not found in this organization"
                )

        updated_permission = await role_service.update_permission(
            db, permission_id, permission_update.model_dump(exclude_unset=True)
        )
        logger.info(f"Permission updated successfully: {permission_id}")

        return PermissionResponse.model_validate(updated_permission)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update permission"
        )

@router.delete("/{organization_id}/permissions/{permission_id}")
async def delete_permission(
    organization_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Delete a permission within the organization."""
    logger.info(f"Deleting permission {permission_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete permissions in this organization"
        )

    try:
        permission = await role_service.get_permission(db, permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )

        # Check if permission is system permission
        if permission.is_system:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete system permissions"
            )

        # Verify permission belongs to organization (if organization-scoped)
        if hasattr(permission, 'organization_id') and permission.organization_id:
            if permission.organization_id != organization_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Permission not found in this organization"
                )

        await role_service.delete_permission(db, permission_id)
        logger.info(f"Permission deleted successfully: {permission_id}")
        return {"message": "Permission deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete permission"
        )

# =======================
# ROLE-PERMISSION RELATIONSHIP ENDPOINTS
# =======================

@router.post("/{organization_id}/roles/{role_id}/permissions/{permission_id}")
async def assign_permission_to_role(
    organization_id: UUID,
    role_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Assign a permission to a role within the organization."""
    logger.info(f"Assigning permission {permission_id} to role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign permissions in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        # Verify permission exists and is accessible
        permission = await role_service.get_permission(db, permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )

        # Check if permission can be assigned to this organization's roles
        if hasattr(permission, 'organization_id') and permission.organization_id:
            if permission.organization_id != organization_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot assign permission from different organization"
                )

        await role_service.assign_permission_to_role(db, role_id, permission_id)
        logger.info(f"Permission assigned successfully: {permission_id} to role {role_id}")
        return {"message": "Permission assigned to role successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission assignment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign permission to role"
        )

@router.delete("/{organization_id}/roles/{role_id}/permissions/{permission_id}")
async def unassign_permission_from_role(
    organization_id: UUID,
    role_id: UUID,
    permission_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Unassign a permission from a role within the organization."""
    logger.info(f"Unassigning permission {permission_id} from role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to unassign permissions in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        await role_service.unassign_permission_from_role(db, role_id, permission_id)
        logger.info(f"Permission unassigned successfully: {permission_id} from role {role_id}")
        return {"message": "Permission unassigned from role successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Permission unassignment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unassign permission from role"
        )

@router.get("/{organization_id}/roles/{role_id}/permissions", response_model=List[PermissionResponse])
async def get_role_permissions(
    organization_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all permissions assigned to a specific role within the organization."""
    logger.info(f"Getting permissions for role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access role permissions in this organization"
        )

    try:
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        permissions = await role_service.get_role_permissions(db, role_id)
        logger.info(f"Retrieved {len(permissions)} permissions for role {role_id}")

        return [PermissionResponse.model_validate(perm) for perm in permissions]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve role permissions"
        )

# =======================
# BULK OPERATIONS & CONVENIENCE ENDPOINTS
# =======================

@router.post("/{organization_id}/roles/{role_id}/permissions/bulk-assign")
async def bulk_assign_permissions_to_role(
    organization_id: UUID,
    role_id: UUID,
    permission_ids: List[UUID],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """Bulk assign multiple permissions to a role within the organization."""
    logger.info(f"Bulk assigning {len(permission_ids)} permissions to role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign permissions in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        successful_assignments = 0
        failed_assignments = []

        for permission_id in permission_ids:
            try:
                # Verify permission exists and is accessible
                permission = await role_service.get_permission(db, permission_id)
                if not permission:
                    failed_assignments.append({"permission_id": str(permission_id), "reason": "Permission not found"})
                    continue

                # Check organization scope
                if hasattr(permission, 'organization_id') and permission.organization_id:
                    if permission.organization_id != organization_id:
                        failed_assignments.append({"permission_id": str(permission_id), "reason": "Permission belongs to different organization"})
                        continue

                await role_service.assign_permission_to_role(db, role_id, permission_id)
                successful_assignments += 1

            except Exception as e:
                failed_assignments.append({"permission_id": str(permission_id), "reason": str(e)})

        logger.info(f"Bulk assignment completed: {successful_assignments} successful, {len(failed_assignments)} failed")

        return {
            "message": f"Bulk permission assignment completed",
            "successful_assignments": successful_assignments,
            "failed_assignments": failed_assignments,
            "total_requested": len(permission_ids)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk permission assignment failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to bulk assign permissions to role"
        )

@router.get("/{organization_id}/roles/{role_id}/available-permissions", response_model=List[PermissionResponse])
async def get_available_permissions_for_role(
    organization_id: UUID,
    role_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all permissions that can be assigned to a role (not currently assigned)."""
    logger.info(f"Getting available permissions for role {role_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access permissions in this organization"
        )

    try:
        # Verify role belongs to organization
        role = await role_service.get_role(db, role_id)
        if not role or role.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found in this organization"
            )

        available_permissions = await role_service.get_available_permissions_for_role(db, role_id, organization_id)
        logger.info(f"Retrieved {len(available_permissions)} available permissions for role {role_id}")

        return [PermissionResponse.model_validate(perm) for perm in available_permissions]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get available permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve available permissions"
        )


