"""
Roles and Permissions management API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from app.database import get_async_session
from app.schemas import (
    RoleCreate, RoleUpdate, RoleResponse, RoleWithPermissions,
    PermissionCreate, PermissionUpdate, PermissionResponse,
    PermissionsByResourceResponse, GroupedPermissionsResponse,
    RolePermissionAssign, PaginatedResponse, MessageResponse
)
from app.services.role_service import RoleService, PermissionService
from app.dependencies import get_current_user, get_current_super_admin
from app.models import User
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Roles & Permissions"])


# Role Management Routes
@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Create a new role with access control:
    - Super Admin: Can create roles in any organization
    - Organization Admin: Can create roles in their organization only
    """
    role_service = RoleService(db)

    # Check permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership required to create roles"
            )
        organization_id = current_user.organization_id
    else:
        # Super admin can specify organization or default to their own
        organization_id = role_data.organization_id or current_user.organization_id

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is required"
        )

    role = await role_service.create_role(role_data, organization_id, current_user.id)
    return role


@router.get("/roles", response_model=PaginatedResponse[RoleResponse])
async def list_roles(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    search: Optional[str] = Query(None, description="Search by name or description"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    List roles with access control:
    - Super Admin: Can see all roles across organizations
    - Organization User: Can only see roles in their organization
    """
    role_service = RoleService(db)

    roles, total = await role_service.list_roles_with_access_control(
        page=page,
        size=size,
        is_active=is_active,
        search=search,
        organization_id=organization_id if current_user.is_super_admin else None,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    return PaginatedResponse(
        items=roles,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get role by ID with access control:
    - Super Admin: Can access any role
    - Organization User: Can only access roles in their organization
    """
    role_service = RoleService(db)

    role = await role_service.get_role_with_access_control(
        role_id=role_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found or access denied"
        )

    return role


@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    role_data: RoleUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Update role with access control:
    - Super Admin: Can update any role
    - Organization Admin: Can update roles in their organization
    """
    role_service = RoleService(db)

    # Check if user can manage the role
    can_manage = await role_service.can_user_manage_role(
        role_id=role_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only update roles in your organization."
        )

    # Get the role to determine organization_id
    role = await role_service.get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    updated_role = await role_service.update_role(
        role_id=role_id,
        role_data=role_data,
        organization_id=role.organization_id,
        updated_by_user_id=current_user.id
    )

    return updated_role


@router.delete("/roles/{role_id}", response_model=MessageResponse)
async def delete_role(
    role_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Delete role with access control:
    - Super Admin: Can delete any role
    - Organization Admin: Can delete roles in their organization
    """
    role_service = RoleService(db)

    # Check if user can manage the role
    can_manage = await role_service.can_user_manage_role(
        role_id=role_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only delete roles in your organization."
        )

    # Get the role to determine organization_id
    role = await role_service.get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    success = await role_service.delete_role(
        role_id=role_id,
        organization_id=role.organization_id,
        deleted_by_user_id=current_user.id
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    return MessageResponse(message="Role deleted successfully")


@router.post("/roles/{role_id}/permissions", response_model=List[str])
async def assign_permissions_to_role(
    role_id: str,
    permission_assignment: RolePermissionAssign,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Assign permissions to role with access control:
    - Super Admin: Can assign permissions to any role
    - Organization Admin: Can assign permissions to roles in their organization
    """
    role_service = RoleService(db)

    # Check if user can manage the role
    can_manage = await role_service.can_user_manage_role(
        role_id=role_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only assign permissions to roles in your organization."
        )

    # Get the role to determine organization_id
    role = await role_service.get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    permissions = await role_service.assign_permissions_to_role(
        role_id=role_id,
        permission_assignment=permission_assignment,
        organization_id=role.organization_id,
        assigned_by_user_id=current_user.id
    )

    return [permission.id for permission in permissions]


@router.get("/roles/{role_id}/permissions", response_model=List[PermissionResponse])
async def get_role_permissions(
    role_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get role permissions with access control:
    - Super Admin: Can see permissions of any role
    - Organization User: Can see permissions of roles in their organization
    """
    role_service = RoleService(db)

    # Check if user can access the role
    role = await role_service.get_role_with_access_control(
        role_id=role_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found or access denied"
        )

    permissions = await role_service.get_role_permissions(role_id)
    return permissions


# Permission Management Routes (Super Admin Only)
@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission_data: PermissionCreate,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_session)
):
    """Create a new permission (Super Admin only)"""
    permission_service = PermissionService(db)
    permission = await permission_service.create_permission(permission_data, current_user.id)
    return permission


@router.get("/permissions", response_model=PaginatedResponse[PermissionResponse])
async def list_permissions(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=100, description="Page size"),
    resource: Optional[str] = Query(None, description="Filter by resource"),
    action: Optional[str] = Query(None, description="Filter by action"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """List all permissions (All authenticated users can read permissions)"""
    permission_service = PermissionService(db)

    permissions, total = await permission_service.list_permissions(
        page=page,
        size=size,
        resource=resource,
        action=action
    )

    return PaginatedResponse(
        items=permissions,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/permissions/grouped", response_model=GroupedPermissionsResponse)
async def list_permissions_grouped(
    search: Optional[str] = Query(None, description="Search permissions"),
    resource: Optional[str] = Query(None, description="Filter by resource"),
    action: Optional[str] = Query(None, description="Filter by action"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """List permissions grouped by resource (All authenticated users can read permissions)"""
    permission_service = PermissionService(db)

    permissions_by_resource, total = await permission_service.list_permissions_grouped_by_resource(
        search=search,
        resource=resource,
        action=action
    )

    # Convert to the expected response format
    grouped_permissions = []
    for resource_name, permissions in permissions_by_resource.items():
        grouped_permissions.append(
            PermissionsByResourceResponse(
                resource=resource_name,
                permissions=permissions
            )
        )

    return GroupedPermissionsResponse(
        permissions_by_resource=grouped_permissions,
        total=total
    )
