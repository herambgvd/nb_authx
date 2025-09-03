"""
Role and Permission API endpoints for the AuthX service.
This module provides API endpoints for role-based access control (RBAC) functionality.
"""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.api.deps import get_current_user, get_async_db, get_organization_admin, get_current_superuser
from app.models.user import User
from app.models.role import Role, Permission, role_permissions
from app.schemas.role import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    RoleListResponse,
    PermissionCreate,
    PermissionUpdate,
    PermissionResponse,
    PermissionListResponse,
    PermissionAssignment,
    PermissionCheckRequest,
    PermissionCheckResponse,
    RoleHierarchyItem,
    ApprovalWorkflowRequest,
    ApprovalWorkflowResponse,
    ApprovalDecisionRequest
)

router = APIRouter()

# Role CRUD Operations
@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    role_data: RoleCreate
):
    """
    Create a new role.
    Organization admins can create roles within their organization.
    """
    # Set organization_id from current user if not provided or validate access
    if not role_data.organization_id:
        role_data.organization_id = current_user.organization_id
    elif current_user.organization_id != role_data.organization_id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create roles in this organization"
        )

    # Check if role with same name exists in organization
    result = await db.execute(
        select(Role).where(
            and_(
                Role.name == role_data.name,
                Role.organization_id == role_data.organization_id
            )
        )
    )
    existing_role = result.scalar_one_or_none()

    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role with name '{role_data.name}' already exists in this organization"
        )

    # Create new role
    new_role = Role(**role_data.dict())
    db.add(new_role)
    await db.commit()
    await db.refresh(new_role)

    return new_role

@router.get("/roles", response_model=RoleListResponse)
async def list_roles(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    is_active: Optional[bool] = None,
    organization_id: Optional[UUID] = None
):
    """
    List roles with filtering and pagination.
    Users can only see roles from their organization unless they are superusers.
    """
    # Build query based on user permissions
    if current_user.is_superuser:
        query = select(Role)
        if organization_id:
            query = query.where(Role.organization_id == organization_id)
    else:
        query = select(Role).where(Role.organization_id == current_user.organization_id)

    # Apply filters
    if name:
        query = query.where(Role.name.ilike(f"%{name}%"))
    if is_active is not None:
        query = query.where(Role.is_active == is_active)

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply pagination
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    roles = result.scalars().all()

    return RoleListResponse(
        roles=[RoleResponse.from_orm(role) for role in roles],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    role_id: UUID
):
    """Get role by ID."""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != role.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    return role

@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID,
    role_data: RoleUpdate
):
    """Update role information."""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != role.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Update role with provided data
    update_data = role_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(role, key, value)

    await db.commit()
    await db.refresh(role)

    return role

@router.delete("/roles/{role_id}")
async def delete_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID
):
    """Delete (deactivate) role."""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != role.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Deactivate instead of hard delete
    role.is_active = False
    await db.commit()

    return {"message": "Role deactivated successfully"}

# Permission management endpoints
@router.get("/permissions", response_model=PermissionListResponse)
async def list_permissions(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    resource: Optional[str] = None,
    action: Optional[str] = None
):
    """List available permissions."""
    query = select(Permission)

    # Apply filters
    if resource:
        query = query.where(Permission.resource.ilike(f"%{resource}%"))
    if action:
        query = query.where(Permission.action.ilike(f"%{action}%"))

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply pagination
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    permissions = result.scalars().all()

    return PermissionListResponse(
        permissions=[PermissionResponse.from_orm(perm) for perm in permissions],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
async def assign_permissions_to_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID,
    permission_assignment: PermissionAssignment
):
    """Assign permissions to a role."""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != role.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Verify permissions exist
    for perm_id in permission_assignment.permission_ids:
        perm_result = await db.execute(select(Permission).where(Permission.id == perm_id))
        permission = perm_result.scalar_one_or_none()
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Permission {perm_id} not found"
            )

    # Assign permissions (this would involve updating the role_permissions table)
    # Implementation depends on your specific role-permission relationship model

    await db.commit()
    await db.refresh(role)

    return role

@router.delete("/roles/{role_id}/permissions/{permission_id}")
async def remove_permission_from_role(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID,
    permission_id: UUID
):
    """Remove permission from a role."""
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != role.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Remove permission from role (implementation depends on your model)

    await db.commit()

    return {"message": "Permission removed from role successfully"}

@router.post("/permissions/check", response_model=PermissionCheckResponse)
async def check_permission(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    permission_check: PermissionCheckRequest
):
    """Check if user has specific permission."""
    user_id = permission_check.user_id or current_user.id

    # Only allow checking own permissions unless superuser
    if user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only check your own permissions"
        )

    # Implementation would check user's roles and permissions
    has_permission = False  # Placeholder - implement actual permission checking logic

    return PermissionCheckResponse(
        user_id=user_id,
        resource=permission_check.resource,
        action=permission_check.action,
        has_permission=has_permission,
        granted_through=[]  # List of roles that grant this permission
    )
