"""
Role and Permission API endpoints for the AuthX service.
This module provides API endpoints for role-based access control (RBAC) functionality.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.api.deps import get_current_user, get_db, get_organization_admin, get_current_superadmin
from app.models.user import User, UserRole
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
    db: Session = Depends(get_db),
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
    elif current_user.organization_id != role_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create roles for this organization"
        )

    # Validate parent role if provided
    if role_data.parent_id:
        parent_role = db.query(Role).filter(
            Role.id == role_data.parent_id,
            Role.organization_id == role_data.organization_id
        ).first()

        if not parent_role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent role not found or belongs to a different organization"
            )

    # Validate location if location-specific
    if role_data.is_location_specific and not role_data.location_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Location ID must be provided for location-specific roles"
        )

    # Check if role with the same name already exists in the organization
    existing_role = db.query(Role).filter(
        Role.name == role_data.name,
        Role.organization_id == role_data.organization_id
    ).first()

    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role with name '{role_data.name}' already exists in this organization"
        )

    # Create role without permissions first
    role_dict = role_data.dict(exclude={"permission_ids"})
    new_role = Role(**role_dict)
    db.add(new_role)
    db.commit()
    db.refresh(new_role)

    # Assign permissions if provided
    if role_data.permission_ids:
        permissions = db.query(Permission).filter(Permission.id.in_(role_data.permission_ids)).all()
        for permission in permissions:
            new_role.permissions.append(permission)
        db.commit()
        db.refresh(new_role)

    return new_role

@router.get("/roles", response_model=RoleListResponse)
async def get_roles(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    is_system_role: Optional[bool] = None,
    is_location_specific: Optional[bool] = None,
    location_id: Optional[UUID] = None
):
    """
    Get a paginated list of roles with optional filtering.
    Users can only view roles within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view roles for this organization"
        )

    # Build query
    query = db.query(Role).filter(Role.organization_id == organization_id)

    # Apply filters
    if name:
        query = query.filter(Role.name.ilike(f"%{name}%"))

    if is_system_role is not None:
        query = query.filter(Role.is_system_role == is_system_role)

    if is_location_specific is not None:
        query = query.filter(Role.is_location_specific == is_location_specific)

    if location_id:
        query = query.filter(Role.location_id == location_id)

    # Get total count
    total = query.count()

    # Apply pagination
    roles = query.offset(skip).limit(limit).all()

    return {
        "items": roles,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    role_id: UUID
):
    """
    Get detailed information about a specific role by ID.
    Users can only view roles within their organization unless they are superadmins.
    """
    # Get role
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if user has permission to view this role
    if current_user.organization_id != role.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this role"
        )

    return role

@router.patch("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID,
    role_data: RoleUpdate
):
    """
    Update a role's details.
    Organization admins can update roles within their organization.
    """
    # Get role
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if user has permission to update this role
    if current_user.organization_id != role.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this role"
        )

    # Prevent updating system roles unless superadmin
    if role.is_system_role and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update system roles"
        )

    # Validate parent role if provided
    if role_data.parent_id and role_data.parent_id != role.parent_id:
        # Check that the parent ID is not the role itself
        if role_data.parent_id == role_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A role cannot be its own parent"
            )

        parent_role = db.query(Role).filter(
            Role.id == role_data.parent_id,
            Role.organization_id == role.organization_id
        ).first()

        if not parent_role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent role not found or belongs to a different organization"
            )

        # Check for circular references in the hierarchy
        current_parent_id = parent_role.parent_id
        while current_parent_id:
            if current_parent_id == role_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Circular reference detected in role hierarchy"
                )

            parent = db.query(Role).filter(Role.id == current_parent_id).first()
            if not parent:
                break
            current_parent_id = parent.parent_id

    # Check if name is being updated and validate uniqueness
    if role_data.name and role_data.name != role.name:
        existing_role = db.query(Role).filter(
            Role.name == role_data.name,
            Role.organization_id == role.organization_id,
            Role.id != role_id
        ).first()

        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Role with name '{role_data.name}' already exists in this organization"
            )

    # Validate location if changing to location-specific
    if role_data.is_location_specific is True and not (role_data.location_id or role.location_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Location ID must be provided for location-specific roles"
        )

    # Update role attributes
    update_data = role_data.dict(exclude={"permission_ids"}, exclude_unset=True)
    for key, value in update_data.items():
        setattr(role, key, value)

    # Update permissions if provided
    if role_data.permission_ids is not None:
        # Clear existing permissions
        role.permissions = []

        # Add new permissions
        permissions = db.query(Permission).filter(Permission.id.in_(role_data.permission_ids)).all()
        for permission in permissions:
            role.permissions.append(permission)

    db.commit()
    db.refresh(role)

    return role

@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID
):
    """
    Delete a role.
    Organization admins can delete roles within their organization.
    """
    # Get role
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if user has permission to delete this role
    if current_user.organization_id != role.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this role"
        )

    # Prevent deleting system roles unless superadmin
    if role.is_system_role and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete system roles"
        )

    # Check if the role is in use
    role_in_use = db.query(UserRole).filter(UserRole.role_id == role_id).first() is not None

    if role_in_use:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a role that is assigned to users"
        )

    # Check if the role has children
    has_children = db.query(Role).filter(Role.parent_id == role_id).first() is not None

    if has_children:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a role that has child roles"
        )

    # Delete the role
    db.delete(role)
    db.commit()

    return None

@router.get("/roles/hierarchy", response_model=List[RoleHierarchyItem])
async def get_role_hierarchy(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None
):
    """
    Get roles organized in a hierarchical structure.
    Users can only view roles within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view roles for this organization"
        )

    # Get all roles for the organization
    roles = db.query(Role).filter(Role.organization_id == organization_id).all()

    # Create a mapping of ID to role data
    role_map = {
        role.id: RoleHierarchyItem(id=role.id, name=role.name, children=[])
        for role in roles
    }

    # Build the hierarchy
    root_roles = []
    for role_id, role_data in role_map.items():
        # Get the actual role object
        role = next((r for r in roles if r.id == role_id), None)
        if not role:
            continue

        # If the role has a parent, add it as a child to the parent
        if role.parent_id and role.parent_id in role_map:
            parent = role_map[role.parent_id]
            parent.children.append(role_data)
        else:
            # Top-level role (no parent)
            root_roles.append(role_data)

    return root_roles

# Permission Management
@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    permission_data: PermissionCreate
):
    """
    Create a new permission.
    Only superadmins can create permissions.
    """
    # Check if permission with the same name already exists
    existing_permission = db.query(Permission).filter(
        Permission.name == permission_data.name
    ).first()

    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission with name '{permission_data.name}' already exists"
        )

    # Create new permission
    new_permission = Permission(**permission_data.dict())
    db.add(new_permission)
    db.commit()
    db.refresh(new_permission)

    return new_permission

@router.get("/permissions", response_model=PermissionListResponse)
async def get_permissions(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    is_system_permission: Optional[bool] = None
):
    """
    Get a paginated list of permissions with optional filtering.
    All users can view permissions.
    """
    # Build query
    query = db.query(Permission)

    # Apply filters
    if name:
        query = query.filter(Permission.name.ilike(f"%{name}%"))

    if resource:
        query = query.filter(Permission.resource.ilike(f"%{resource}%"))

    if action:
        query = query.filter(Permission.action.ilike(f"%{action}%"))

    if is_system_permission is not None:
        query = query.filter(Permission.is_system_permission == is_system_permission)

    # Get total count
    total = query.count()

    # Apply pagination
    permissions = query.offset(skip).limit(limit).all()

    return {
        "items": permissions,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
async def get_permission(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    permission_id: UUID
):
    """
    Get detailed information about a specific permission by ID.
    All users can view permissions.
    """
    # Get permission
    permission = db.query(Permission).filter(Permission.id == permission_id).first()

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )

    return permission

@router.patch("/permissions/{permission_id}", response_model=PermissionResponse)
async def update_permission(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    permission_id: UUID,
    permission_data: PermissionUpdate
):
    """
    Update a permission's details.
    Only superadmins can update permissions.
    """
    # Get permission
    permission = db.query(Permission).filter(Permission.id == permission_id).first()

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )

    # Prevent updating system permissions
    if permission.is_system_permission and permission_data.is_system_permission is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change a system permission to a non-system permission"
        )

    # Check if name is being updated and validate uniqueness
    if permission_data.name and permission_data.name != permission.name:
        existing_permission = db.query(Permission).filter(
            Permission.name == permission_data.name,
            Permission.id != permission_id
        ).first()

        if existing_permission:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Permission with name '{permission_data.name}' already exists"
            )

    # Update permission
    update_data = permission_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(permission, key, value)

    db.commit()
    db.refresh(permission)

    return permission

@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    permission_id: UUID
):
    """
    Delete a permission.
    Only superadmins can delete permissions.
    """
    # Get permission
    permission = db.query(Permission).filter(Permission.id == permission_id).first()

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )

    # Prevent deleting system permissions
    if permission.is_system_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete system permissions"
        )

    # Check if the permission is in use
    permission_in_use = db.query(role_permissions).filter(
        role_permissions.c.permission_id == permission_id
    ).first() is not None

    if permission_in_use:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a permission that is assigned to roles"
        )

    # Delete the permission
    db.delete(permission)
    db.commit()

    return None

# Permission Inheritance and Assignment
@router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
async def assign_permissions_to_role(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    role_id: UUID,
    permission_data: PermissionAssignment
):
    """
    Assign permissions to a role.
    Organization admins can assign permissions to roles within their organization.
    """
    # Get role
    role = db.query(Role).filter(Role.id == role_id).first()

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if user has permission to update this role
    if current_user.organization_id != role.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign permissions to this role"
        )

    # Prevent updating system roles unless superadmin
    if role.is_system_role and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify system roles"
        )

    # Get permissions
    permissions = db.query(Permission).filter(
        Permission.id.in_(permission_data.permission_ids)
    ).all()

    if len(permissions) != len(permission_data.permission_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or more permissions not found"
        )

    # Replace existing permissions
    role.permissions = permissions
    db.commit()
    db.refresh(role)

    return role

# Permission Evaluation
@router.post("/check", response_model=PermissionCheckResponse)
async def check_permission(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    check_data: PermissionCheckRequest
):
    """
    Check if the current user has a specific permission.
    This endpoint allows clients to check permissions before performing actions.
    """
    # Get user's roles including inherited permissions through role hierarchy
    user_role_ids = [ur.role_id for ur in current_user.roles]

    # If superadmin, always grant permission
    if current_user.is_superadmin:
        return {"has_permission": True, "reason": "User is a superadmin"}

    # Get all roles, including parent roles (to support inheritance)
    roles = db.query(Role).filter(Role.id.in_(user_role_ids)).all()

    # Include parent roles for permission inheritance
    all_role_ids = set(user_role_ids)

    for role in roles:
        current_parent_id = role.parent_id
        while current_parent_id:
            all_role_ids.add(current_parent_id)
            parent = db.query(Role).filter(Role.id == current_parent_id).first()
            if not parent:
                break
            current_parent_id = parent.parent_id

    # Get all permissions for the user's roles
    all_permissions = db.query(Permission).join(
        role_permissions, role_permissions.c.permission_id == Permission.id
    ).filter(
        role_permissions.c.role_id.in_(all_role_ids)
    ).all()

    # Check if any permission matches the requested resource and action
    has_permission = any(
        p.resource == check_data.resource and p.action == check_data.action
        for p in all_permissions
    )

    # If location-specific permission check is requested
    if check_data.location_id and has_permission:
        # Check if the user has any location-specific roles for this location
        location_specific_role = db.query(Role).filter(
            Role.id.in_(all_role_ids),
            Role.is_location_specific == True,
            Role.location_id == check_data.location_id
        ).first()

        # If not, check if user has global (non-location-specific) roles with this permission
        if not location_specific_role:
            global_permission = False
            for role_id in all_role_ids:
                role = db.query(Role).filter(Role.id == role_id).first()
                if role and not role.is_location_specific:
                    # Check if this non-location-specific role has the requested permission
                    role_permissions_list = [p.id for p in role.permissions]
                    matching_permission = db.query(Permission).filter(
                        Permission.id.in_(role_permissions_list),
                        Permission.resource == check_data.resource,
                        Permission.action == check_data.action
                    ).first()

                    if matching_permission:
                        global_permission = True
                        break

            has_permission = global_permission

    return {
        "has_permission": has_permission,
        "reason": "Permission granted" if has_permission else "Permission denied"
    }

# Approval Workflows for Sensitive Operations
@router.post("/approval/request", response_model=ApprovalWorkflowResponse, status_code=status.HTTP_201_CREATED)
async def request_approval(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    approval_data: ApprovalWorkflowRequest
):
    """
    Request approval for a sensitive operation.
    This endpoint allows users to request approval for actions they don't have direct permission to perform.
    """
    # Create approval request
    # This would typically create a record in an approval_requests table
    # For the sake of this example, we'll return a mock response

    return {
        "id": UUID("550e8400-e29b-41d4-a716-446655440000"),  # Mock ID
        "status": "pending",
        "requested_by": current_user.id,
        "approved_by": None,
        "rejected_by": None,
        "reason": approval_data.reason,
        "approval_date": None,
        "rejection_date": None,
        "metadata": approval_data.metadata,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

@router.post("/approval/{approval_id}/decision", response_model=ApprovalWorkflowResponse)
async def make_approval_decision(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    approval_id: UUID,
    decision_data: ApprovalDecisionRequest
):
    """
    Approve or reject a request.
    Organization admins can approve or reject requests within their organization.
    """
    # In a real implementation, this would update the approval request in the database
    # For this example, we'll return a mock response

    decision = decision_data.decision.lower()
    if decision not in ["approve", "reject"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision must be either 'approve' or 'reject'"
        )

    now = datetime.utcnow().isoformat()

    return {
        "id": approval_id,
        "status": "approved" if decision == "approve" else "rejected",
        "requested_by": UUID("550e8400-e29b-41d4-a716-446655440001"),  # Mock requested_by
        "approved_by": current_user.id if decision == "approve" else None,
        "rejected_by": current_user.id if decision == "reject" else None,
        "reason": decision_data.reason,
        "approval_date": now if decision == "approve" else None,
        "rejection_date": now if decision == "reject" else None,
        "metadata": {},
        "created_at": (datetime.utcnow() - timedelta(days=1)).isoformat(),  # Mock created_at
        "updated_at": now
    }
