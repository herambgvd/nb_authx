"""
Role and Permission schemas for the AuthX service.
This module provides Pydantic models for role-based access control (RBAC).
"""
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Permission Schemas
class PermissionBase(BaseSchema):
    """Base schema for permission data."""
    name: str
    description: Optional[str] = None
    resource: str
    action: str
    is_system_permission: bool = False

class PermissionCreate(PermissionBase):
    """Schema for creating a new permission."""
    pass

class PermissionUpdate(BaseSchema):
    """Schema for updating an existing permission."""
    name: Optional[str] = None
    description: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    is_system_permission: Optional[bool] = None

class PermissionResponse(UUIDSchema, PermissionBase, TimestampSchema):
    """Schema for permission response data."""
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "read:users",
                "description": "Ability to view user data",
                "resource": "users",
                "action": "read",
                "is_system_permission": False,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

# Role Schemas
class RoleBase(BaseSchema):
    """Base schema for role data."""
    name: str
    description: Optional[str] = None
    is_system_role: bool = False
    is_location_specific: bool = False
    location_id: Optional[UUID] = None
    parent_id: Optional[UUID] = None

class RoleCreate(RoleBase, TenantBaseSchema):
    """Schema for creating a new role."""
    permission_ids: Optional[List[UUID]] = None

class RoleUpdate(BaseSchema):
    """Schema for updating an existing role."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_system_role: Optional[bool] = None
    is_location_specific: Optional[bool] = None
    location_id: Optional[UUID] = None
    parent_id: Optional[UUID] = None
    permission_ids: Optional[List[UUID]] = None

class RoleResponse(UUIDSchema, RoleBase, TimestampSchema):
    """Schema for role response data."""
    organization_id: UUID
    permissions: List[PermissionResponse] = []

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Admin",
                "description": "Administrator role with full access",
                "is_system_role": True,
                "is_location_specific": False,
                "location_id": None,
                "parent_id": None,
                "organization_id": "550e8400-e29b-41d4-a716-446655440001",
                "permissions": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440002",
                        "name": "read:users",
                        "description": "Ability to view user data",
                        "resource": "users",
                        "action": "read",
                        "is_system_permission": False,
                        "created_at": "2023-01-01T00:00:00Z",
                        "updated_at": "2023-01-01T00:00:00Z"
                    }
                ],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class RoleListResponse(BaseSchema):
    """Schema for paginated role response data."""
    items: List[RoleResponse]
    total: int
    page: int
    size: int

class PermissionListResponse(BaseSchema):
    """Schema for paginated permission response data."""
    items: List[PermissionResponse]
    total: int
    page: int
    size: int

# Role Template Schemas
class RoleTemplateBase(BaseSchema):
    """Base schema for role template data."""
    name: str
    description: Optional[str] = None
    is_location_specific: bool = False
    permissions: List[Dict[str, str]] = []  # List of permission identifiers (resource:action)

class RoleTemplateCreate(RoleTemplateBase):
    """Schema for creating a new role template."""
    pass

class RoleTemplateResponse(UUIDSchema, RoleTemplateBase, TimestampSchema):
    """Schema for role template response data."""
    pass

class RoleTemplateListResponse(BaseSchema):
    """Schema for paginated role template response data."""
    items: List[RoleTemplateResponse]
    total: int
    page: int
    size: int

# Permission Inheritance and Assignment Schemas
class PermissionAssignment(BaseSchema):
    """Schema for assigning permissions to a role."""
    permission_ids: List[UUID]

class RoleHierarchyItem(BaseSchema):
    """Schema for representing a role in a hierarchy."""
    id: UUID
    name: str
    children: List[Any] = []

# Permission Evaluation and Approval Schemas
class PermissionCheckRequest(BaseSchema):
    """Schema for checking if a user has a specific permission."""
    resource: str
    action: str
    resource_id: Optional[UUID] = None
    location_id: Optional[UUID] = None

class PermissionCheckResponse(BaseSchema):
    """Schema for permission check response."""
    has_permission: bool
    reason: Optional[str] = None

class ApprovalWorkflowRequest(BaseSchema):
    """Schema for requesting approval for a sensitive operation."""
    resource: str
    action: str
    resource_id: Optional[UUID] = None
    reason: str
    metadata: Optional[Dict[str, Any]] = None

class ApprovalWorkflowResponse(UUIDSchema, TimestampSchema):
    """Schema for approval workflow response."""
    status: str  # pending, approved, rejected
    requested_by: UUID
    approved_by: Optional[UUID] = None
    rejected_by: Optional[UUID] = None
    reason: str
    approval_date: Optional[str] = None
    rejection_date: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class ApprovalDecisionRequest(BaseSchema):
    """Schema for approving or rejecting a request."""
    decision: str  # approve, reject
    reason: str
