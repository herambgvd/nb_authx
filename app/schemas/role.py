"""
Role and Permission-related schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict
from app.schemas.base import UUIDSchema, TimestampSchema


class RoleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None


class RoleCreate(RoleBase):
    pass


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class RoleResponse(RoleBase, UUIDSchema, TimestampSchema):
    is_active: bool
    organization_id: str

    model_config = ConfigDict(from_attributes=True)


class PermissionBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    resource: str = Field(..., min_length=1, max_length=100)
    action: str = Field(..., min_length=1, max_length=50)


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None


class PermissionResponse(PermissionBase, UUIDSchema, TimestampSchema):
    model_config = ConfigDict(from_attributes=True)


class PermissionsByResourceResponse(BaseModel):
    """Permissions grouped by resource for easier frontend consumption"""
    resource: str
    permissions: List[PermissionResponse]


class GroupedPermissionsResponse(BaseModel):
    """Response containing permissions grouped by resource"""
    permissions_by_resource: List[PermissionsByResourceResponse]
    total_count: int


class RoleWithPermissions(RoleResponse):
    permissions: List["PermissionResponse"] = []


class RolePermissionAssign(BaseModel):
    permission_ids: List[str]
