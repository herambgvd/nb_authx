"""
User-related schemas
"""
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from app.schemas.base import UUIDSchema, TimestampSchema


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=1, max_length=100)
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    organization_id: Optional[str] = None


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=1, max_length=100)
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None


class UserResponse(UserBase, UUIDSchema, TimestampSchema):
    is_active: bool
    is_verified: bool
    is_super_admin: bool
    is_org_admin: bool  # Organization Admin flag
    organization_id: Optional[str] = None
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class UserWithOrganization(UserResponse):
    organization: Optional["OrganizationResponse"] = None


class UserRoleAssign(BaseModel):
    role_ids: List[str]


class UserWithRoles(UserResponse):
    roles: List["RoleResponse"] = []
