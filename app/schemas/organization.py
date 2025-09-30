"""
Organization-related schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from app.schemas.base import UUIDSchema, TimestampSchema


class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r'^[a-z0-9-]+$')
    description: Optional[str] = None
    max_users: int = Field(default=100, ge=1, le=10000)


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    max_users: Optional[int] = Field(None, ge=1, le=10000)
    is_active: Optional[bool] = None


# Forward reference for circular import issue
class LocationSummary(BaseModel):
    id: str
    name: str
    code: str
    is_active: bool
    model_config = ConfigDict(from_attributes=True)


class OrganizationResponse(OrganizationBase, UUIDSchema, TimestampSchema):
    is_active: bool
    locations: List[LocationSummary] = []

    model_config = ConfigDict(from_attributes=True)
