"""
Location-related schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from app.schemas.base import UUIDSchema, TimestampSchema


class LocationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    code: str = Field(..., min_length=1, max_length=50, pattern=r'^[A-Z0-9_-]+$')
    description: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None


class LocationCreate(LocationBase):
    pass


class LocationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
    is_active: Optional[bool] = None


class LocationResponse(LocationBase, UUIDSchema, TimestampSchema):
    is_active: bool
    organization_id: str

    model_config = ConfigDict(from_attributes=True)


class LocationAssignRequest(BaseModel):
    user_id: str = Field(..., description="User ID to assign locations to")
    location_ids: List[str] = Field(..., description="List of location IDs to assign")
    primary_location_id: Optional[str] = Field(None, description="Primary location ID (must be in location_ids)")


class LocationAssignResponse(BaseModel):
    user_id: str
    assigned_locations: List[LocationResponse]
    primary_location: Optional[LocationResponse] = None

    model_config = ConfigDict(from_attributes=True)


class UserLocationResponse(UUIDSchema, TimestampSchema):
    user_id: str
    location_id: str
    is_primary: bool
    location: Optional[LocationResponse] = None

    model_config = ConfigDict(from_attributes=True)
