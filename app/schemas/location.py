"""
Location schemas for the AuthX service.
This module provides Pydantic models for location-related API requests and responses.
"""
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Base Location Schema
class LocationBase(BaseSchema):
    """Base schema for location data."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    location_type: str = Field(..., pattern="^(office|warehouse|store|datacenter|remote|other)$")
    code: Optional[str] = Field(None, min_length=2, max_length=50)

    # Address fields
    address_line1: Optional[str] = Field(None, max_length=255)
    address_line2: Optional[str] = Field(None, max_length=255)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    postal_code: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)

    # Geographic coordinates
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)

    # Contact information
    phone: Optional[str] = Field(None, max_length=20)
    email: Optional[str] = Field(None, max_length=255)

    is_active: bool = True
    is_primary: bool = False

class LocationCreate(LocationBase):
    """Schema for creating a new location."""
    organization_id: UUID
    parent_location_id: Optional[UUID] = None

class LocationUpdate(BaseSchema):
    """Schema for updating an existing location."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    location_type: Optional[str] = Field(None, pattern="^(office|warehouse|store|datacenter|remote|other)$")
    code: Optional[str] = Field(None, min_length=2, max_length=50)

    address_line1: Optional[str] = Field(None, max_length=255)
    address_line2: Optional[str] = Field(None, max_length=255)
    city: Optional[str] = Field(None, max_length=100)
    state: Optional[str] = Field(None, max_length=100)
    postal_code: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)

    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)

    phone: Optional[str] = Field(None, max_length=20)
    email: Optional[str] = Field(None, max_length=255)

    is_active: Optional[bool] = None
    is_primary: Optional[bool] = None
    parent_location_id: Optional[UUID] = None

class LocationResponse(UUIDSchema, LocationBase, TimestampSchema):
    """Schema for location response data."""
    organization_id: UUID
    parent_location_id: Optional[UUID]
    user_count: int = 0
    child_locations: List['LocationResponse'] = Field(default_factory=list)

    @property
    def full_address(self) -> str:
        """Get the full formatted address."""
        parts = []
        if self.address_line1:
            parts.append(self.address_line1)
        if self.address_line2:
            parts.append(self.address_line2)
        if self.city:
            parts.append(self.city)
        if self.state:
            parts.append(self.state)
        if self.postal_code:
            parts.append(self.postal_code)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts)

# Location List Response Schema
class LocationListResponse(BaseSchema):
    """Schema for paginated location list response."""
    locations: List[LocationResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Location Hierarchy Schemas
class LocationHierarchyItem(BaseSchema):
    """Schema for location hierarchy items."""
    location_id: UUID
    location_name: str
    parent_id: Optional[UUID] = None
    children: List['LocationHierarchyItem'] = Field(default_factory=list)
    location_type: str
    is_active: bool

# GeoFence Schemas
class GeoFenceCheckRequest(BaseSchema):
    """Schema for geofence check requests."""
    location_id: UUID
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    radius_meters: Optional[int] = Field(100, ge=1, le=10000)

class GeoFenceCheckResponse(BaseSchema):
    """Schema for geofence check response."""
    location_id: UUID
    is_within_fence: bool
    distance_meters: float
    message: str

# Location Group Schemas
class LocationGroupBase(BaseSchema):
    """Base schema for location group data."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    color: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    is_active: bool = True

class LocationGroupCreate(BaseSchema):
    """Schema for creating location groups."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    organization_id: UUID
    location_ids: List[UUID] = Field(default_factory=list)

class LocationGroupUpdate(BaseSchema):
    """Schema for updating location groups."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    location_ids: Optional[List[UUID]] = None

class LocationGroupResponse(UUIDSchema, TimestampSchema):
    """Schema for location group response."""
    name: str
    description: Optional[str]
    organization_id: UUID
    locations: List[LocationResponse] = Field(default_factory=list)
    location_count: int = 0

class LocationGroupListResponse(BaseSchema):
    """Schema for paginated location group list response."""
    groups: List[LocationGroupResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Location Assignment Schemas
class LocationAssignment(BaseSchema):
    """Schema for assigning users to locations."""
    user_id: UUID
    location_id: UUID
    is_primary: bool = False
    access_level: str = Field(default="read", pattern="^(read|write|admin)$")

class LocationAssignmentResponse(UUIDSchema, TimestampSchema):
    """Schema for location assignment response."""
    user_id: UUID
    location_id: UUID
    user_name: str
    location_name: str
    is_primary: bool
    access_level: str

# Location Statistics Schemas
class LocationStats(BaseSchema):
    """Schema for location statistics."""
    total_locations: int = 0
    active_locations: int = 0
    inactive_locations: int = 0
    locations_by_type: Dict[str, int] = Field(default_factory=dict)
    users_by_location: Dict[str, int] = Field(default_factory=dict)

class LocationStatsResponse(BaseSchema):
    """Schema for location statistics response."""
    stats: LocationStats
    top_locations: List[Dict[str, Any]] = Field(default_factory=list)
    recent_changes: List[Dict[str, Any]] = Field(default_factory=list)

# Update forward references
LocationResponse.model_rebuild()
LocationHierarchyItem.model_rebuild()
