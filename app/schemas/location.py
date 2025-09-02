"""
Location schemas for the AuthX service.
This module provides Pydantic models for location-related API requests and responses.
"""
from typing import Optional, List, Any, Dict
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, model_validator
from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Base Location Schema
class LocationBase(BaseSchema):
    """Base schema for location data."""
    name: str
    code: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    contact_name: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    geo_fencing_enabled: bool = False
    geo_fencing_radius: Optional[int] = None

    @model_validator(mode='after')
    def validate_geo_fencing(self):
        """Validate that geo-fencing radius is provided if geo-fencing is enabled."""
        geo_enabled = self.geo_fencing_enabled
        geo_radius = self.geo_fencing_radius
        lat = self.latitude
        lng = self.longitude

        if geo_enabled:
            if geo_radius is None:
                raise ValueError("Geo-fencing radius must be provided when geo-fencing is enabled")
            if lat is None or lng is None:
                raise ValueError("Latitude and longitude must be provided when geo-fencing is enabled")

        return self

# Location Create Schema
class LocationCreate(LocationBase, TenantBaseSchema):
    """Schema for creating a new location."""
    is_active: bool = True

# Location Update Schema
class LocationUpdate(BaseSchema):
    """Schema for updating an existing location."""
    name: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    contact_name: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    is_active: Optional[bool] = None
    geo_fencing_enabled: Optional[bool] = None
    geo_fencing_radius: Optional[int] = None

    @model_validator(mode='after')
    def validate_geo_fencing(self):
        """Validate geo-fencing settings."""
        geo_enabled = getattr(self, 'geo_fencing_enabled', None)
        if geo_enabled is not None and geo_enabled:
            geo_radius = getattr(self, 'geo_fencing_radius', None)
            if geo_radius is None:
                raise ValueError("Geo-fencing radius must be provided when enabling geo-fencing")

        return self

# Location Response Schema
class LocationResponse(UUIDSchema, LocationBase, TimestampSchema):
    """Schema for location response data."""
    organization_id: UUID
    is_active: bool

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "organization_id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "Headquarters",
                "code": "HQ-001",
                "description": "Main company headquarters",
                "parent_id": None,
                "address_line1": "123 Main Street",
                "address_line2": "Suite 500",
                "city": "San Francisco",
                "state": "CA",
                "postal_code": "94105",
                "country": "United States",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "contact_name": "John Doe",
                "contact_email": "john.doe@example.com",
                "contact_phone": "+1234567890",
                "is_active": True,
                "geo_fencing_enabled": True,
                "geo_fencing_radius": 500,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

# Location List Response Schema
class LocationListResponse(BaseSchema):
    """Schema for paginated location response data."""
    items: List[LocationResponse]
    total: int
    page: int
    size: int

# Location Hierarchy Schema
class LocationHierarchyItem(LocationResponse):
    """Schema for representing a location in a hierarchy."""
    children: List[Any] = []

# Location GeoFence Check Schema
class GeoFenceCheckRequest(BaseSchema):
    """Schema for checking if coordinates are within a location's geo-fence."""
    latitude: float
    longitude: float

class GeoFenceCheckResponse(BaseSchema):
    """Schema for geo-fence check response."""
    inside_fence: bool
    distance: Optional[float] = None  # Distance in meters from the center

# Location Group Schema
class LocationGroupBase(BaseSchema):
    """Base schema for location group data."""
    name: str
    description: Optional[str] = None

class LocationGroupCreate(LocationGroupBase, TenantBaseSchema):
    """Schema for creating a new location group."""
    location_ids: List[UUID] = []

class LocationGroupUpdate(BaseSchema):
    """Schema for updating an existing location group."""
    name: Optional[str] = None
    description: Optional[str] = None
    location_ids: Optional[List[UUID]] = None

class LocationGroupResponse(UUIDSchema, LocationGroupBase, TimestampSchema):
    """Schema for location group response data."""
    organization_id: UUID
    locations: List[LocationResponse] = []

class LocationGroupListResponse(BaseSchema):
    """Schema for paginated location group response data."""
    items: List[LocationGroupResponse]
    total: int
    page: int
    size: int
