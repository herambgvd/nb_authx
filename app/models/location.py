"""
Location model for AuthX system.
Defines physical or logical locations within organizations with async support.
"""
from sqlalchemy import String, Boolean, Text, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from typing import Optional, List
import uuid

from app.models.base import TenantBaseModel

class Location(TenantBaseModel):
    """Location model for managing physical or logical locations with async support."""

    __tablename__ = "locations"

    # Basic location fields
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    location_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Location code for internal reference
    code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)

    # Address fields
    address_line1: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    address_line2: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    postal_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Geographic coordinates
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Contact information
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Status fields
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Hierarchical relationship
    parent_location_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id"),
        nullable=True,
        index=True
    )

    # Relationships
    parent_location = relationship("Location", remote_side="Location.id", back_populates="child_locations")
    child_locations = relationship("Location", back_populates="parent_location")

    # Many-to-many relationship with location groups
    groups: Mapped[List["LocationGroup"]] = relationship(
        "LocationGroup",
        secondary="location_group_associations",
        back_populates="locations"
    )

    # User access control relationships
    user_accesses = relationship("UserLocationAccess", foreign_keys="UserLocationAccess.location_id", back_populates="location", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Location(id={self.id}, name='{self.name}', type='{self.location_type}')>"

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

    @property
    def coordinates(self) -> Optional[tuple]:
        """Get latitude and longitude as a tuple."""
        if self.latitude is not None and self.longitude is not None:
            return (self.latitude, self.longitude)
        return None

    def is_within_radius(self, lat: float, lng: float, radius_km: float) -> bool:
        """Check if location is within a given radius of coordinates."""
        if not self.coordinates:
            return False

        # Simple distance calculation (not accounting for earth curvature)
        import math
        lat_diff = abs(self.latitude - lat)
        lng_diff = abs(self.longitude - lng)
        distance = math.sqrt(lat_diff**2 + lng_diff**2) * 111  # Rough km conversion

        return distance <= radius_km

    def get_authorized_users(self) -> List["User"]:
        """Get all users who have access to this location."""
        return [access.user for access in self.user_accesses if access.is_valid]

    def has_user_access(self, user_id: uuid.UUID) -> bool:
        """Check if a user has access to this location."""
        for access in self.user_accesses:
            if access.user_id == user_id and access.is_valid:
                return True
        return False
