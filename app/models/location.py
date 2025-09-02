"""
Location model for the AuthX service.
This module defines the Location entity for geographic organization structure.
"""
from typing import Optional, List
from sqlalchemy import Column, String, Boolean, Text, Integer, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.models.base import TenantBaseModel

class Location(TenantBaseModel):
    """
    Location model representing a physical or logical location within an organization.
    """
    __tablename__ = "locations"
    __allow_unmapped__ = True

    # Basic information
    name = Column(String(255), nullable=False)
    code = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)

    # Hierarchical structure
    parent_id = Column(UUID(as_uuid=True), ForeignKey("locations.id"), nullable=True)

    # Address and geographic information
    address_line1 = Column(String(255), nullable=True)
    address_line2 = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    postal_code = Column(String(20), nullable=True)
    country = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    # Contact information
    contact_name = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    contact_phone = Column(String(50), nullable=True)

    # Status and settings
    is_active = Column(Boolean, default=True, nullable=False)
    geo_fencing_enabled = Column(Boolean, default=False, nullable=False)
    geo_fencing_radius = Column(Integer, default=100, nullable=True)  # in meters

    # Relationships
    organization = relationship("Organization", back_populates="locations")
    parent = relationship("Location", remote_side="Location.id", backref="children")

    def __repr__(self) -> str:
        return f"<Location {self.name}>"
