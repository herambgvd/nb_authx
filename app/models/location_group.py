"""
Location group model for the AuthX service.
This module defines the LocationGroup entity for grouping locations.
"""
from typing import Optional, List
from sqlalchemy import Column, String, Text, Table, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.models.base import TenantBaseModel

# Association table for many-to-many relationship between LocationGroup and Location
location_group_association = Table(
    'location_group_locations',
    TenantBaseModel.metadata,
    Column('location_group_id', UUID(as_uuid=True), ForeignKey('location_groups.id'), primary_key=True),
    Column('location_id', UUID(as_uuid=True), ForeignKey('locations.id'), primary_key=True),
)

class LocationGroup(TenantBaseModel):
    """
    LocationGroup model for grouping locations for access control and management.
    """
    __tablename__ = "location_groups"

    # Basic information
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Relationships
    locations = relationship("Location", secondary=location_group_association, backref="groups")
    organization = relationship("Organization", back_populates="location_groups")

    def __repr__(self) -> str:
        return f"<LocationGroup {self.name}>"
