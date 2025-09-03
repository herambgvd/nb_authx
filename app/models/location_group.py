"""
Location Group model for AuthX system.
Defines groups of locations for organizational purposes.
"""
from sqlalchemy import String, Boolean, Text, ForeignKey, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from typing import Optional, List

from app.models.base import TenantBaseModel

# Association table for many-to-many relationship between locations and location groups
location_group_association = Table(
    'location_group_associations',
    TenantBaseModel.metadata,
    Column('location_id', UUID(as_uuid=True), ForeignKey('locations.id'), primary_key=True),
    Column('location_group_id', UUID(as_uuid=True), ForeignKey('location_groups.id'), primary_key=True)
)

class LocationGroup(TenantBaseModel):
    """Location Group model for organizing locations."""

    __tablename__ = "location_groups"

    # Basic group fields
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Visual indicator
    color: Mapped[Optional[str]] = mapped_column(String(7), nullable=True)  # Hex color code

    # Status fields
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="location_groups")
    locations: Mapped[List["Location"]] = relationship(
        "Location",
        secondary=location_group_association,
        back_populates="groups"
    )

    def __repr__(self) -> str:
        return f"<LocationGroup(id={self.id}, name='{self.name}', organization_id={self.organization_id})>"

    @property
    def location_count(self) -> int:
        """Get the number of locations in this group."""
        return len(self.locations) if self.locations else 0
