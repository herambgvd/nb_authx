"""
Location model and User-Location association
"""
from sqlalchemy import Column, String, Boolean, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class Location(Base, UUIDMixin, TimestampMixin):
    """Location model - organization scoped"""
    __tablename__ = "locations"

    name = Column(String(255), nullable=False)
    code = Column(String(50), nullable=False)  # Short code for the location
    description = Column(Text)
    address = Column(Text)
    city = Column(String(100))
    state = Column(String(100))
    country = Column(String(100))
    postal_code = Column(String(20))
    is_active = Column(Boolean, default=True, nullable=False)

    # Organization relationship
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="locations")

    # Relationships
    user_locations = relationship("UserLocation", back_populates="location", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_locations_organization_id', 'organization_id'),
        Index('ix_locations_is_active', 'is_active'),
        Index('ix_locations_code', 'code'),
        UniqueConstraint('code', 'organization_id', name='uq_location_code_organization'),
    )


class UserLocation(Base, UUIDMixin, TimestampMixin):
    """User-Location association - allows users to have access to multiple locations"""
    __tablename__ = "user_locations"

    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    location_id = Column(String(36), ForeignKey("locations.id"), nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)  # One primary location per user

    # Relationships
    user = relationship("User", back_populates="user_locations")
    location = relationship("Location", back_populates="user_locations")

    __table_args__ = (
        Index('ix_user_locations_user_id', 'user_id'),
        Index('ix_user_locations_location_id', 'location_id'),
        Index('ix_user_locations_is_primary', 'is_primary'),
        UniqueConstraint('user_id', 'location_id', name='uq_user_location'),
    )
