"""
Super Admin models for the AuthX service.
This module defines entities for system configuration, license management, and other admin features.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

from sqlalchemy import Column, String, Boolean, Text, DateTime, Integer, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.base import BaseModel

class SystemConfig(BaseModel):
    """
    SystemConfig model for storing global system configuration values.
    """
    __tablename__ = "system_configs"

    key = Column(String(255), nullable=False, unique=True)
    value = Column(JSONB, nullable=False)
    description = Column(Text, nullable=True)
    is_encrypted = Column(Boolean, default=False, nullable=False)

    # Audit fields
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    def __repr__(self) -> str:
        return f"<SystemConfig {self.key}>"

class License(BaseModel):
    """
    License model for tracking organization licenses.
    """
    __tablename__ = "licenses"

    key = Column(String(255), nullable=False, unique=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    type = Column(String(50), nullable=False)  # enterprise, professional, starter, trial
    max_users = Column(Integer, nullable=False)
    max_locations = Column(Integer, nullable=False)
    features = Column(JSONB, nullable=False, default=list)
    issued_date = Column(DateTime, nullable=False)
    expiration_date = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Additional license details
    contact_name = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="license")

    def __repr__(self) -> str:
        return f"<License {self.key} for org {self.organization_id}>"

class UserImpersonation(BaseModel):
    """
    UserImpersonation model for tracking support impersonation sessions.
    """
    __tablename__ = "user_impersonations"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    impersonator_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    reason = Column(Text, nullable=False)
    token = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Additional tracking
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    ended_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    impersonator = relationship("User", foreign_keys=[impersonator_id])

    def __repr__(self) -> str:
        return f"<UserImpersonation of {self.user_id} by {self.impersonator_id}>"

class MaintenanceWindow(BaseModel):
    """
    MaintenanceWindow model for scheduling system maintenance.
    """
    __tablename__ = "maintenance_windows"

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    affected_services = Column(JSONB, nullable=False, default=list)
    status = Column(String(50), nullable=False, default="scheduled")  # scheduled, in-progress, completed, cancelled

    # Notifications
    notification_sent = Column(Boolean, default=False, nullable=False)
    notified_organizations = Column(JSONB, nullable=True)

    # Created by
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<MaintenanceWindow {self.title} {self.start_time}-{self.end_time}>"

class PlatformMetric(BaseModel):
    """
    PlatformMetric model for storing aggregated platform metrics.
    """
    __tablename__ = "platform_metrics"

    metric_name = Column(String(100), nullable=False)
    metric_value = Column(JSONB, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Dimensionality
    dimension = Column(String(50), nullable=True)  # organization, user, location, etc.
    dimension_id = Column(String(255), nullable=True)  # ID of the dimension entity

    # Aggregation
    interval = Column(String(20), nullable=False, default="day")  # minute, hour, day, week, month

    def __repr__(self) -> str:
        return f"<PlatformMetric {self.metric_name} ({self.interval})>"
