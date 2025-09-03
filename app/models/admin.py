"""
Super Admin models for the AuthX service.
This module defines entities for system configuration, license management, and other admin features.
"""
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, Text, DateTime, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, UUIDBaseModel

class SystemConfig(BaseModel):
    """
    SystemConfig model for storing global system configuration values.
    """
    __tablename__ = "system_configs"

    key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Audit fields
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    updater = relationship("User", foreign_keys=[updated_by])

    def __repr__(self) -> str:
        return f"<SystemConfig {self.key}>"

class License(BaseModel):
    """
    License model for tracking organization licenses.
    """
    __tablename__ = "licenses"

    license_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )

    # License details
    license_type: Mapped[str] = mapped_column(String(50), nullable=False)  # enterprise, premium, basic
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")  # active, expired, suspended

    # Limits
    max_users: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    max_organizations: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Dates
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Additional metadata
    features: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=lambda: {})
    license_metadata: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=lambda: {})

    # Relationships
    organization = relationship("Organization", back_populates="licenses")

    def __repr__(self) -> str:
        return f"<License {self.license_key} - {self.license_type}>"

class SystemAlert(UUIDBaseModel):
    """
    SystemAlert model for system-wide alerts and notifications.
    """
    __tablename__ = "system_alerts"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # Targeting
    target_type: Mapped[str] = mapped_column(String(50), nullable=False, default="all")
    target_ids: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Display settings
    is_dismissible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_dismiss_after: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    starts_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Audit
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<SystemAlert {self.title} ({self.alert_type})>"

class UserImpersonation(UUIDBaseModel):
    """
    UserImpersonation model for tracking admin user impersonation sessions.
    """
    __tablename__ = "user_impersonations"

    # Admin user doing the impersonation
    admin_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # Target user being impersonated
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # Session details
    session_token: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Timestamps
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Request context
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    admin_user = relationship("User", foreign_keys=[admin_user_id])
    target_user = relationship("User", foreign_keys=[target_user_id])

    def __repr__(self) -> str:
        return f"<UserImpersonation {self.admin_user_id} -> {self.target_user_id}>"

class MaintenanceWindow(UUIDBaseModel):
    """
    MaintenanceWindow model for scheduling system maintenance periods.
    """
    __tablename__ = "maintenance_windows"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Maintenance details
    maintenance_type: Mapped[str] = mapped_column(String(50), nullable=False)  # scheduled, emergency, security
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="scheduled")  # scheduled, active, completed, cancelled
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")  # low, medium, high, critical

    # Timing
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    estimated_duration_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Affected services
    affected_services: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: [])

    # Notifications
    notify_users: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notification_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Creator
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<MaintenanceWindow {self.title} - {self.status}>"

class PlatformMetric(UUIDBaseModel):
    """
    PlatformMetric model for storing system-wide metrics and analytics.
    """
    __tablename__ = "platform_metrics"

    metric_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    metric_type: Mapped[str] = mapped_column(String(20), nullable=False)  # counter, gauge, histogram

    # Metric data
    value: Mapped[float] = mapped_column(nullable=False)
    unit: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Dimensions/tags
    dimensions: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=lambda: {})

    # Metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Timestamp
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<PlatformMetric {self.metric_name}: {self.value}>"
