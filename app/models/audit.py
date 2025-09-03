"""
Audit and logging models for the AuthX service.
This module defines entities for tracking user activities and security events with async support.
"""
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import TenantBaseModel

class AuditLog(TenantBaseModel):
    """
    AuditLog model for tracking user activities across the system with async support.
    """
    __tablename__ = "audit_logs"

    # Who performed the action
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # What was done
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Details of the action
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="success", index=True)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Context information
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type} on {self.resource_type}:{self.resource_id}>"

class SecurityEvent(TenantBaseModel):
    """
    SecurityEvent model for tracking security-related events and alerts with async support.
    """
    __tablename__ = "security_events"

    # Event classification
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Source of the event
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Event details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Response status
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="new", index=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=True
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Alert information
    alert_sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    alert_recipients: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="security_events")
    user = relationship("User", back_populates="security_events", foreign_keys=[user_id])
    resolver = relationship("User", foreign_keys=[resolved_by])

    def __repr__(self) -> str:
        return f"<SecurityEvent {self.event_type} severity={self.severity}>"

class ComplianceReport(TenantBaseModel):
    """
    ComplianceReport model for storing compliance report data with async support.
    """
    __tablename__ = "compliance_reports"

    # Report metadata
    report_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Report generation
    generated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )
    parameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Report data
    data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Report status
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="generating", index=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Report access
    shared_with: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="compliance_reports")
    generator = relationship("User", foreign_keys=[generated_by])

    def __repr__(self) -> str:
        return f"<ComplianceReport {self.name} type={self.report_type}>"

class ForensicSnapshot(TenantBaseModel):
    """
    ForensicSnapshot model for storing point-in-time snapshots for forensic analysis with async support.
    """
    __tablename__ = "forensic_snapshots"

    # Snapshot metadata
    snapshot_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # Snapshot creation
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Snapshot data
    data: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)

    # Snapshot status
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active", index=True)

    # Relationships
    organization = relationship("Organization", back_populates="forensic_snapshots")
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<ForensicSnapshot {self.snapshot_type} for {self.resource_type}:{self.resource_id}>"
