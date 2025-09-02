"""
Audit and logging models for the AuthX service.
This module defines entities for tracking user activities and security events.
"""
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy import Column, String, Boolean, Text, JSON, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.models.base import TenantBaseModel, BaseModel

class AuditLog(TenantBaseModel):
    """
    AuditLog model for tracking user activities across the system.
    """
    __tablename__ = "audit_logs"

    # Who performed the action
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    user_email = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    # What was done
    event_type = Column(String(100), nullable=False)  # login, logout, create, update, delete, etc.
    resource_type = Column(String(100), nullable=False)  # user, role, organization, etc.
    resource_id = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False)  # create, read, update, delete, etc.

    # Details of the action
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="success")  # success, failure, etc.
    details = Column(JSONB, nullable=True)  # Additional details specific to the event

    # Context information
    source = Column(String(100), nullable=True)  # API, UI, etc.
    session_id = Column(String(255), nullable=True)
    request_id = Column(String(255), nullable=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type} on {self.resource_type}:{self.resource_id}>"

class SecurityEvent(TenantBaseModel):
    """
    SecurityEvent model for tracking security-related events and alerts.
    """
    __tablename__ = "security_events"

    # Event classification
    event_type = Column(String(100), nullable=False)  # login_failure, brute_force, suspicious_activity, etc.
    severity = Column(String(50), nullable=False)  # low, medium, high, critical

    # Source of the event
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    ip_address = Column(String(45), nullable=True)
    location = Column(String(255), nullable=True)
    device_id = Column(String(255), nullable=True)

    # Event details
    description = Column(Text, nullable=False)
    details = Column(JSONB, nullable=True)

    # Response status
    status = Column(String(50), nullable=False, default="new")  # new, investigating, resolved, false_positive
    resolution = Column(Text, nullable=True)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Alert information
    alert_sent = Column(Boolean, default=False, nullable=False)
    alert_recipients = Column(JSONB, nullable=True)  # List of emails or user IDs that received the alert

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    resolver = relationship("User", foreign_keys=[resolved_by])

    def __repr__(self) -> str:
        return f"<SecurityEvent {self.event_type} severity={self.severity}>"

class ComplianceReport(TenantBaseModel):
    """
    ComplianceReport model for storing compliance report data.
    """
    __tablename__ = "compliance_reports"

    # Report metadata
    report_type = Column(String(100), nullable=False)  # access_review, user_activity, security_events, etc.
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Report generation
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    parameters = Column(JSONB, nullable=True)  # Search parameters used to generate the report

    # Report data
    data = Column(JSONB, nullable=True)  # The actual report data
    summary = Column(JSONB, nullable=True)  # Summary statistics

    # Report status
    status = Column(String(50), nullable=False, default="generating")  # generating, completed, failed
    file_path = Column(String(255), nullable=True)  # Path to the generated report file

    # Report access
    shared_with = Column(JSONB, nullable=True)  # List of user IDs that have access to this report

    # Relationships
    generator = relationship("User", foreign_keys=[generated_by])

    def __repr__(self) -> str:
        return f"<ComplianceReport {self.name} type={self.report_type}>"

class ForensicSnapshot(TenantBaseModel):
    """
    ForensicSnapshot model for storing point-in-time snapshots for forensic analysis.
    """
    __tablename__ = "forensic_snapshots"

    # Snapshot metadata
    snapshot_type = Column(String(100), nullable=False)  # user_state, organization_state, etc.
    resource_type = Column(String(100), nullable=False)  # user, role, organization, etc.
    resource_id = Column(String(255), nullable=False)

    # Snapshot creation
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    reason = Column(Text, nullable=True)

    # Snapshot data
    data = Column(JSONB, nullable=False)  # Complete state of the resource at the time of snapshot

    # Snapshot status
    status = Column(String(50), nullable=False, default="active")  # active, archived, deleted

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<ForensicSnapshot {self.snapshot_type} for {self.resource_type}:{self.resource_id}>"
