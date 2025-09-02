"""
Audit and logging schemas for the AuthX service.
This module provides Pydantic models for audit-related API requests and responses.
"""
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Audit Log Schemas
class AuditLogBase(BaseSchema):
    """Base schema for audit log data."""
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    event_type: str
    resource_type: str
    resource_id: Optional[str] = None
    action: str
    description: Optional[str] = None
    status: str = "success"
    details: Optional[Dict[str, Any]] = None
    source: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

class AuditLogCreate(AuditLogBase, TenantBaseSchema):
    """Schema for creating a new audit log entry."""
    pass

class AuditLogResponse(UUIDSchema, AuditLogBase, TimestampSchema):
    """Schema for audit log response data."""
    organization_id: UUID

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "550e8400-e29b-41d4-a716-446655440001",
                "user_email": "user@example.com",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "event_type": "login",
                "resource_type": "user",
                "resource_id": "550e8400-e29b-41d4-a716-446655440001",
                "action": "authenticate",
                "description": "User login successful",
                "status": "success",
                "details": {"method": "password", "mfa_used": False},
                "source": "web",
                "session_id": "session-12345",
                "request_id": "req-6789",
                "organization_id": "550e8400-e29b-41d4-a716-446655440002",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class AuditLogListResponse(BaseSchema):
    """Schema for paginated audit log response data."""
    items: List[AuditLogResponse]
    total: int
    page: int
    size: int

class AuditLogFilterRequest(BaseSchema):
    """Schema for filtering audit logs."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    event_types: Optional[List[str]] = None
    resource_types: Optional[List[str]] = None
    resource_id: Optional[str] = None
    actions: Optional[List[str]] = None
    status: Optional[str] = None
    ip_address: Optional[str] = None
    source: Optional[str] = None

# Security Event Schemas
class SecurityEventBase(BaseSchema):
    """Base schema for security event data."""
    event_type: str
    severity: str
    user_id: Optional[UUID] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    device_id: Optional[str] = None
    description: str
    details: Optional[Dict[str, Any]] = None
    status: str = "new"
    resolution: Optional[str] = None

class SecurityEventCreate(SecurityEventBase, TenantBaseSchema):
    """Schema for creating a new security event."""
    pass

class SecurityEventUpdate(BaseSchema):
    """Schema for updating a security event."""
    severity: Optional[str] = None
    status: Optional[str] = None
    resolution: Optional[str] = None
    alert_sent: Optional[bool] = None
    alert_recipients: Optional[List[str]] = None

class SecurityEventResponse(UUIDSchema, SecurityEventBase, TimestampSchema):
    """Schema for security event response data."""
    organization_id: UUID
    resolved_by: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    alert_sent: bool
    alert_recipients: Optional[List[str]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "event_type": "login_failure",
                "severity": "medium",
                "user_id": "550e8400-e29b-41d4-a716-446655440001",
                "ip_address": "192.168.1.1",
                "location": "New York, USA",
                "device_id": "device-12345",
                "description": "Multiple failed login attempts",
                "details": {"attempts": 5, "time_window": "10 minutes"},
                "status": "investigating",
                "resolution": None,
                "resolved_by": None,
                "resolved_at": None,
                "alert_sent": True,
                "alert_recipients": ["admin@example.com"],
                "organization_id": "550e8400-e29b-41d4-a716-446655440002",
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class SecurityEventListResponse(BaseSchema):
    """Schema for paginated security event response data."""
    items: List[SecurityEventResponse]
    total: int
    page: int
    size: int

class SecurityEventFilterRequest(BaseSchema):
    """Schema for filtering security events."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_types: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    user_id: Optional[UUID] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None

# Compliance Report Schemas
class ComplianceReportBase(BaseSchema):
    """Base schema for compliance report data."""
    report_type: str
    name: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

class ComplianceReportCreate(ComplianceReportBase, TenantBaseSchema):
    """Schema for creating a new compliance report."""
    pass

class ComplianceReportResponse(UUIDSchema, ComplianceReportBase, TimestampSchema):
    """Schema for compliance report response data."""
    organization_id: UUID
    generated_by: UUID
    status: str
    summary: Optional[Dict[str, Any]] = None
    file_path: Optional[str] = None
    shared_with: Optional[List[UUID]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "report_type": "user_activity",
                "name": "User Activity Report - January 2023",
                "description": "Monthly user activity report",
                "parameters": {"start_date": "2023-01-01", "end_date": "2023-01-31"},
                "organization_id": "550e8400-e29b-41d4-a716-446655440001",
                "generated_by": "550e8400-e29b-41d4-a716-446655440002",
                "status": "completed",
                "summary": {"total_events": 1250, "unique_users": 45},
                "file_path": "/reports/user_activity_202301.pdf",
                "shared_with": ["550e8400-e29b-41d4-a716-446655440003"],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class ComplianceReportListResponse(BaseSchema):
    """Schema for paginated compliance report response data."""
    items: List[ComplianceReportResponse]
    total: int
    page: int
    size: int

# Forensic Snapshot Schemas
class ForensicSnapshotBase(BaseSchema):
    """Base schema for forensic snapshot data."""
    snapshot_type: str
    resource_type: str
    resource_id: str
    reason: Optional[str] = None

class ForensicSnapshotCreate(ForensicSnapshotBase, TenantBaseSchema):
    """Schema for creating a new forensic snapshot."""
    pass

class ForensicSnapshotResponse(UUIDSchema, ForensicSnapshotBase, TimestampSchema):
    """Schema for forensic snapshot response data."""
    organization_id: UUID
    created_by: UUID
    status: str
    data: Dict[str, Any]

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "snapshot_type": "user_state",
                "resource_type": "user",
                "resource_id": "550e8400-e29b-41d4-a716-446655440001",
                "reason": "Security investigation",
                "organization_id": "550e8400-e29b-41d4-a716-446655440002",
                "created_by": "550e8400-e29b-41d4-a716-446655440003",
                "status": "active",
                "data": {
                    "email": "user@example.com",
                    "roles": ["admin"],
                    "last_login": "2023-01-01T00:00:00Z"
                },
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class ForensicSnapshotListResponse(BaseSchema):
    """Schema for paginated forensic snapshot response data."""
    items: List[ForensicSnapshotResponse]
    total: int
    page: int
    size: int

# Alert Schemas
class AlertConfigBase(BaseSchema):
    """Base schema for alert configuration."""
    event_types: List[str]
    severity_threshold: str = "medium"  # low, medium, high, critical
    recipients: List[str]
    enabled: bool = True

class AlertConfigCreate(AlertConfigBase, TenantBaseSchema):
    """Schema for creating a new alert configuration."""
    pass

class AlertConfigResponse(UUIDSchema, AlertConfigBase, TimestampSchema):
    """Schema for alert configuration response data."""
    organization_id: UUID

class AlertTriggerRequest(BaseSchema):
    """Schema for manually triggering an alert."""
    title: str
    message: str
    severity: str
    recipients: List[str]
    event_data: Optional[Dict[str, Any]] = None
