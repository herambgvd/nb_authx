"""
Audit schemas for the AuthX service.
This module provides Pydantic models for audit logging and security event tracking.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema, TenantBaseSchema

# Audit Log Schemas
class AuditLogBase(BaseSchema):
    """Base schema for audit log data."""
    event_type: str = Field(..., max_length=100)
    resource_type: str = Field(..., max_length=100)
    resource_id: Optional[str] = Field(None, max_length=255)
    action: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    status: str = Field(default="success", pattern="^(success|failure|error|warning)$")
    source: Optional[str] = Field(None, max_length=100)

class AuditLogCreate(AuditLogBase):
    """Schema for creating audit log entries."""
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    organization_id: UUID

class AuditLogResponse(UUIDSchema, AuditLogBase, TimestampSchema):
    """Schema for audit log response."""
    organization_id: UUID
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class AuditLogListResponse(BaseSchema):
    """Schema for paginated audit log list response."""
    logs: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

class AuditLogFilterRequest(BaseSchema):
    """Schema for audit log filtering requests."""
    event_type: Optional[str] = None
    resource_type: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(success|failure|error|warning)$")
    user_id: Optional[UUID] = None
    user_email: Optional[str] = None
    ip_address: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    organization_id: Optional[UUID] = None

# Security Event Schemas
class SecurityEventBase(BaseSchema):
    """Base schema for security event data."""
    event_type: str = Field(..., max_length=100)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    description: str = Field(..., max_length=1000)
    source_ip: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    is_resolved: bool = False

class SecurityEventCreate(SecurityEventBase):
    """Schema for creating security events."""
    user_id: Optional[UUID] = None
    organization_id: UUID
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SecurityEventUpdate(BaseModel):
    """Schema for updating security events."""
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    description: Optional[str] = Field(None, max_length=1000)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    is_resolved: Optional[bool] = None
    resolution_notes: Optional[str] = Field(None, max_length=1000)

class SecurityEventResponse(UUIDSchema, SecurityEventBase, TimestampSchema):
    """Schema for security event response."""
    organization_id: UUID
    user_id: Optional[UUID] = None
    details: Dict[str, Any]
    metadata: Dict[str, Any]
    resolution_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None

class SecurityEventListResponse(BaseSchema):
    """Schema for paginated security event list response."""
    events: List[SecurityEventResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

class SecurityEventFilterRequest(BaseSchema):
    """Schema for security event filtering requests."""
    event_type: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    is_resolved: Optional[bool] = None
    min_risk_score: Optional[int] = Field(None, ge=0, le=100)
    max_risk_score: Optional[int] = Field(None, ge=0, le=100)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

# Compliance Report Schemas
class ComplianceReportBase(BaseSchema):
    """Base schema for compliance reports."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    report_type: str = Field(..., pattern="^(gdpr|hipaa|sox|pci|custom)$")
    period_start: datetime
    period_end: datetime

class ComplianceReportCreate(ComplianceReportBase):
    """Schema for creating compliance reports."""
    organization_id: UUID
    include_audit_logs: bool = True
    include_security_events: bool = True
    include_user_activities: bool = True
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ComplianceReportResponse(UUIDSchema, ComplianceReportBase, TimestampSchema):
    """Schema for compliance report response."""
    organization_id: UUID
    status: str = Field(..., pattern="^(generating|completed|failed)$")
    file_path: Optional[str] = None
    file_size_mb: Optional[float] = None
    generated_by: UUID
    completed_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = Field(default_factory=dict)

class ComplianceReportListResponse(BaseSchema):
    """Schema for paginated compliance report list response."""
    reports: List[ComplianceReportResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Forensic Snapshot Schemas
class ForensicSnapshotBase(BaseSchema):
    """Base schema for forensic snapshots."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    snapshot_type: str = Field(..., pattern="^(full|incremental|targeted)$")
    trigger_event: str = Field(..., max_length=255)

class ForensicSnapshotCreate(ForensicSnapshotBase):
    """Schema for creating forensic snapshots."""
    organization_id: UUID
    target_user_id: Optional[UUID] = None
    include_audit_logs: bool = True
    include_security_events: bool = True
    include_user_data: bool = False
    date_range_start: Optional[datetime] = None
    date_range_end: Optional[datetime] = None

class ForensicSnapshotResponse(UUIDSchema, ForensicSnapshotBase, TimestampSchema):
    """Schema for forensic snapshot response."""
    organization_id: UUID
    status: str = Field(..., pattern="^(creating|completed|failed)$")
    file_path: Optional[str] = None
    file_size_mb: Optional[float] = None
    created_by: UUID
    completed_at: Optional[datetime] = None
    hash_checksum: Optional[str] = None

class ForensicSnapshotListResponse(BaseSchema):
    """Schema for paginated forensic snapshot list response."""
    snapshots: List[ForensicSnapshotResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Audit Log Query Schemas
class AuditLogQuery(BaseSchema):
    """Schema for audit log query requests."""
    query: str = Field(..., min_length=1, max_length=1000)
    filters: Optional[AuditLogFilterRequest] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    sort_by: Optional[str] = Field(default="created_at")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")

class AuditLogQueryResponse(BaseSchema):
    """Schema for audit log query response."""
    query: str
    results: List[AuditLogResponse]
    total_matches: int
    execution_time_ms: float
    applied_filters: Dict[str, Any]

# Security Event Query Schemas
class SecurityEventQuery(BaseSchema):
    """Schema for security event query requests."""
    query: str = Field(..., min_length=1, max_length=1000)
    filters: Optional[SecurityEventFilterRequest] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)
    sort_by: Optional[str] = Field(default="created_at")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")

class SecurityEventQueryResponse(BaseSchema):
    """Schema for security event query response."""
    query: str
    results: List[SecurityEventResponse]
    total_matches: int
    execution_time_ms: float
    applied_filters: Dict[str, Any]

# Audit Statistics Schemas
class AuditStats(BaseSchema):
    """Schema for audit statistics."""
    total_audit_logs: int = 0
    total_security_events: int = 0
    events_by_type: Dict[str, int] = Field(default_factory=dict)
    events_by_status: Dict[str, int] = Field(default_factory=dict)
    top_users: List[Dict[str, Any]] = Field(default_factory=list)
    top_resources: List[Dict[str, Any]] = Field(default_factory=list)
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list)

class AuditStatsResponse(BaseSchema):
    """Schema for audit statistics response."""
    stats: AuditStats
    period_start: datetime
    period_end: datetime
    collected_at: datetime

# Alert Configuration Schemas
class AlertConfigBase(BaseSchema):
    """Base schema for alert configurations."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    alert_type: str = Field(..., pattern="^(security_event|audit_log|compliance|threshold)$")
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    is_enabled: bool = True
    conditions: Dict[str, Any] = Field(default_factory=dict)
    actions: Dict[str, Any] = Field(default_factory=dict)

class AlertConfigCreate(AlertConfigBase):
    """Schema for creating alert configurations."""
    organization_id: UUID

class AlertConfigUpdate(BaseSchema):
    """Schema for updating alert configurations."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    alert_type: Optional[str] = Field(None, pattern="^(security_event|audit_log|compliance|threshold)$")
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    is_enabled: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[Dict[str, Any]] = None

class AlertConfigResponse(UUIDSchema, AlertConfigBase, TimestampSchema):
    """Schema for alert configuration response."""
    organization_id: UUID
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0

class AlertConfigListResponse(BaseSchema):
    """Schema for paginated alert configuration list response."""
    configs: List[AlertConfigResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Alert Trigger Schemas
class AlertTriggerRequest(BaseSchema):
    """Schema for triggering alerts manually."""
    alert_config_id: UUID
    trigger_data: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = Field(None, max_length=500)

class AlertTriggerResponse(BaseSchema):
    """Schema for alert trigger response."""
    alert_config_id: UUID
    triggered_at: datetime
    trigger_id: str
    success: bool
    message: str
    actions_executed: List[str] = Field(default_factory=list)

