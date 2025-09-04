"""
Admin schemas for AuthX super admin functionality.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

class SuperAdminDashboard(BaseModel):
    """Super admin dashboard data."""
    organization_stats: Dict[str, int]
    user_stats: Dict[str, int]
    system_health: Dict[str, Any]
    current_metrics: Optional[Dict[str, Any]] = None
    recent_audit_logs: List[Dict[str, Any]]

class OrganizationApprovalRequest(BaseModel):
    """Organization approval request."""
    organization_id: UUID
    approval_notes: Optional[str] = None

class OrganizationRejectionRequest(BaseModel):
    """Organization rejection request."""
    organization_id: UUID
    rejection_reason: str = Field(..., min_length=10, max_length=500)

class SystemStats(BaseModel):
    """System statistics."""
    total_organizations: int
    active_organizations: int
    total_users: int
    active_users: int
    system_uptime: str
    last_backup: Optional[datetime] = None

class UserManagementAction(BaseModel):
    """User management action request."""
    user_id: UUID
    action: str = Field(..., pattern="^(activate|deactivate|verify_email|reset_password|make_super_admin|remove_super_admin)$")
    details: Optional[Dict[str, Any]] = None

class AuditLogFilter(BaseModel):
    """Audit log filter parameters."""
    action_filter: Optional[str] = None
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=50, ge=1, le=100)

class UserFilter(BaseModel):
    """User filter parameters."""
    search: Optional[str] = None
    organization_id: Optional[UUID] = None
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=50, ge=1, le=100)

class SystemAlert(BaseModel):
    """System alert model."""
    type: str
    message: str
    severity: str = Field(default="warning", pattern="^(info|warning|error|critical)$")
    timestamp: datetime
    resolved: bool = False

class PerformanceMetrics(BaseModel):
    """Performance metrics model."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    response_time: float
    error_rate: float
    active_connections: int
    timestamp: datetime

class HealthCheckResult(BaseModel):
    """Health check result model."""
    service: str
    status: str = Field(pattern="^(healthy|degraded|unhealthy)$")
    response_time: float
    details: Dict[str, Any]
    timestamp: datetime

class BulkUserAction(BaseModel):
    """Bulk user action request."""
    user_ids: List[UUID] = Field(..., min_items=1, max_items=100)
    action: str = Field(..., pattern="^(activate|deactivate|verify_email|delete)$")
    reason: Optional[str] = None

# System Configuration Schemas
class SystemConfigBase(BaseModel):
    """Base system configuration schema."""
    key: str = Field(..., min_length=1, max_length=100)
    value: str = Field(..., min_length=1)
    description: Optional[str] = None
    category: str = Field(default="general")
    is_sensitive: bool = Field(default=False)

class SystemConfigCreate(SystemConfigBase):
    """System configuration creation schema."""
    pass

class SystemConfigUpdate(BaseModel):
    """System configuration update schema."""
    value: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    is_sensitive: Optional[bool] = None

class SystemConfigResponse(SystemConfigBase):
    """System configuration response schema."""
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None
    created_by: UUID
    updated_by: Optional[UUID] = None

class SystemConfigListResponse(BaseModel):
    """System configuration list response."""
    configs: List[SystemConfigResponse]
    total: int
    page: int
    limit: int

# License Management Schemas
class LicenseBase(BaseModel):
    """Base license schema."""
    license_type: str = Field(..., pattern="^(free|basic|professional|enterprise)$")
    max_users: int = Field(..., ge=1)
    max_organizations: int = Field(..., ge=1)
    features: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None

class LicenseCreate(LicenseBase):
    """License creation schema."""
    organization_id: UUID

class LicenseUpdate(BaseModel):
    """License update schema."""
    license_type: Optional[str] = None
    max_users: Optional[int] = None
    max_organizations: Optional[int] = None
    features: Optional[List[str]] = None
    expires_at: Optional[datetime] = None

class LicenseResponse(LicenseBase):
    """License response schema."""
    id: UUID
    organization_id: UUID
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

class LicenseListResponse(BaseModel):
    """License list response."""
    licenses: List[LicenseResponse]
    total: int
    page: int
    limit: int

# Analytics Schemas
class AnalyticsTimeRange(BaseModel):
    """Analytics time range."""
    start_date: datetime
    end_date: datetime
    granularity: str = Field(default="day", pattern="^(hour|day|week|month)$")

class AnalyticsMetric(BaseModel):
    """Single analytics metric."""
    name: str
    value: float
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None

class AnalyticsSeries(BaseModel):
    """Analytics data series."""
    metric_name: str
    data_points: List[AnalyticsMetric]
    aggregation: str = Field(default="sum", pattern="^(sum|avg|count|min|max)$")

class PlatformAnalyticsResponse(BaseModel):
    """Platform-wide analytics response."""
    time_range: AnalyticsTimeRange
    series: List[AnalyticsSeries]
    summary: Dict[str, Any]

class OrganizationAnalyticsResponse(BaseModel):
    """Organization-specific analytics response."""
    organization_id: UUID
    time_range: AnalyticsTimeRange
    series: List[AnalyticsSeries]
    summary: Dict[str, Any]

# Impersonation Schemas
class ImpersonationRequest(BaseModel):
    """User impersonation request."""
    target_user_id: UUID
    reason: str = Field(..., min_length=10, max_length=500)
    duration_minutes: int = Field(default=60, ge=5, le=480)  # 5 minutes to 8 hours

class ImpersonationResponse(BaseModel):
    """Impersonation response."""
    session_id: str
    target_user_id: UUID
    expires_at: datetime
    access_token: str

class ImpersonationEndRequest(BaseModel):
    """End impersonation request."""
    session_id: str

# Health Check Schemas
class HealthCheckComponent(BaseModel):
    """Health check component."""
    name: str
    status: str = Field(pattern="^(healthy|degraded|unhealthy)$")
    response_time_ms: float
    details: Dict[str, Any]
    last_checked: datetime

class SystemHealthResponse(BaseModel):
    """System health response."""
    overall_status: str = Field(pattern="^(healthy|degraded|unhealthy)$")
    components: List[HealthCheckComponent]
    timestamp: datetime
    uptime_seconds: int

# System Alert Schemas
class SystemAlertBase(BaseModel):
    """Base system alert schema."""
    alert_type: str
    severity: str = Field(pattern="^(info|warning|error|critical)$")
    title: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., min_length=1, max_length=1000)
    source: str = Field(default="system")
    metadata: Optional[Dict[str, Any]] = None

class SystemAlertCreate(SystemAlertBase):
    """System alert creation schema."""
    pass

class SystemAlertUpdate(BaseModel):
    """System alert update schema."""
    resolved: bool
    resolved_by: Optional[UUID] = None
    resolution_notes: Optional[str] = None

class SystemAlertResponse(SystemAlertBase):
    """System alert response schema."""
    id: UUID
    resolved: bool
    resolved_by: Optional[UUID] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

class SystemAlertListResponse(BaseModel):
    """System alert list response."""
    alerts: List[SystemAlertResponse]
    total: int
    page: int
    limit: int

# Additional System Management Schemas
class SystemStatsResponse(BaseModel):
    """System statistics response."""
    stats: SystemStats
    timestamp: datetime
    generated_by: UUID

class SystemBackupCreate(BaseModel):
    """System backup creation request."""
    backup_type: str = Field(default="full", pattern="^(full|incremental|differential)$")
    description: Optional[str] = None
    include_user_data: bool = Field(default=True)
    include_system_config: bool = Field(default=True)

class SystemBackupResponse(BaseModel):
    """System backup response."""
    id: UUID
    backup_type: str
    status: str = Field(pattern="^(pending|running|completed|failed)$")
    file_path: str
    file_size_bytes: int
    description: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    created_by: UUID

class SystemMaintenanceCreate(BaseModel):
    """System maintenance window creation."""
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)
    scheduled_start: datetime
    estimated_duration_minutes: int = Field(..., ge=1, le=1440)  # 1 minute to 24 hours
    maintenance_type: str = Field(default="planned", pattern="^(planned|emergency|routine)$")
    affected_services: List[str] = Field(default_factory=list)

class SystemMaintenanceResponse(BaseModel):
    """System maintenance response."""
    id: UUID
    title: str
    description: str
    scheduled_start: datetime
    estimated_duration_minutes: int
    actual_duration_minutes: Optional[int] = None
    maintenance_type: str
    status: str = Field(pattern="^(scheduled|in_progress|completed|cancelled)$")
    affected_services: List[str]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: UUID
