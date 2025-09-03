"""
Admin schemas for the AuthX service.
This module provides Pydantic models for system administration functionality.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# System Config Schemas
class SystemConfigBase(BaseSchema):
    """Base schema for system configuration."""
    key: str = Field(..., min_length=1, max_length=255)
    value: Dict[str, Any]
    description: Optional[str] = Field(None, max_length=1000)
    is_encrypted: bool = False

    @validator('key')
    def validate_key_format(cls, v):
        """Validate configuration key format."""
        import re
        if not re.match(r'^[a-z0-9._-]+$', v):
            raise ValueError('Key must contain only lowercase letters, numbers, dots, hyphens, and underscores')
        return v

class SystemConfigCreate(SystemConfigBase):
    """Schema for creating system configuration."""
    pass

class SystemConfigUpdate(BaseSchema):
    """Schema for updating system configuration."""
    value: Optional[Dict[str, Any]] = None
    description: Optional[str] = Field(None, max_length=1000)
    is_encrypted: Optional[bool] = None

class SystemConfigResponse(UUIDSchema, SystemConfigBase, TimestampSchema):
    """Schema for system configuration response."""
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None

class SystemConfigListResponse(BaseSchema):
    """Schema for paginated system config list response."""
    configs: List[SystemConfigResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# License Schemas
class LicenseBase(BaseSchema):
    """Base schema for license data."""
    license_key: str = Field(..., min_length=10, max_length=255)
    license_type: str = Field(..., pattern="^(trial|starter|professional|enterprise)$")
    max_users: Optional[int] = Field(None, ge=1)
    max_organizations: Optional[int] = Field(None, ge=1)
    features: Dict[str, Any] = Field(default_factory=dict)

class LicenseCreate(LicenseBase):
    """Schema for creating a license."""
    organization_id: UUID
    expires_at: Optional[datetime] = None

class LicenseUpdate(BaseSchema):
    """Schema for updating a license."""
    license_type: Optional[str] = Field(None, pattern="^(trial|starter|professional|enterprise)$")
    max_users: Optional[int] = Field(None, ge=1)
    max_organizations: Optional[int] = Field(None, ge=1)
    features: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None

class LicenseResponse(UUIDSchema, LicenseBase, TimestampSchema):
    """Schema for license response."""
    organization_id: UUID
    status: str
    issued_at: datetime
    expires_at: Optional[datetime]
    activated_at: Optional[datetime]

class LicenseListResponse(BaseSchema):
    """Schema for paginated license list response."""
    licenses: List[LicenseResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

# Analytics Schemas
class AnalyticsTimeRange(BaseSchema):
    """Schema for analytics time range."""
    start_date: datetime
    end_date: datetime
    granularity: str = Field(default="day", pattern="^(hour|day|week|month)$")

    @classmethod
    def last_30_days(cls) -> 'AnalyticsTimeRange':
        """Create a time range for the last 30 days."""
        from datetime import datetime, timedelta
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        return cls(start_date=start_date, end_date=end_date)

    @classmethod
    def last_7_days(cls) -> 'AnalyticsTimeRange':
        """Create a time range for the last 7 days."""
        from datetime import datetime, timedelta
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        return cls(start_date=start_date, end_date=end_date)

    @classmethod
    def last_24_hours(cls) -> 'AnalyticsTimeRange':
        """Create a time range for the last 24 hours."""
        from datetime import datetime, timedelta
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=24)
        return cls(start_date=start_date, end_date=end_date, granularity="hour")

class AnalyticsMetric(BaseSchema):
    """Schema for analytics metric."""
    name: str
    value: float
    unit: Optional[str] = None
    change_percentage: Optional[float] = None
    trend: Optional[str] = Field(None, pattern="^(up|down|stable)$")

class AnalyticsSeries(BaseModel):
    """Schema for analytics time series data."""
    timestamp: datetime
    value: float
    label: Optional[str] = None

class PlatformAnalyticsResponse(BaseSchema):
    """Schema for platform analytics response."""
    total_users: AnalyticsMetric
    active_users: AnalyticsMetric
    total_organizations: AnalyticsMetric
    total_sessions: AnalyticsMetric
    time_series: List[AnalyticsSeries] = Field(default_factory=list)
    top_organizations: List[Dict[str, Any]] = Field(default_factory=list)

class OrganizationAnalyticsResponse(BaseSchema):
    """Schema for organization analytics response."""
    organization_id: UUID
    organization_name: str
    user_count: AnalyticsMetric
    active_sessions: AnalyticsMetric
    login_frequency: AnalyticsMetric
    storage_usage: AnalyticsMetric
    time_series: List[AnalyticsSeries] = Field(default_factory=list)

# Impersonation Schemas
class ImpersonationRequest(BaseSchema):
    """Schema for user impersonation request."""
    target_user_id: UUID
    reason: str = Field(..., min_length=10, max_length=500)
    duration_minutes: int = Field(default=60, ge=5, le=480)  # Max 8 hours

class ImpersonationResponse(UUIDSchema, TimestampSchema):
    """Schema for impersonation response."""
    admin_user_id: UUID
    target_user_id: UUID
    session_token: str
    reason: str
    is_active: bool
    started_at: datetime
    expires_at: datetime
    ip_address: Optional[str]

class ImpersonationEndRequest(BaseSchema):
    """Schema for ending impersonation."""
    session_token: str

# System Health Schemas
class SystemHealthCheck(BaseSchema):
    """Schema for system health check request."""
    component: Optional[str] = Field(None, description="Specific component to check")
    deep_check: bool = Field(default=False, description="Perform deep health check")

class HealthCheckComponent(BaseSchema):
    """Schema for health check component."""
    name: str
    status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    message: Optional[str] = None
    response_time_ms: Optional[float] = None
    last_checked: datetime

class SystemHealthResponse(BaseSchema):
    """Schema for system health response."""
    overall_status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
    components: List[HealthCheckComponent]
    uptime_seconds: float
    version: str
    environment: str
    timestamp: datetime

# System Alert Schemas
class SystemAlertBase(BaseSchema):
    """Base schema for system alerts."""
    title: str = Field(..., min_length=1, max_length=255)
    message: str = Field(..., min_length=1, max_length=1000)
    alert_type: str = Field(..., pattern="^(info|warning|error|success)$")
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    target_type: str = Field(default="all", pattern="^(all|organization|user|role)$")
    target_ids: Optional[Dict[str, Any]] = Field(default_factory=dict)
    is_dismissible: bool = True
    auto_dismiss_after: Optional[int] = Field(None, ge=1, le=43200)  # Max 12 hours
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None

class SystemAlertCreate(SystemAlertBase):
    """Schema for creating system alerts."""
    pass

class SystemAlertUpdate(BaseSchema):
    """Schema for updating system alerts."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    message: Optional[str] = Field(None, min_length=1, max_length=1000)
    alert_type: Optional[str] = Field(None, pattern="^(info|warning|error|success)$")
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    target_type: Optional[str] = Field(None, pattern="^(all|organization|user|role)$")
    target_ids: Optional[Dict[str, Any]] = None
    is_dismissible: Optional[bool] = None
    auto_dismiss_after: Optional[int] = Field(None, ge=1, le=43200)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    is_active: Optional[bool] = None

class SystemAlertResponse(UUIDSchema, SystemAlertBase, TimestampSchema):
    """Schema for system alert response."""
    is_active: bool
    created_by: UUID

# System Statistics Schemas
class SystemStats(BaseSchema):
    """Schema for system statistics."""
    total_organizations: int
    total_users: int
    active_users_24h: int
    total_locations: int
    total_roles: int
    total_audit_logs: int
    total_security_events: int
    database_size_mb: Optional[float] = None
    cache_hit_rate: Optional[float] = None
    average_response_time_ms: Optional[float] = None

class SystemStatsResponse(BaseSchema):
    """Schema for system statistics response."""
    stats: SystemStats
    collected_at: datetime
    period: str = "current"

# System Backup Schemas
class SystemBackupCreate(BaseSchema):
    """Schema for creating system backup."""
    backup_type: str = Field(..., pattern="^(full|incremental|config_only)$")
    description: Optional[str] = Field(None, max_length=500)
    include_audit_logs: bool = True
    include_user_data: bool = True

class SystemBackupResponse(UUIDSchema, TimestampSchema):
    """Schema for system backup response."""
    backup_type: str
    description: Optional[str] = None
    status: str = Field(..., pattern="^(creating|completed|failed)$")
    file_path: Optional[str] = None
    file_size_mb: Optional[float] = None
    created_by: UUID
    completed_at: Optional[datetime] = None

# System Maintenance Schemas
class SystemMaintenanceCreate(BaseSchema):
    """Schema for scheduling system maintenance."""
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1, max_length=1000)
    maintenance_type: str = Field(..., pattern="^(update|migration|backup|cleanup)$")
    scheduled_start: datetime
    estimated_duration_minutes: int = Field(..., ge=1, le=1440)  # Max 24 hours
    notify_users: bool = True

class SystemMaintenanceResponse(UUIDSchema, SystemMaintenanceCreate, TimestampSchema):
    """Schema for system maintenance response."""
    status: str = Field(..., pattern="^(scheduled|in_progress|completed|cancelled)$")
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    created_by: UUID

# List Response Schemas
class SystemConfigListResponse(BaseSchema):
    """Schema for paginated system config list response."""
    configs: List[SystemConfigResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

class LicenseListResponse(BaseSchema):
    """Schema for paginated license list response."""
    licenses: List[LicenseResponse]
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool

class SystemAlertListResponse(BaseSchema):
    """Schema for system alert list response."""
    alerts: List[SystemAlertResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
