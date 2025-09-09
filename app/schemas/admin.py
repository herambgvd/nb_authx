"""
Admin schemas for AuthX API.
Defines Pydantic models for admin-related data validation and serialization.
"""
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema


class SystemConfigBase(BaseModel):
    """Base system configuration schema."""
    key: str = Field(..., min_length=1, max_length=255, description="Configuration key")
    value: Dict[str, Any] = Field(..., description="Configuration value")
    description: Optional[str] = Field(None, max_length=1000, description="Configuration description")
    is_encrypted: bool = Field(False, description="Whether the value is encrypted")

    @validator('key')
    def validate_key(cls, v):
        if not v or not v.strip():
            raise ValueError('Configuration key cannot be empty')
        return v.strip().upper()


class SystemConfigCreate(SystemConfigBase):
    """Schema for creating a system configuration."""
    pass


class SystemConfigUpdate(BaseModel):
    """Schema for updating a system configuration."""
    value: Optional[Dict[str, Any]] = None
    description: Optional[str] = Field(None, max_length=1000)
    is_encrypted: Optional[bool] = None


class SystemConfigResponse(SystemConfigBase):
    """Schema for system configuration responses."""
    id: UUID
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None

    class Config:
        from_attributes = True


class LicenseBase(BaseModel):
    """Base license schema."""
    license_key: str = Field(..., min_length=1, max_length=255, description="License key")
    organization_id: UUID = Field(..., description="Organization ID")
    license_type: str = Field(..., max_length=50, description="License type")
    max_users: int = Field(100, ge=1, description="Maximum number of users")
    max_locations: int = Field(10, ge=1, description="Maximum number of locations")
    valid_from: datetime = Field(..., description="License valid from date")
    valid_until: datetime = Field(..., description="License valid until date")
    is_active: bool = Field(True, description="License active status")
    features: Optional[Dict[str, Any]] = Field(None, description="License features")

    @validator('license_type')
    def validate_license_type(cls, v):
        allowed_types = ['trial', 'basic', 'premium', 'enterprise']
        if v not in allowed_types:
            raise ValueError(f'License type must be one of: {", ".join(allowed_types)}')
        return v

    @validator('valid_until')
    def validate_dates(cls, v, values):
        if 'valid_from' in values and v <= values['valid_from']:
            raise ValueError('Valid until date must be after valid from date')
        return v


class LicenseCreate(LicenseBase):
    """Schema for creating a license."""
    pass


class LicenseUpdate(BaseModel):
    """Schema for updating a license."""
    license_type: Optional[str] = Field(None, max_length=50)
    max_users: Optional[int] = Field(None, ge=1)
    max_locations: Optional[int] = Field(None, ge=1)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_active: Optional[bool] = None
    features: Optional[Dict[str, Any]] = None

    @validator('license_type')
    def validate_license_type(cls, v):
        if v is not None:
            allowed_types = ['trial', 'basic', 'premium', 'enterprise']
            if v not in allowed_types:
                raise ValueError(f'License type must be one of: {", ".join(allowed_types)}')
        return v


class LicenseResponse(LicenseBase):
    """Schema for license responses."""
    id: UUID
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None

    class Config:
        from_attributes = True


class AdminBase(BaseModel):
    """Base admin schema."""
    user_id: UUID = Field(..., description="User ID")
    admin_level: str = Field("super_admin", max_length=50, description="Admin level")
    permissions: Optional[Dict[str, Any]] = Field(None, description="Admin permissions")
    is_active: bool = Field(True, description="Admin active status")

    @validator('admin_level')
    def validate_admin_level(cls, v):
        allowed_levels = ['super_admin', 'admin', 'moderator']
        if v not in allowed_levels:
            raise ValueError(f'Admin level must be one of: {", ".join(allowed_levels)}')
        return v


class AdminCreate(AdminBase):
    """Schema for creating an admin."""
    pass


class AdminUpdate(BaseModel):
    """Schema for updating an admin."""
    admin_level: Optional[str] = Field(None, max_length=50)
    permissions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

    @validator('admin_level')
    def validate_admin_level(cls, v):
        if v is not None:
            allowed_levels = ['super_admin', 'admin', 'moderator']
            if v not in allowed_levels:
                raise ValueError(f'Admin level must be one of: {", ".join(allowed_levels)}')
        return v


class AdminResponse(AdminBase):
    """Schema for admin responses."""
    id: UUID
    created_at: datetime
    created_by: Optional[UUID] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class AdminStats(BaseModel):
    """Schema for admin statistics."""
    total_users: int
    active_users: int
    total_organizations: int
    active_organizations: int
    total_locations: int
    active_locations: int
    system_health: str
    recent_activities: List[Dict[str, Any]] = []


class SystemHealthResponse(BaseModel):
    """Schema for system health responses."""
    status: str
    timestamp: datetime
    version: str
    environment: str
    database_status: str
    redis_status: str
    services: Dict[str, Any]
    metrics: Dict[str, Any]


class SuperAdminDashboard(BaseModel):
    """Schema for super admin dashboard data."""
    total_organizations: int
    active_organizations: int
    pending_organizations: int
    total_users: int
    active_users: int
    new_users_today: int
    system_health: str
    recent_activities: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    alerts: List[Dict[str, Any]]


class OrganizationApprovalRequest(BaseModel):
    """Schema for organization approval requests."""
    organization_id: UUID = Field(..., description="Organization ID to approve")
    approval_notes: Optional[str] = Field(None, max_length=1000, description="Approval notes")
    license_type: str = Field("basic", description="License type to assign")
    max_users: int = Field(100, ge=1, description="Maximum users allowed")
    max_locations: int = Field(10, ge=1, description="Maximum locations allowed")


class OrganizationRejectionRequest(BaseModel):
    """Schema for organization rejection requests."""
    organization_id: UUID = Field(..., description="Organization ID to reject")
    rejection_reason: str = Field(..., min_length=1, max_length=1000, description="Reason for rejection")
    notify_user: bool = Field(True, description="Whether to notify the organization owner")


class UserManagementAction(BaseModel):
    """Schema for user management actions."""
    user_ids: List[UUID] = Field(..., min_items=1, description="List of user IDs")
    action: str = Field(..., description="Action to perform")
    reason: Optional[str] = Field(None, max_length=500, description="Reason for action")

    @validator('action')
    def validate_action(cls, v):
        allowed_actions = ['activate', 'deactivate', 'suspend', 'verify', 'unverify', 'reset_password', 'force_logout']
        if v not in allowed_actions:
            raise ValueError(f'Action must be one of: {", ".join(allowed_actions)}')
        return v


class AuditLogFilter(BaseModel):
    """Schema for audit log filtering."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    action_type: Optional[str] = None
    resource_type: Optional[str] = None
    ip_address: Optional[str] = None
    severity: Optional[str] = None


class UserFilter(BaseModel):
    """Schema for user filtering."""
    organization_id: Optional[UUID] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_superuser: Optional[bool] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    last_login_after: Optional[datetime] = None
    last_login_before: Optional[datetime] = None


class SystemAlert(BaseModel):
    """Schema for system alerts."""
    id: UUID
    alert_type: str
    severity: str
    title: str
    message: str
    details: Optional[Dict[str, Any]] = None
    is_acknowledged: bool = False
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[UUID] = None


class PerformanceMetrics(BaseModel):
    """Schema for system performance metrics."""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    database_connections: int
    active_sessions: int
    requests_per_minute: int
    response_time_avg: float
    error_rate: float
    uptime_seconds: int


class SystemStats(BaseModel):
    """Schema for comprehensive system statistics."""
    total_users: int
    active_users: int
    inactive_users: int
    verified_users: int
    unverified_users: int
    total_organizations: int
    active_organizations: int
    pending_organizations: int
    total_locations: int
    active_locations: int
    total_roles: int
    total_sessions: int
    system_uptime: int
    database_size: Optional[str] = None
    cache_hit_ratio: Optional[float] = None
    avg_response_time: Optional[float] = None
    error_rate: Optional[float] = None
    last_updated: datetime

