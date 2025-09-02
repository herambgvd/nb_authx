"""
Super Admin schemas for the AuthX service.
This module provides Pydantic models for super admin-related API requests and responses.
"""
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from pydantic import BaseModel, Field, validator

from app.schemas.base import BaseSchema, UUIDSchema, TimestampSchema

# System Config Schemas
class SystemConfigBase(BaseSchema):
    """Base schema for system configuration data."""
    key: str
    value: Any
    description: Optional[str] = None
    is_encrypted: bool = False

class SystemConfigCreate(SystemConfigBase):
    """Schema for creating a new system configuration."""
    pass

class SystemConfigUpdate(BaseSchema):
    """Schema for updating a system configuration."""
    value: Any
    description: Optional[str] = None

class SystemConfigResponse(UUIDSchema, SystemConfigBase, TimestampSchema):
    """Schema for system configuration response data."""
    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "key": "default_password_policy",
                "value": "standard",
                "description": "Default password policy for new organizations",
                "is_encrypted": False,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class SystemConfigListResponse(BaseSchema):
    """Schema for paginated system configuration response data."""
    items: List[SystemConfigResponse]
    total: int
    page: int
    size: int

# License Management Schemas
class LicenseBase(BaseSchema):
    """Base schema for license data."""
    key: str
    organization_id: Optional[UUID] = None
    type: str  # enterprise, professional, starter, trial
    max_users: int
    max_locations: int
    features: List[str]
    issued_date: datetime
    expiration_date: datetime
    is_active: bool = True

class LicenseCreate(LicenseBase):
    """Schema for creating a new license."""
    pass

class LicenseUpdate(BaseSchema):
    """Schema for updating a license."""
    type: Optional[str] = None
    max_users: Optional[int] = None
    max_locations: Optional[int] = None
    features: Optional[List[str]] = None
    expiration_date: Optional[datetime] = None
    is_active: Optional[bool] = None

class LicenseResponse(UUIDSchema, LicenseBase, TimestampSchema):
    """Schema for license response data."""
    status: str  # active, expired, revoked
    usage: Dict[str, Any]  # Current usage metrics

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "key": "LICENSE-123-456-789",
                "organization_id": "550e8400-e29b-41d4-a716-446655440001",
                "type": "enterprise",
                "max_users": 1000,
                "max_locations": 100,
                "features": ["advanced_rbac", "sso", "audit_logs"],
                "issued_date": "2023-01-01T00:00:00Z",
                "expiration_date": "2024-01-01T00:00:00Z",
                "is_active": True,
                "status": "active",
                "usage": {
                    "current_users": 450,
                    "current_locations": 35
                },
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }

class LicenseListResponse(BaseSchema):
    """Schema for paginated license response data."""
    items: List[LicenseResponse]
    total: int
    page: int
    size: int

# Platform Analytics Schemas
class AnalyticsTimeRange(BaseSchema):
    """Schema for analytics time range."""
    start_date: datetime
    end_date: datetime
    interval: str = "day"  # day, week, month

class AnalyticsMetric(BaseSchema):
    """Schema for a single analytics metric."""
    name: str
    value: Any
    change: Optional[float] = None  # Percentage change from previous period
    trend: Optional[str] = None  # up, down, flat

class AnalyticsSeries(BaseSchema):
    """Schema for a time series of analytics data."""
    name: str
    data: List[Dict[str, Any]]  # List of {timestamp, value} pairs

class PlatformAnalyticsResponse(BaseSchema):
    """Schema for platform analytics response data."""
    time_range: Dict[str, Any]
    summary_metrics: List[AnalyticsMetric]
    series_data: List[AnalyticsSeries]

class OrganizationAnalyticsResponse(BaseSchema):
    """Schema for organization analytics response data."""
    organization_id: UUID
    time_range: Dict[str, Any]
    summary_metrics: List[AnalyticsMetric]
    series_data: List[AnalyticsSeries]

# User Impersonation Schemas
class ImpersonationRequest(BaseSchema):
    """Schema for requesting user impersonation."""
    user_id: UUID
    reason: str
    max_duration_minutes: int = 60

class ImpersonationResponse(UUIDSchema, TimestampSchema):
    """Schema for impersonation response data."""
    user_id: UUID
    impersonator_id: UUID
    reason: str
    token: str
    expires_at: datetime
    is_active: bool = True

class ImpersonationEndRequest(BaseSchema):
    """Schema for ending an impersonation session."""
    session_id: UUID

# System Health Schemas
class HealthCheckComponent(BaseSchema):
    """Schema for a health check component."""
    name: str
    status: str  # healthy, degraded, unhealthy
    details: Optional[Dict[str, Any]] = None

class SystemHealthResponse(BaseSchema):
    """Schema for system health response data."""
    status: str  # healthy, degraded, unhealthy
    components: List[HealthCheckComponent]
    timestamp: datetime
