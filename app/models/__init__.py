"""
Models package initialization.
Imports all database models for the AuthX system with async support.
"""
from app.models.base import BaseModel, UUIDBaseModel, TenantBaseModel, Base
from app.models.user import User
from app.models.user_device import UserDevice
from app.models.organization import Organization
from app.models.organization_settings import OrganizationSettings
from app.models.role import Role, Permission
from app.models.location import Location
from app.models.location_group import LocationGroup, location_group_association
from app.models.audit import AuditLog, SecurityEvent, ComplianceReport, ForensicSnapshot
from app.models.admin import SystemConfig, License, UserImpersonation, MaintenanceWindow, PlatformMetric

# Export all models
__all__ = [
    # Base models
    "BaseModel",
    "UUIDBaseModel",
    "TenantBaseModel",
    "Base",

    # Core models
    "User",
    "UserDevice",
    "Organization",
    "OrganizationSettings",
    "Role",
    "Permission",
    "Location",
    "LocationGroup",

    # Audit and logging models
    "AuditLog",
    "SecurityEvent",
    "ComplianceReport",
    "ForensicSnapshot",

    # Admin models
    "SystemConfig",
    "License",
    "UserImpersonation",
    "MaintenanceWindow",
    "PlatformMetric",

    # Association tables
    "location_group_association",
]
