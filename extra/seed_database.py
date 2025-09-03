"""
Database seeding script for AuthX.
This script populates the database with comprehensive dummy data for testing all API endpoints.
"""
import asyncio
import uuid
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
import bcrypt

from app.db.session import AsyncSessionLocal
from app.models.organization import Organization
from app.models.user import User
from app.models.role import Role, Permission
from app.models.location import Location
from app.models.location_group import LocationGroup
from app.models.user_device import UserDevice
from app.models.organization_settings import OrganizationSettings
from app.models.audit import AuditLog, SecurityEvent, ComplianceReport, ForensicSnapshot
from app.models.admin import SystemConfig, License, UserImpersonation, MaintenanceWindow, PlatformMetric
from app.utils.security import get_password_hash

async def clean_database(db: AsyncSession):
    """Delete all existing data to start fresh."""
    print("Cleaning existing data from database...")

    # Disable foreign key checks temporarily or delete in correct order
    # Delete in reverse order of dependencies to avoid foreign key constraint errors
    await db.execute(delete(MaintenanceWindow))
    await db.execute(delete(PlatformMetric))
    await db.execute(delete(UserImpersonation))
    await db.execute(delete(ForensicSnapshot))
    await db.execute(delete(ComplianceReport))
    await db.execute(delete(SecurityEvent))
    await db.execute(delete(AuditLog))
    await db.execute(delete(UserDevice))
    await db.execute(delete(LocationGroup))
    await db.execute(delete(Location))

    # Clear user_id foreign key references in roles before deleting users
    from sqlalchemy import update
    await db.execute(update(Role).values(user_id=None))

    await db.execute(delete(User))
    await db.execute(delete(Role))
    await db.execute(delete(Permission))
    await db.execute(delete(License))
    await db.execute(delete(OrganizationSettings))
    await db.execute(delete(Organization))
    await db.execute(delete(SystemConfig))

    await db.commit()
    print("Database cleaned successfully!")

async def create_system_configs(db: AsyncSession):
    """Create system configuration entries."""
    print("Creating system configurations...")

    configs = [
        {
            "key": "security.max_login_attempts",
            "value": {"max_attempts": 5, "lockout_duration_minutes": 30},
            "description": "Maximum login attempts before account lockout"
        },
        {
            "key": "security.password_policy",
            "value": {
                "min_length": 8,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digits": True,
                "require_special_chars": True
            },
            "description": "Password complexity requirements"
        },
        {
            "key": "email.smtp_settings",
            "value": {
                "host": "smtp.gmail.com",
                "port": 587,
                "use_tls": True,
                "username": "authx@example.com"
            },
            "description": "SMTP configuration for email sending"
        },
        {
            "key": "audit.retention_days",
            "value": {"days": 90},
            "description": "Number of days to retain audit logs"
        }
    ]

    for config_data in configs:
        config = SystemConfig(**config_data)
        db.add(config)

    await db.commit()
    print(f"Created {len(configs)} system configurations")

async def create_organizations(db: AsyncSession):
    """Create sample organizations."""
    print("Creating organizations...")

    organizations_data = [
        {
            "name": "Acme Corporation",
            "slug": "acme-corp",
            "description": "A leading technology company",
            "is_active": True,
            "max_users": 1000,
            "subscription_tier": "enterprise"
        },
        {
            "name": "TechStart Inc",
            "slug": "techstart",
            "description": "An innovative startup",
            "is_active": True,
            "max_users": 50,
            "subscription_tier": "professional"
        },
        {
            "name": "Global Solutions Ltd",
            "slug": "global-solutions",
            "description": "International consulting firm",
            "is_active": True,
            "max_users": 500,
            "subscription_tier": "enterprise"
        }
    ]

    created_orgs = []
    for org_data in organizations_data:
        org = Organization(**org_data)
        db.add(org)
        created_orgs.append(org)

    await db.commit()
    # Refresh to get IDs
    for org in created_orgs:
        await db.refresh(org)

    print(f"Created {len(created_orgs)} organizations")
    return created_orgs

async def create_organization_settings(db: AsyncSession, organizations):
    """Create organization settings."""
    print("Creating organization settings...")

    for org in organizations:
        settings = OrganizationSettings(
            organization_id=org.id,
            security_settings={
                "enforce_mfa": True,
                "password_expiry_days": 90,
                "session_timeout_minutes": 60,
                "require_password_change": True,
                "enable_audit_logging": True,
                "ip_whitelist": [],
                "enable_geofencing": False,
                "max_login_attempts": 5,
                "lockout_duration_minutes": 30
            },
            notification_settings={
                "email_notifications": True,
                "security_alerts": True,
                "weekly_reports": True,
                "maintenance_notifications": True,
                "marketing_emails": False
            },
            branding_settings={
                "primary_color": "#2563eb",
                "secondary_color": "#64748b",
                "logo_url": None,
                "company_name": org.name
            },
            integration_settings={
                "allowed_file_types": ["pdf", "doc", "docx", "xls", "xlsx"],
                "max_file_size_mb": 10,
                "api_rate_limit": 1000,
                "webhook_endpoints": []
            },
            feature_flags={
                "beta_features": False,
                "advanced_analytics": True,
                "custom_themes": org.subscription_tier == "enterprise",
                "api_access": True
            },
            custom_settings={
                "timezone": "UTC",
                "date_format": "YYYY-MM-DD",
                "currency": "USD"
            }
        )
        db.add(settings)

    await db.commit()
    print(f"Created organization settings for {len(organizations)} organizations")

async def create_licenses(db: AsyncSession, organizations):
    """Create license entries for organizations."""
    print("Creating licenses...")

    for i, org in enumerate(organizations):
        license_data = {
            "license_key": f"AUTHX-{uuid.uuid4().hex[:16].upper()}",
            "organization_id": org.id,
            "license_type": ["trial", "professional", "enterprise"][i % 3],
            "status": "active",
            "max_users": org.max_users,
            "max_organizations": 1,
            "issued_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=365),
            "activated_at": datetime.utcnow(),
            "features": {
                "sso": True,
                "audit_logs": True,
                "api_access": True,
                "custom_roles": True,
                "advanced_security": i > 0
            },
            "license_metadata": {
                "issued_by": "AuthX System",
                "contact_email": f"admin@{org.slug}.example.com"
            }
        }
        license = License(**license_data)
        db.add(license)

    await db.commit()
    print(f"Created {len(organizations)} licenses")

async def create_permissions(db: AsyncSession):
    """Create system permissions."""
    print("Creating permissions...")

    permissions_data = [
        # User permissions
        {"name": "user.read", "description": "Read user information", "resource": "user", "action": "read"},
        {"name": "user.write", "description": "Create and update users", "resource": "user", "action": "write"},
        {"name": "user.delete", "description": "Delete users", "resource": "user", "action": "delete"},

        # Organization permissions
        {"name": "organization.read", "description": "Read organization data", "resource": "organization", "action": "read"},
        {"name": "organization.write", "description": "Update organization settings", "resource": "organization", "action": "write"},
        {"name": "organization.admin", "description": "Full organization administration", "resource": "organization", "action": "admin"},

        # Role permissions
        {"name": "role.read", "description": "View roles and permissions", "resource": "role", "action": "read"},
        {"name": "role.write", "description": "Create and modify roles", "resource": "role", "action": "write"},
        {"name": "role.assign", "description": "Assign roles to users", "resource": "role", "action": "assign"},

        # Location permissions
        {"name": "location.read", "description": "View locations", "resource": "location", "action": "read"},
        {"name": "location.write", "description": "Manage locations", "resource": "location", "action": "write"},
        {"name": "location.admin", "description": "Full location administration", "resource": "location", "action": "admin"},

        # Audit permissions
        {"name": "audit.read", "description": "View audit logs", "resource": "audit", "action": "read"},
        {"name": "audit.export", "description": "Export audit data", "resource": "audit", "action": "export"},

        # System permissions
        {"name": "system.admin", "description": "System administration", "resource": "system", "action": "admin"},
        {"name": "system.config", "description": "System configuration", "resource": "system", "action": "config"}
    ]

    created_permissions = []
    for perm_data in permissions_data:
        permission = Permission(**perm_data)
        db.add(permission)
        created_permissions.append(permission)

    await db.commit()
    # Refresh to get IDs
    for perm in created_permissions:
        await db.refresh(perm)

    print(f"Created {len(created_permissions)} permissions")
    return created_permissions

async def create_roles(db: AsyncSession, organizations, permissions):
    """Create roles for organizations."""
    print("Creating roles...")

    role_templates = [
        {
            "name": "Super Admin",
            "slug": "super-admin",
            "description": "Full system access",
            "is_system": True,
            "priority": 100,
            "permission_names": ["system.admin", "system.config", "organization.admin", "user.delete"]
        },
        {
            "name": "Organization Admin",
            "slug": "org-admin",
            "description": "Organization administration",
            "is_system": False,
            "priority": 90,
            "permission_names": ["organization.admin", "user.write", "role.write", "location.admin", "audit.read"]
        },
        {
            "name": "Manager",
            "slug": "manager",
            "description": "Team management role",
            "is_system": False,
            "priority": 70,
            "permission_names": ["user.read", "user.write", "role.read", "location.read", "audit.read"]
        },
        {
            "name": "Employee",
            "slug": "employee",
            "description": "Standard employee access",
            "is_system": False,
            "priority": 50,
            "permission_names": ["user.read", "organization.read", "location.read"]
        },
        {
            "name": "Auditor",
            "slug": "auditor",
            "description": "Audit and compliance access",
            "is_system": False,
            "priority": 60,
            "permission_names": ["audit.read", "audit.export", "organization.read", "user.read"]
        }
    ]

    created_roles = []
    for org in organizations:
        for role_template in role_templates:
            # Create permissions config
            permissions_config = {}
            for perm_name in role_template["permission_names"]:
                resource, action = perm_name.split(".")
                if resource not in permissions_config:
                    permissions_config[resource] = []
                permissions_config[resource].append(action)

            role = Role(
                name=role_template["name"],
                slug=role_template["slug"],
                description=role_template["description"],
                organization_id=org.id,
                is_system=role_template["is_system"],
                priority=role_template["priority"],
                permissions_config=permissions_config
            )
            db.add(role)
            created_roles.append(role)

    await db.commit()

    # Refresh to get IDs
    for role in created_roles:
        await db.refresh(role)

    print(f"Created {len(created_roles)} roles")
    return created_roles

async def create_users(db: AsyncSession, organizations, roles):
    """Create users for organizations."""
    print("Creating users...")

    user_templates = [
        {
            "email": "admin@{domain}",
            "username": "admin",
            "first_name": "Admin",
            "last_name": "User",
            "role_name": "Super Admin",
            "is_superuser": True,
            "is_verified": True
        },
        {
            "email": "manager@{domain}",
            "username": "manager",
            "first_name": "Manager",
            "last_name": "User",
            "role_name": "Manager",
            "is_superuser": False,
            "is_verified": True
        },
        {
            "email": "employee1@{domain}",
            "username": "employee1",
            "first_name": "John",
            "last_name": "Doe",
            "role_name": "Employee",
            "is_superuser": False,
            "is_verified": True
        },
        {
            "email": "employee2@{domain}",
            "username": "employee2",
            "first_name": "Jane",
            "last_name": "Smith",
            "role_name": "Employee",
            "is_superuser": False,
            "is_verified": True
        },
        {
            "email": "auditor@{domain}",
            "username": "auditor",
            "first_name": "Audit",
            "last_name": "User",
            "role_name": "Auditor",
            "is_superuser": False,
            "is_verified": True
        }
    ]

    created_users = []
    password_hash = get_password_hash("AuthX123!")  # Default password for all test users

    for org in organizations:
        for i, user_template in enumerate(user_templates):
            email = user_template["email"].format(domain=f"{org.slug}.example.com")
            username = f"{user_template['username']}_{org.slug}"

            user = User(
                email=email,
                username=username,
                first_name=user_template["first_name"],
                last_name=user_template["last_name"],
                hashed_password=password_hash,
                organization_id=org.id,
                is_superuser=user_template["is_superuser"],
                is_verified=user_template["is_verified"],
                is_active=True,
                phone_number=f"+1-555-{len(created_users):04d}",
                bio=f"Test user for {org.name}",
                timezone="UTC",
                locale="en"
            )
            db.add(user)
            created_users.append(user)

    await db.commit()
    # Refresh to get IDs
    for user in created_users:
        await db.refresh(user)

    print(f"Created {len(created_users)} users")
    return created_users

async def create_locations(db: AsyncSession, organizations):
    """Create locations for organizations."""
    print("Creating locations...")

    location_templates = [
        {
            "name": "Headquarters",
            "location_type": "office",
            "code": "HQ",
            "description": "Main office location",
            "address_line1": "123 Business Ave",
            "city": "New York",
            "state": "NY",
            "postal_code": "10001",
            "country": "USA",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "phone": "+1-555-0100",
            "is_primary": True
        },
        {
            "name": "Development Center",
            "location_type": "office",
            "code": "DEV",
            "description": "Software development office",
            "address_line1": "456 Tech Street",
            "city": "San Francisco",
            "state": "CA",
            "postal_code": "94102",
            "country": "USA",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "phone": "+1-555-0200"
        },
        {
            "name": "Warehouse A",
            "location_type": "warehouse",
            "code": "WH-A",
            "description": "Primary storage facility",
            "address_line1": "789 Industrial Blvd",
            "city": "Chicago",
            "state": "IL",
            "postal_code": "60601",
            "country": "USA",
            "latitude": 41.8781,
            "longitude": -87.6298,
            "phone": "+1-555-0300"
        },
        {
            "name": "Data Center 1",
            "location_type": "datacenter",
            "code": "DC1",
            "description": "Primary data center",
            "address_line1": "321 Server Farm Rd",
            "city": "Austin",
            "state": "TX",
            "postal_code": "78701",
            "country": "USA",
            "latitude": 30.2672,
            "longitude": -97.7431,
            "phone": "+1-555-0400"
        }
    ]

    created_locations = []
    for org in organizations:
        for loc_template in location_templates:
            location = Location(
                organization_id=org.id,
                **loc_template
            )
            db.add(location)
            created_locations.append(location)

    await db.commit()

    # Refresh to get IDs
    for location in created_locations:
        await db.refresh(location)

    print(f"Created {len(created_locations)} locations")
    return created_locations

async def create_location_groups(db: AsyncSession, organizations, locations):
    """Create location groups."""
    print("Creating location groups...")

    created_groups = []
    for org in organizations:
        org_locations = [l for l in locations if l.organization_id == org.id]

        # Create office group
        office_group = LocationGroup(
            organization_id=org.id,
            name="Office Locations",
            description="All office locations",
            color="#2563eb"
        )
        db.add(office_group)
        created_groups.append(office_group)

        # Create facilities group
        facilities_group = LocationGroup(
            organization_id=org.id,
            name="Facilities",
            description="Warehouses and data centers",
            color="#dc2626"
        )
        db.add(facilities_group)
        created_groups.append(facilities_group)

    await db.commit()
    print(f"Created {len(created_groups)} location groups")
    return created_groups

async def create_user_devices(db: AsyncSession, users):
    """Create user devices."""
    print("Creating user devices...")

    device_templates = [
        {
            "device_name": "iPhone 15 Pro",
            "device_type": "mobile",
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "browser_name": "Safari",
            "browser_version": "17.0",
            "os_name": "iOS",
            "os_version": "17.0",
            "is_trusted": True
        },
        {
            "device_name": "MacBook Pro",
            "device_type": "desktop",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "browser_name": "Chrome",
            "browser_version": "120.0",
            "os_name": "macOS",
            "os_version": "14.0",
            "is_trusted": True
        },
        {
            "device_name": "Unknown Device",
            "device_type": "unknown",
            "user_agent": "Mozilla/5.0 (Unknown Device) Generic Browser",
            "browser_name": "Unknown",
            "browser_version": "Unknown",
            "os_name": "Unknown",
            "os_version": "Unknown",
            "is_trusted": False
        }
    ]

    created_devices = []
    for i, user in enumerate(users[:10]):  # Create devices for first 10 users
        device_template = device_templates[i % len(device_templates)]
        ip_address = f"192.168.1.{i + 100}"

        device = UserDevice(
            user_id=user.id,
            device_fingerprint=f"fp_{uuid.uuid4().hex[:16]}",
            last_seen=datetime.utcnow(),
            ip_address=ip_address,
            location=f"Test Location {i}",
            country_code="US",
            first_login_ip=ip_address,  # Add required field
            last_login_ip=ip_address,   # Add required field
            **device_template
        )
        db.add(device)
        created_devices.append(device)

    await db.commit()
    print(f"Created {len(created_devices)} user devices")

async def create_audit_logs(db: AsyncSession, organizations, users):
    """Create sample audit logs."""
    print("Creating audit logs...")

    audit_templates = [
        {
            "event_type": "authentication",
            "resource_type": "user",
            "action": "login",
            "description": "User logged in successfully",
            "status": "success"
        },
        {
            "event_type": "authentication",
            "resource_type": "user",
            "action": "logout",
            "description": "User logged out",
            "status": "success"
        },
        {
            "event_type": "user_management",
            "resource_type": "user",
            "action": "create",
            "description": "New user account created",
            "status": "success"
        },
        {
            "event_type": "user_management",
            "resource_type": "user",
            "action": "update",
            "description": "User profile updated",
            "status": "success"
        },
        {
            "event_type": "role_management",
            "resource_type": "role",
            "action": "assign",
            "description": "Role assigned to user",
            "status": "success"
        },
        {
            "event_type": "security",
            "resource_type": "user",
            "action": "password_change",
            "description": "Password changed successfully",
            "status": "success"
        },
        {
            "event_type": "authentication",
            "resource_type": "user",
            "action": "login",
            "description": "Failed login attempt - invalid password",
            "status": "failure"
        }
    ]

    created_logs = []
    for org in organizations:
        org_users = [u for u in users if u.organization_id == org.id]

        # Create 50 audit logs per organization
        for i in range(50):
            template = audit_templates[i % len(audit_templates)]
            user = org_users[i % len(org_users)] if org_users else None

            audit_log = AuditLog(
                organization_id=org.id,
                user_id=user.id if user else None,
                user_email=user.email if user else None,
                ip_address=f"192.168.1.{i % 255}",
                user_agent="Mozilla/5.0 (Test Browser)",
                resource_id=str(user.id) if user else None,
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "session_id": f"session_{uuid.uuid4().hex[:8]}",
                    "location": "Test Location"
                },
                **template
            )
            db.add(audit_log)
            created_logs.append(audit_log)

    await db.commit()
    print(f"Created {len(created_logs)} audit logs")

async def create_security_events(db: AsyncSession, organizations, users):
    """Create sample security events."""
    print("Creating security events...")

    event_templates = [
        {
            "event_type": "suspicious_login",
            "severity": "medium",
            "description": "Login from unusual location detected",
            "status": "new"
        },
        {
            "event_type": "brute_force_attack",
            "severity": "high",
            "description": "Multiple failed login attempts detected",
            "status": "resolved"
        },
        {
            "event_type": "privilege_escalation",
            "severity": "critical",
            "description": "Unauthorized attempt to access admin functions",
            "status": "investigating"
        },
        {
            "event_type": "data_access_anomaly",
            "severity": "medium",
            "description": "Unusual data access pattern detected",
            "status": "resolved"
        },
        {
            "event_type": "account_lockout",
            "severity": "low",
            "description": "User account locked due to failed attempts",
            "status": "resolved"
        }
    ]

    created_events = []
    for org in organizations:
        org_users = [u for u in users if u.organization_id == org.id]

        # Create 20 security events per organization
        for i in range(20):
            template = event_templates[i % len(event_templates)]
            user = org_users[i % len(org_users)] if org_users else None

            security_event = SecurityEvent(
                organization_id=org.id,
                user_id=user.id if user else None,
                ip_address=f"203.0.113.{i % 255}",
                details={
                    "attack_vector": template["event_type"],
                    "detection_method": "automated",
                    "related_events": []
                },
                **template
            )

            # Set resolved fields for resolved events
            if template["status"] == "resolved":
                security_event.resolved_at = datetime.utcnow() - timedelta(hours=i)
                security_event.resolved_by = user.id if user else None
                security_event.resolution = "Event investigated and resolved by security team"

            db.add(security_event)
            created_events.append(security_event)

    await db.commit()
    print(f"Created {len(created_events)} security events")

async def create_platform_metrics(db: AsyncSession):
    """Create platform metrics."""
    print("Creating platform metrics...")

    metrics_data = [
        {"metric_name": "active_users", "metric_type": "gauge", "value": 150.0, "unit": "count"},
        {"metric_name": "total_logins", "metric_type": "counter", "value": 2500.0, "unit": "count"},
        {"metric_name": "failed_logins", "metric_type": "counter", "value": 45.0, "unit": "count"},
        {"metric_name": "api_requests", "metric_type": "counter", "value": 15000.0, "unit": "count"},
        {"metric_name": "response_time", "metric_type": "histogram", "value": 250.0, "unit": "ms"},
        {"metric_name": "error_rate", "metric_type": "gauge", "value": 0.5, "unit": "percent"},
        {"metric_name": "database_connections", "metric_type": "gauge", "value": 25.0, "unit": "count"},
        {"metric_name": "memory_usage", "metric_type": "gauge", "value": 65.0, "unit": "percent"}
    ]

    created_metrics = []
    for metric_data in metrics_data:
        # Create metrics for the last 7 days
        for i in range(7):
            metric = PlatformMetric(
                recorded_at=datetime.utcnow() - timedelta(days=i),
                dimensions={
                    "environment": "production",
                    "region": "us-east-1",
                    "day": i
                },
                description=f"Platform metric: {metric_data['metric_name']}",
                source="AuthX Monitoring",
                **metric_data
            )
            # Add some variance to the values
            metric.value += (i * 5) + ((i % 3) * 10)
            db.add(metric)
            created_metrics.append(metric)

    await db.commit()
    print(f"Created {len(created_metrics)} platform metrics")

async def create_maintenance_windows(db: AsyncSession, users):
    """Create maintenance windows."""
    print("Creating maintenance windows...")

    admin_user = next((u for u in users if u.is_superuser), users[0])

    maintenance_windows = [
        {
            "title": "Database Maintenance",
            "description": "Scheduled database optimization and backup",
            "maintenance_type": "scheduled",
            "status": "completed",
            "priority": "medium",
            "starts_at": datetime.utcnow() - timedelta(days=7),
            "ends_at": datetime.utcnow() - timedelta(days=7, hours=-2),
            "estimated_duration_minutes": 120,
            "affected_services": ["database", "api"],
            "notify_users": True,
            "created_by": admin_user.id
        },
        {
            "title": "Security Update",
            "description": "Critical security patches installation",
            "maintenance_type": "security",
            "status": "scheduled",
            "priority": "high",
            "starts_at": datetime.utcnow() + timedelta(days=2),
            "ends_at": datetime.utcnow() + timedelta(days=2, hours=1),
            "estimated_duration_minutes": 60,
            "affected_services": ["authentication", "api"],
            "notify_users": True,
            "created_by": admin_user.id
        },
        {
            "title": "System Upgrade",
            "description": "Platform version upgrade",
            "maintenance_type": "update",
            "status": "scheduled",
            "priority": "medium",
            "starts_at": datetime.utcnow() + timedelta(days=14),
            "ends_at": datetime.utcnow() + timedelta(days=14, hours=3),
            "estimated_duration_minutes": 180,
            "affected_services": ["all"],
            "notify_users": True,
            "created_by": admin_user.id
        }
    ]

    for window_data in maintenance_windows:
        maintenance = MaintenanceWindow(**window_data)
        db.add(maintenance)

    await db.commit()
    print(f"Created {len(maintenance_windows)} maintenance windows")

async def main():
    """Main seeding function."""
    print("Starting database seeding...")

    async with AsyncSessionLocal() as db:
        try:
            # Clean existing data
            await clean_database(db)

            # Create data in order of dependencies
            await create_system_configs(db)

            organizations = await create_organizations(db)
            await create_organization_settings(db, organizations)
            await create_licenses(db, organizations)

            permissions = await create_permissions(db)
            roles = await create_roles(db, organizations, permissions)
            users = await create_users(db, organizations, roles)

            locations = await create_locations(db, organizations)
            location_groups = await create_location_groups(db, organizations, locations)

            await create_user_devices(db, users)
            await create_audit_logs(db, organizations, users)
            await create_security_events(db, organizations, users)

            await create_platform_metrics(db)
            await create_maintenance_windows(db, users)

            print("\n" + "="*50)
            print("Database seeding completed successfully!")
            print("="*50)
            print(f"Created:")
            print(f"  - {len(organizations)} Organizations")
            print(f"  - {len(users)} Users (password: AuthX123!)")
            print(f"  - {len(roles)} Roles")
            print(f"  - {len(permissions)} Permissions")
            print(f"  - {len(locations)} Locations")
            print(f"  - Sample audit logs, security events, and metrics")
            print("\nTest users for each organization:")
            print("  - admin@[domain] (Super Admin)")
            print("  - manager@[domain] (Manager)")
            print("  - employee1@[domain] (Employee)")
            print("  - employee2@[domain] (Employee)")
            print("  - auditor@[domain] (Auditor)")
            print("\nAll users have the password: AuthX123!")

        except Exception as e:
            print(f"Error during seeding: {e}")
            await db.rollback()
            raise
        else:
            await db.commit()

if __name__ == "__main__":
    asyncio.run(main())
