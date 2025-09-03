"""
Organization management service for the AuthX microservice.
This module provides comprehensive organization management functionality.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.utils import generate_correlation_id
from app.models.organization import Organization
from app.models.organization_settings import OrganizationSettings
from app.models.user import User
from app.models.role import Role
from app.models.location import Location
from app.models.audit import AuditLog
from app.schemas.organization import OrganizationCreate, OrganizationUpdate
from app.services.email_service import EmailService

class OrganizationService:
    """Comprehensive organization management service."""

    def __init__(self):
        self.email_service = EmailService()

    async def create_organization(
        self,
        db: AsyncSession,
        org_create: OrganizationCreate,
        created_by: Optional[UUID] = None
    ) -> Organization:
        """Create a new organization with default settings."""

        # Check if organization with slug already exists
        existing_org = await self.get_organization_by_slug(db, org_create.slug)
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization with this slug already exists"
            )

        # Create organization
        organization = Organization(
            name=org_create.name,
            slug=org_create.slug,
            description=org_create.description,
            email=org_create.email,
            phone=org_create.phone,
            website=org_create.website,
            logo_url=org_create.logo_url,
            address_line1=org_create.address_line1,
            address_line2=org_create.address_line2,
            city=org_create.city,
            state=org_create.state,
            postal_code=org_create.postal_code,
            country=org_create.country,
            subscription_tier=org_create.subscription_tier,
            billing_email=org_create.billing_email,
            max_users=org_create.max_users,
            max_locations=org_create.max_locations,
            is_active=True
        )

        db.add(organization)
        await db.commit()
        await db.refresh(organization)

        # Create default organization settings
        await self._create_default_settings(db, organization.id)

        # Create default roles
        await self._create_default_roles(db, organization.id)

        # Log creation
        await self._log_organization_action(
            db, organization.id, created_by, "create", "success",
            f"Organization {organization.name} created successfully"
        )

        return organization

    async def get_organization_by_id(
        self,
        db: AsyncSession,
        org_id: UUID,
        include_settings: bool = False
    ) -> Optional[Organization]:
        """Get organization by ID with optional settings."""
        query = select(Organization).where(Organization.id == org_id)

        if include_settings:
            query = query.options(selectinload(Organization.settings))

        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_organization_by_slug(
        self,
        db: AsyncSession,
        slug: str
    ) -> Optional[Organization]:
        """Get organization by slug."""
        result = await db.execute(
            select(Organization).where(Organization.slug == slug.lower())
        )
        return result.scalar_one_or_none()

    async def update_organization(
        self,
        db: AsyncSession,
        org_id: UUID,
        org_update: OrganizationUpdate,
        updated_by: Optional[UUID] = None
    ) -> Organization:
        """Update organization with validation and audit logging."""
        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Update fields
        update_data = org_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(organization, field, value)

        await db.commit()
        await db.refresh(organization)

        # Log update
        await self._log_organization_action(
            db, organization.id, updated_by, "update", "success",
            f"Organization {organization.name} updated successfully"
        )

        return organization

    async def delete_organization(
        self,
        db: AsyncSession,
        org_id: UUID,
        deleted_by: Optional[UUID] = None
    ) -> bool:
        """Soft delete organization (deactivate)."""
        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Soft delete by deactivating
        organization.is_active = False
        await db.commit()

        # Log deletion
        await self._log_organization_action(
            db, organization.id, deleted_by, "delete", "success",
            f"Organization {organization.name} deactivated"
        )

        return True

    async def list_organizations(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[List[Organization], int]:
        """List organizations with filtering and pagination."""
        query = select(Organization)
        count_query = select(func.count(Organization.id))

        # Apply filters
        if is_active is not None:
            query = query.where(Organization.is_active == is_active)
            count_query = count_query.where(Organization.is_active == is_active)

        if search:
            search_filter = or_(
                Organization.name.ilike(f"%{search}%"),
                Organization.slug.ilike(f"%{search}%"),
                Organization.email.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)

        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Get organizations with pagination
        query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
        result = await db.execute(query)
        organizations = result.scalars().all()

        return list(organizations), total

    async def get_organization_statistics(
        self,
        db: AsyncSession,
        org_id: UUID
    ) -> Dict[str, Any]:
        """Get comprehensive organization statistics."""
        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # User statistics
        total_users_result = await db.execute(
            select(func.count(User.id)).where(User.organization_id == org_id)
        )
        total_users = total_users_result.scalar()

        active_users_result = await db.execute(
            select(func.count(User.id)).where(
                and_(User.organization_id == org_id, User.is_active == True)
            )
        )
        active_users = active_users_result.scalar()

        # Location statistics
        total_locations_result = await db.execute(
            select(func.count(Location.id)).where(Location.organization_id == org_id)
        )
        total_locations = total_locations_result.scalar()

        # Role statistics
        total_roles_result = await db.execute(
            select(func.count(Role.id)).where(Role.organization_id == org_id)
        )
        total_roles = total_roles_result.scalar()

        # Recent activity (last 30 days)
        recent_logins_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.organization_id == org_id,
                    AuditLog.event_type == "login",
                    AuditLog.status == "success",
                    AuditLog.created_at >= datetime.utcnow() - timedelta(days=30)
                )
            )
        )
        recent_logins = recent_logins_result.scalar()

        return {
            "organization_id": str(org_id),
            "name": organization.name,
            "total_users": total_users,
            "active_users": active_users,
            "total_locations": total_locations,
            "total_roles": total_roles,
            "recent_logins_30d": recent_logins,
            "subscription_tier": organization.subscription_tier,
            "max_users": organization.max_users,
            "max_locations": organization.max_locations,
            "user_utilization": (total_users / organization.max_users * 100) if organization.max_users else 0,
            "location_utilization": (total_locations / organization.max_locations * 100) if organization.max_locations else 0
        }

    async def get_organization_settings(
        self,
        db: AsyncSession,
        org_id: UUID
    ) -> Optional[OrganizationSettings]:
        """Get organization settings."""
        result = await db.execute(
            select(OrganizationSettings).where(
                OrganizationSettings.organization_id == org_id
            )
        )
        return result.scalar_one_or_none()

    async def update_organization_settings(
        self,
        db: AsyncSession,
        org_id: UUID,
        settings_data: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> OrganizationSettings:
        """Update organization settings."""
        settings = await self.get_organization_settings(db, org_id)
        if not settings:
            # Create settings if they don't exist
            settings = OrganizationSettings(organization_id=org_id)
            db.add(settings)

        # Update settings categories
        for category, data in settings_data.items():
            if hasattr(settings, f"{category}_settings"):
                setattr(settings, f"{category}_settings", data)

        await db.commit()
        await db.refresh(settings)

        # Log settings update
        await self._log_organization_action(
            db, org_id, updated_by, "update_settings", "success",
            f"Organization settings updated for {org_id}"
        )

        return settings

    async def add_organization_member(
        self,
        db: AsyncSession,
        org_id: UUID,
        user_id: UUID,
        role: str,
        added_by: Optional[UUID] = None
    ) -> bool:
        """Add a user to an organization."""
        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if organization is at user limit
        if organization.is_at_user_limit:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization has reached its user limit"
            )

        # Get user
        user_result = await db.execute(select(User).where(User.id == user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Update user's organization
        user.organization_id = org_id
        await db.commit()

        # Log member addition
        await self._log_organization_action(
            db, org_id, added_by, "add_member", "success",
            f"User {user.email} added to organization as {role}"
        )

        return True

    async def remove_organization_member(
        self,
        db: AsyncSession,
        org_id: UUID,
        user_id: UUID,
        removed_by: Optional[UUID] = None
    ) -> bool:
        """Remove a user from an organization."""
        user_result = await db.execute(
            select(User).where(
                and_(User.id == user_id, User.organization_id == org_id)
            )
        )
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in organization"
            )

        # Remove user from organization
        user.organization_id = None
        await db.commit()

        # Log member removal
        await self._log_organization_action(
            db, org_id, removed_by, "remove_member", "success",
            f"User {user.email} removed from organization"
        )

        return True

    async def _create_default_settings(
        self,
        db: AsyncSession,
        org_id: UUID
    ):
        """Create default organization settings."""
        settings = OrganizationSettings(
            organization_id=org_id,
            security_settings={
                "password_policy": {
                    "min_length": settings.PASSWORD_MIN_LENGTH,
                    "require_uppercase": settings.PASSWORD_REQUIRE_UPPERCASE,
                    "require_lowercase": settings.PASSWORD_REQUIRE_LOWERCASE,
                    "require_digits": settings.PASSWORD_REQUIRE_DIGITS,
                    "require_special": settings.PASSWORD_REQUIRE_SPECIAL
                },
                "mfa_required": False,
                "session_timeout": settings.SESSION_EXPIRE_MINUTES
            },
            branding_settings={
                "primary_color": "#007bff",
                "logo_url": None,
                "company_name": ""
            },
            notification_settings={
                "email_notifications": True,
                "security_alerts": True,
                "login_notifications": False
            },
            feature_flags={
                "mfa_enabled": True,
                "audit_logging": True,
                "device_tracking": True
            }
        )

        db.add(settings)
        await db.commit()

    async def _create_default_roles(
        self,
        db: AsyncSession,
        org_id: UUID
    ):
        """Create default roles for organization."""
        default_roles = [
            {
                "name": "Administrator",
                "slug": "admin",
                "description": "Full access to organization",
                "permissions": {
                    "users": {"create": True, "read": True, "update": True, "delete": True},
                    "roles": {"create": True, "read": True, "update": True, "delete": True},
                    "locations": {"create": True, "read": True, "update": True, "delete": True},
                    "organization": {"read": True, "update": True},
                    "audit": {"read": True}
                }
            },
            {
                "name": "Manager",
                "slug": "manager",
                "description": "Manage users and locations",
                "permissions": {
                    "users": {"create": True, "read": True, "update": True, "delete": False},
                    "roles": {"read": True},
                    "locations": {"create": True, "read": True, "update": True, "delete": False},
                    "organization": {"read": True}
                }
            },
            {
                "name": "User",
                "slug": "user",
                "description": "Standard user access",
                "is_default": True,
                "permissions": {
                    "users": {"read": False},
                    "roles": {"read": False},
                    "locations": {"read": True},
                    "organization": {"read": True}
                }
            }
        ]

        for role_data in default_roles:
            role = Role(
                organization_id=org_id,
                **role_data
            )
            db.add(role)

        await db.commit()

    async def _log_organization_action(
        self,
        db: AsyncSession,
        org_id: UUID,
        performed_by: Optional[UUID],
        action: str,
        status: str,
        description: str
    ):
        """Log organization management action."""
        audit_log = AuditLog(
            user_id=performed_by,
            organization_id=org_id,
            event_type="organization_management",
            resource_type="organization",
            resource_id=str(org_id),
            action=action,
            status=status,
            description=description,
            source="api"
        )
        db.add(audit_log)
        await db.commit()

# Global organization service instance
organization_service = OrganizationService()
