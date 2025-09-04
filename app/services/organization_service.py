"""
Organization management service for the AuthX microservice.
This module provides comprehensive organization management functionality with full async support.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging
import re

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.models.organization import Organization
from app.models.organization_settings import OrganizationSettings
from app.models.user import User
from app.models.role import Role

logger = logging.getLogger(__name__)

class OrganizationService:
    """Comprehensive organization management service with full async support."""

    def __init__(self):
        self.supported_subscription_tiers = [
            'free', 'basic', 'professional', 'enterprise', 'custom'
        ]

    def _generate_slug(self, name: str) -> str:
        """Generate a URL-friendly slug from organization name."""
        # Convert to lowercase and replace spaces with hyphens
        slug = re.sub(r'[^\w\s-]', '', name.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        return slug.strip('-')

    async def create_organization(
        self,
        db: AsyncSession,
        org_data: Dict[str, Any],
        created_by: Optional[UUID] = None
    ) -> Organization:
        """Create a new organization with comprehensive validation."""
        logger.info(f"Creating organization: {org_data.get('name')}")

        # Validate subscription tier
        subscription_tier = org_data.get('subscription_tier', 'free')
        if subscription_tier not in self.supported_subscription_tiers:
            logger.warning(f"Invalid subscription tier: {subscription_tier}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid subscription tier. Supported tiers: {', '.join(self.supported_subscription_tiers)}"
            )

        # Generate slug from name
        slug = self._generate_slug(org_data['name'])

        # Check if organization with same slug already exists
        existing_org = await self.get_organization_by_slug(db, slug)
        if existing_org:
            # Make slug unique by appending a number
            counter = 1
            while existing_org:
                new_slug = f"{slug}-{counter}"
                existing_org = await self.get_organization_by_slug(db, new_slug)
                counter += 1
            slug = new_slug

        # Create organization
        organization = Organization(
            name=org_data['name'],
            slug=slug,
            description=org_data.get('description'),
            subscription_tier=subscription_tier,
            max_users=org_data.get('max_users', 10),  # Default based on tier
            contact_email=org_data.get('contact_email'),
            contact_phone=org_data.get('contact_phone'),
            website=org_data.get('website'),
            industry=org_data.get('industry'),
            timezone=org_data.get('timezone', 'UTC'),
            created_by=created_by
        )

        db.add(organization)
        await db.commit()
        await db.refresh(organization)

        # Create default organization settings
        await self._create_default_settings(db, organization.id)

        # Create default roles for the organization
        await self._create_default_roles(db, organization.id)

        logger.info(f"Organization created successfully: {organization.id}")
        return organization

    async def get_organization_by_id(self, db: AsyncSession, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID with all relationships loaded."""
        logger.debug(f"Fetching organization by ID: {org_id}")

        result = await db.execute(
            select(Organization)
            .options(
                selectinload(Organization.users),
                selectinload(Organization.settings),
                selectinload(Organization.locations),
                selectinload(Organization.roles)
            )
            .where(Organization.id == org_id)
        )
        organization = result.scalar_one_or_none()

        if organization:
            logger.debug(f"Organization found: {organization.name}")
        else:
            logger.debug(f"Organization not found with ID: {org_id}")

        return organization

    async def get_organization_by_slug(self, db: AsyncSession, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        logger.debug(f"Fetching organization by slug: {slug}")

        result = await db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        return result.scalar_one_or_none()

    async def update_organization(
        self,
        db: AsyncSession,
        org_id: UUID,
        org_update: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> Optional[Organization]:
        """Update organization with validation."""
        logger.info(f"Updating organization: {org_id}")

        # Get existing organization
        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            logger.warning(f"Organization not found for update: {org_id}")
            return None

        # Validate subscription tier if being updated
        subscription_tier = org_update.get('subscription_tier')
        if subscription_tier and subscription_tier not in self.supported_subscription_tiers:
            logger.warning(f"Invalid subscription tier: {subscription_tier}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid subscription tier. Supported tiers: {', '.join(self.supported_subscription_tiers)}"
            )

        # Update allowed fields
        allowed_fields = {
            'name', 'description', 'subscription_tier', 'max_users',
            'contact_email', 'contact_phone', 'website', 'industry',
            'timezone', 'is_active'
        }

        # Update slug if name is being changed
        if 'name' in org_update and org_update['name'] != organization.name:
            new_slug = self._generate_slug(org_update['name'])
            existing_org = await self.get_organization_by_slug(db, new_slug)
            if existing_org and existing_org.id != org_id:
                # Make slug unique
                counter = 1
                while existing_org:
                    new_slug = f"{self._generate_slug(org_update['name'])}-{counter}"
                    existing_org = await self.get_organization_by_slug(db, new_slug)
                    counter += 1
            organization.slug = new_slug

        for field, value in org_update.items():
            if field in allowed_fields and hasattr(organization, field):
                setattr(organization, field, value)
                logger.debug(f"Updated {field} for organization {org_id}")

        organization.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(organization)

        logger.info(f"Organization updated successfully: {org_id}")
        return organization

    async def delete_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Delete organization with validation."""
        logger.info(f"Deleting organization: {org_id}")

        organization = await self.get_organization_by_id(db, org_id)
        if not organization:
            logger.warning(f"Organization not found for deletion: {org_id}")
            return False

        # Check if organization has active users
        result = await db.execute(
            select(func.count(User.id))
            .where(and_(User.organization_id == org_id, User.is_active == True))
        )
        active_user_count = result.scalar()

        if active_user_count > 0:
            logger.warning(f"Cannot delete organization with active users: {active_user_count}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete organization that has active users"
            )

        await db.execute(delete(Organization).where(Organization.id == org_id))
        await db.commit()

        logger.info(f"Organization deleted successfully: {org_id}")
        return True

    async def list_organizations(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[List[Organization], int]:
        """List organizations with filtering, search, and pagination."""
        logger.info(f"Listing organizations - skip: {skip}, limit: {limit}")

        # Build query
        query = select(Organization)

        # Apply filters
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                or_(
                    Organization.name.ilike(search_pattern),
                    Organization.description.ilike(search_pattern),
                    Organization.slug.ilike(search_pattern)
                )
            )

        if subscription_tier:
            query = query.where(Organization.subscription_tier == subscription_tier)

        if is_active is not None:
            query = query.where(Organization.is_active == is_active)

        # Get total count
        count_result = await db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar()

        # Apply pagination and ordering
        query = query.order_by(Organization.name).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        organizations = result.scalars().all()

        logger.info(f"Retrieved {len(organizations)} organizations out of {total} total")
        return organizations, total

    async def get_organization_stats(self, db: AsyncSession, org_id: UUID) -> Dict[str, Any]:
        """Get organization statistics."""
        logger.info(f"Getting stats for organization: {org_id}")

        # Get user count
        user_count_result = await db.execute(
            select(func.count(User.id)).where(User.organization_id == org_id)
        )
        total_users = user_count_result.scalar()

        # Get active user count
        active_user_count_result = await db.execute(
            select(func.count(User.id))
            .where(and_(User.organization_id == org_id, User.is_active == True))
        )
        active_users = active_user_count_result.scalar()

        # Get location count (if location model exists)
        try:
            from app.models.location import Location
            location_count_result = await db.execute(
                select(func.count(Location.id)).where(Location.organization_id == org_id)
            )
            total_locations = location_count_result.scalar()
        except ImportError:
            total_locations = 0

        # Get role count
        role_count_result = await db.execute(
            select(func.count(Role.id)).where(Role.organization_id == org_id)
        )
        total_roles = role_count_result.scalar()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_locations": total_locations,
            "total_roles": total_roles
        }

    async def _create_default_settings(self, db: AsyncSession, org_id: UUID):
        """Create default organization settings."""
        logger.debug(f"Creating default settings for organization: {org_id}")

        settings = OrganizationSettings(
            organization_id=org_id,
            settings_data={
                "security": {
                    "password_policy": {
                        "min_length": 8,
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "require_numbers": True,
                        "require_special_chars": True
                    },
                    "session_timeout": 3600,
                    "max_login_attempts": 5
                },
                "features": {
                    "multi_factor_auth": False,
                    "audit_logging": True,
                    "api_access": True
                },
                "notifications": {
                    "email_notifications": True,
                    "security_alerts": True
                }
            }
        )

        db.add(settings)
        await db.commit()

    async def _create_default_roles(self, db: AsyncSession, org_id: UUID):
        """Create default roles for organization."""
        logger.debug(f"Creating default roles for organization: {org_id}")

        default_roles = [
            {
                "name": "Administrator",
                "slug": "administrator",
                "description": "Full access to organization resources",
                "permissions_config": {
                    "users": ["read", "write", "delete"],
                    "roles": ["read", "write", "delete"],
                    "locations": ["read", "write", "delete"],
                    "organization": ["read", "write"]
                },
                "priority": 1
            },
            {
                "name": "Manager",
                "slug": "manager",
                "description": "Management access with limited administrative privileges",
                "permissions_config": {
                    "users": ["read", "write"],
                    "roles": ["read"],
                    "locations": ["read", "write"],
                    "organization": ["read"]
                },
                "priority": 2
            },
            {
                "name": "User",
                "slug": "user",
                "description": "Standard user access",
                "permissions_config": {
                    "users": ["read"],
                    "locations": ["read"]
                },
                "priority": 3,
                "is_default": True
            }
        ]

        for role_data in default_roles:
            role = Role(
                organization_id=org_id,
                **role_data
            )
            db.add(role)

        await db.commit()

# Create singleton instance
organization_service = OrganizationService()
