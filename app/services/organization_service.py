"""
Organization management service for the AuthX microservice.
This module provides comprehensive organization management functionality with full async support.
"""
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.location import Location
from app.models.organization import Organization
from app.models.organization_settings import OrganizationSettings
from app.models.role import Role
from app.models.user import User
from app.services.email_service import EmailService

logger = logging.getLogger(__name__)


class OrganizationService:
    """Comprehensive organization management service with full async support."""

    def __init__(self):
        self.email_service = EmailService()

    async def create_organization(
            self,
            db: AsyncSession,
            org_data: Dict[str, Any],
            created_by: Optional[UUID] = None
    ) -> Organization:
        """Create a new organization with default settings and comprehensive validation."""
        logger.info(f"Creating organization: {org_data.get('name')}")

        # Check if organization with slug already exists
        existing_org = await self.get_organization_by_slug(db, org_data.get('slug'))
        if existing_org:
            logger.warning(f"Organization creation failed - slug already exists: {org_data.get('slug')}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization with this slug already exists"
            )

        # Create organization
        organization = Organization(
            name=org_data['name'],
            slug=org_data['slug'],
            description=org_data.get('description'),
            email=org_data.get('email'),
            phone=org_data.get('phone'),
            website=org_data.get('website'),
            address_line1=org_data.get('address_line1'),
            address_line2=org_data.get('address_line2'),
            city=org_data.get('city'),
            state=org_data.get('state'),
            postal_code=org_data.get('postal_code'),
            country=org_data.get('country'),
            max_users=org_data.get('max_users', 100),
            max_locations=org_data.get('max_locations', 10),
            subscription_tier=org_data.get('subscription_tier', 'free'),
            billing_email=org_data.get('billing_email')
        )

        db.add(organization)
        await db.commit()
        await db.refresh(organization)

        # Create default organization settings
        await self._create_default_settings(db, organization.id)

        logger.info(f"Organization created successfully: {organization.id}")
        return organization

    async def get_organization_by_id(self, db: AsyncSession, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID with all relationships loaded."""
        logger.debug(f"Fetching organization by ID: {org_id}")

        result = await db.execute(
            select(Organization)
            .options(
                selectinload(Organization.users),
                selectinload(Organization.locations),
                selectinload(Organization.roles),
                selectinload(Organization.settings)
            )
            .where(Organization.id == org_id)
        )
        org = result.scalar_one_or_none()

        if org:
            logger.debug(f"Organization found: {org.name}")
        else:
            logger.debug(f"Organization not found with ID: {org_id}")

        return org

    async def get_organization_by_slug(self, db: AsyncSession, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        logger.debug(f"Fetching organization by slug: {slug}")

        result = await db.execute(
            select(Organization)
            .options(
                selectinload(Organization.users),
                selectinload(Organization.locations),
                selectinload(Organization.roles),
                selectinload(Organization.settings)
            )
            .where(Organization.slug == slug)
        )
        return result.scalar_one_or_none()

    async def update_organization(
            self,
            db: AsyncSession,
            org_id: UUID,
            org_update: Dict[str, Any],
            updated_by: Optional[UUID] = None
    ) -> Optional[Organization]:
        """Update organization with validation and audit logging."""
        logger.info(f"Updating organization: {org_id}")

        # Get existing organization
        org = await self.get_organization_by_id(db, org_id)
        if not org:
            logger.warning(f"Organization not found for update: {org_id}")
            return None

        # Update allowed fields
        allowed_fields = {
            'name', 'description', 'email', 'phone', 'website',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country', 'max_users', 'max_locations',
            'subscription_tier', 'billing_email', 'logo_url'
        }

        for field, value in org_update.items():
            if field in allowed_fields and hasattr(org, field):
                setattr(org, field, value)
                logger.debug(f"Updated {field} for organization {org_id}")

        org.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(org)

        logger.info(f"Organization updated successfully: {org_id}")
        return org

    async def activate_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Activate organization."""
        logger.info(f"Activating organization: {org_id}")

        org = await self.get_organization_by_id(db, org_id)
        if not org:
            logger.warning(f"Organization not found for activation: {org_id}")
            return False

        org.is_active = True
        await db.commit()

        logger.info(f"Organization activated successfully: {org_id}")
        return True

    async def deactivate_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Deactivate organization."""
        logger.info(f"Deactivating organization: {org_id}")

        org = await self.get_organization_by_id(db, org_id)
        if not org:
            logger.warning(f"Organization not found for deactivation: {org_id}")
            return False

        org.is_active = False
        await db.commit()

        logger.info(f"Organization deactivated successfully: {org_id}")
        return True

    async def delete_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Soft delete organization."""
        logger.info(f"Deleting organization: {org_id}")

        org = await self.get_organization_by_id(db, org_id)
        if not org:
            logger.warning(f"Organization not found for deletion: {org_id}")
            return False

        # Check if organization has active users
        result = await db.execute(
            select(func.count(User.id)).where(
                and_(User.organization_id == org_id, User.is_active == True)
            )
        )
        active_users = result.scalar()

        if active_users > 0:
            logger.warning(f"Cannot delete organization with active users: {active_users}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete organization with {active_users} active users"
            )

        # Soft delete by deactivating
        org.is_active = False
        org.updated_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Organization deleted successfully: {org_id}")
        return True

    async def list_organizations(self,
                                 db: AsyncSession, skip: int = 0,
                                 limit: int = 100, search: Optional[str] = None,
                                 is_active: Optional[bool] = None
                                 ) -> Tuple[List[Organization], int]:
        """List organizations with pagination and filtering."""
        logger.debug(f"Listing organizations - skip: {skip}, limit: {limit}, search: {search}")

        query = select(Organization).options(
            selectinload(Organization.users),
            selectinload(Organization.settings)
        )

        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    Organization.name.ilike(search_term),
                    Organization.slug.ilike(search_term),
                    Organization.description.ilike(search_term)
                )
            )

        if is_active is not None:
            query = query.where(Organization.is_active == is_active)

        # Get total count
        count_query = select(func.count(Organization.id))
        if search:
            count_query = count_query.where(
                or_(
                    Organization.name.ilike(search_term),
                    Organization.slug.ilike(search_term),
                    Organization.description.ilike(search_term)
                )
            )
        if is_active is not None:
            count_query = count_query.where(Organization.is_active == is_active)

        count_result = await db.execute(count_query)
        total = count_result.scalar()

        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
        result = await db.execute(query)
        organizations = result.scalars().all()

        logger.debug(f"Found {len(organizations)} organizations out of {total} total")
        return list(organizations), total

    async def get_organization_stats(self, db: AsyncSession, org_id: UUID) -> Dict[str, Any]:
        """Get organization statistics."""
        logger.debug(f"Getting stats for organization: {org_id}")

        # Get user count
        user_count_result = await db.execute(
            select(func.count(User.id)).where(User.organization_id == org_id)
        )
        user_count = user_count_result.scalar()

        # Get active user count
        active_user_count_result = await db.execute(
            select(func.count(User.id)).where(
                and_(User.organization_id == org_id, User.is_active == True)
            )
        )
        active_user_count = active_user_count_result.scalar()

        # Get location count
        location_count_result = await db.execute(
            select(func.count(Location.id)).where(Location.organization_id == org_id)
        )
        location_count = location_count_result.scalar()

        # Get role count
        role_count_result = await db.execute(
            select(func.count(Role.id)).where(Role.organization_id == org_id)
        )
        role_count = role_count_result.scalar()

        stats = {
            'total_users': user_count,
            'active_users': active_user_count,
            'total_locations': location_count,
            'total_roles': role_count
        }

        logger.debug(f"Organization stats: {stats}")
        return stats

    async def _create_default_settings(self, db: AsyncSession, org_id: UUID):
        """Create default organization settings."""
        logger.debug(f"Creating default settings for organization: {org_id}")

        settings = OrganizationSettings(
            organization_id=org_id,
            timezone='UTC',
            date_format='YYYY-MM-DD',
            time_format='24h',
            language='en',
            currency='USD',
            password_policy={
                'min_length': 8,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special_chars': True
            },
            session_timeout_minutes=60,
            max_login_attempts=5,
            lockout_duration_minutes=15,
            require_mfa=False,
            allowed_mfa_methods=['totp', 'email'],
            require_email_verification=True
        )

        db.add(settings)
        await db.commit()
        logger.debug(f"Default settings created for organization: {org_id}")


# Create singleton instance
organization_service = OrganizationService()
