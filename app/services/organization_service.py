"""
Organization service for AuthX.
Provides comprehensive organization management operations with async support.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
from typing import Optional, List, Dict, Any
from uuid import UUID
import logging
import re

from app.models.organization import Organization
from app.models.user import User
from app.models.location import Location
from app.models.role import Role
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationSearchRequest,
    OrganizationStats
)

logger = logging.getLogger(__name__)


class OrganizationService:
    """Service class for organization management operations."""

    async def create_organization(
        self,
        db: AsyncSession,
        org_data: OrganizationCreate,
        creator_id: UUID
    ) -> Organization:
        """Create a new organization with validation."""

        # Generate slug from name
        slug = self._generate_slug(org_data.name)

        # Check if organization with same name or slug exists
        existing_org = await self._get_by_name_or_slug(db, org_data.name, slug)
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization with this name already exists"
            )

        # Check domain uniqueness if provided
        if org_data.domain:
            existing_domain = await self._get_by_domain(db, org_data.domain)
            if existing_domain:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization with this domain already exists"
                )

        # Create organization
        organization = Organization(
            name=org_data.name,
            slug=slug,
            description=org_data.description,
            domain=org_data.domain,
            email=org_data.email,
            phone=org_data.phone,
            website=org_data.website,
            address_line1=org_data.address_line1,
            address_line2=org_data.address_line2,
            city=org_data.city,
            state=org_data.state,
            postal_code=org_data.postal_code,
            country=org_data.country,
            max_users=org_data.max_users,
            max_locations=org_data.max_locations,
            logo_url=org_data.logo_url,
            subscription_tier=org_data.subscription_tier,
            billing_email=org_data.billing_email
        )

        db.add(organization)
        await db.commit()
        await db.refresh(organization)

        logger.info(f"Organization created: {organization.id} - {organization.name}")
        return organization

    async def get_organization(self, db: AsyncSession, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID with related data."""
        result = await db.execute(
            select(Organization)
            .options(selectinload(Organization.users))
            .where(Organization.id == org_id)
        )
        return result.scalar_one_or_none()

    async def get_organization_by_slug(self, db: AsyncSession, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        result = await db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        return result.scalar_one_or_none()

    async def get_organizations(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        search: Optional[OrganizationSearchRequest] = None
    ) -> tuple[List[Organization], int]:
        """Get paginated list of organizations with optional filtering."""

        query = select(Organization).options(selectinload(Organization.users))
        count_query = select(func.count(Organization.id))

        # Apply filters if search criteria provided
        if search:
            conditions = []

            if search.query:
                search_term = f"%{search.query}%"
                conditions.append(
                    or_(
                        Organization.name.ilike(search_term),
                        Organization.description.ilike(search_term),
                        Organization.domain.ilike(search_term)
                    )
                )

            if search.is_active is not None:
                conditions.append(Organization.is_active == search.is_active)

            if search.subscription_tier:
                conditions.append(Organization.subscription_tier == search.subscription_tier)

            if search.domain:
                conditions.append(Organization.domain.ilike(f"%{search.domain}%"))

            if conditions:
                filter_clause = and_(*conditions)
                query = query.where(filter_clause)
                count_query = count_query.where(filter_clause)

        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
        result = await db.execute(query)
        organizations = result.scalars().all()

        return list(organizations), total

    async def update_organization(
        self,
        db: AsyncSession,
        org_id: UUID,
        org_data: OrganizationUpdate
    ) -> Organization:
        """Update organization with validation."""

        organization = await self.get_organization(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check name uniqueness if name is being updated
        if org_data.name and org_data.name != organization.name:
            new_slug = self._generate_slug(org_data.name)
            existing_org = await self._get_by_name_or_slug(db, org_data.name, new_slug)
            if existing_org and existing_org.id != org_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization with this name already exists"
                )
            organization.slug = new_slug

        # Check domain uniqueness if domain is being updated
        if org_data.domain and org_data.domain != organization.domain:
            existing_domain = await self._get_by_domain(db, org_data.domain)
            if existing_domain and existing_domain.id != org_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization with this domain already exists"
                )

        # Update fields
        update_data = org_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(organization, field, value)

        await db.commit()
        await db.refresh(organization)

        logger.info(f"Organization updated: {organization.id} - {organization.name}")
        return organization

    async def delete_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Soft delete organization and handle related data."""

        organization = await self.get_organization(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if organization has users
        if organization.users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete organization with active users. Transfer or deactivate users first."
            )

        # Soft delete by deactivating
        organization.is_active = False
        await db.commit()

        logger.info(f"Organization deactivated: {organization.id} - {organization.name}")
        return True

    async def get_organization_stats(self, db: AsyncSession, org_id: UUID) -> OrganizationStats:
        """Get comprehensive statistics for an organization."""

        organization = await self.get_organization(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Get user statistics
        user_stats = await db.execute(
            select(
                func.count(User.id).label('total_users'),
                func.count(User.id).filter(User.is_active == True).label('active_users')
            ).where(User.organization_id == org_id)
        )
        user_counts = user_stats.one()

        # Get location statistics
        location_stats = await db.execute(
            select(
                func.count(Location.id).label('total_locations'),
                func.count(Location.id).filter(Location.is_active == True).label('active_locations')
            ).where(Location.organization_id == org_id)
        )
        location_counts = location_stats.one()

        # Get role count
        role_stats = await db.execute(
            select(func.count(Role.id)).where(Role.organization_id == org_id)
        )
        role_count = role_stats.scalar()

        return OrganizationStats(
            total_users=user_counts.total_users,
            active_users=user_counts.active_users,
            total_locations=location_counts.total_locations,
            active_locations=location_counts.active_locations,
            total_roles=role_count,
            subscription_tier=organization.subscription_tier,
            is_at_user_limit=organization.is_at_user_limit,
            is_at_location_limit=(
                organization.max_locations is not None and
                location_counts.total_locations >= organization.max_locations
            )
        )

    async def bulk_action(
        self,
        db: AsyncSession,
        organization_ids: List[UUID],
        action: str
    ) -> Dict[str, Any]:
        """Perform bulk actions on organizations."""

        # Get organizations
        result = await db.execute(
            select(Organization).where(Organization.id.in_(organization_ids))
        )
        organizations = result.scalars().all()

        if not organizations:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No organizations found with provided IDs"
            )

        success_count = 0
        errors = []

        for org in organizations:
            try:
                if action == "activate":
                    org.is_active = True
                    success_count += 1
                elif action == "deactivate":
                    org.is_active = False
                    success_count += 1
                elif action == "delete":
                    # Check if has users before deletion
                    if org.users:
                        errors.append(f"Organization {org.name} has active users")
                    else:
                        org.is_active = False
                        success_count += 1
            except Exception as e:
                errors.append(f"Error processing organization {org.name}: {str(e)}")

        await db.commit()

        return {
            "success_count": success_count,
            "total_count": len(organization_ids),
            "errors": errors
        }

    # Helper methods

    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from organization name."""
        slug = re.sub(r'[^\w\s-]', '', name.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        return slug.strip('-')

    async def _get_by_name_or_slug(
        self,
        db: AsyncSession,
        name: str,
        slug: str
    ) -> Optional[Organization]:
        """Check if organization exists by name or slug."""
        result = await db.execute(
            select(Organization).where(
                or_(
                    Organization.name.ilike(name),
                    Organization.slug == slug
                )
            )
        )
        return result.scalar_one_or_none()

    async def _get_by_domain(self, db: AsyncSession, domain: str) -> Optional[Organization]:
        """Check if organization exists by domain."""
        result = await db.execute(
            select(Organization).where(Organization.domain.ilike(domain))
        )
        return result.scalar_one_or_none()


# Create service instance
organization_service = OrganizationService()
