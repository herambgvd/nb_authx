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

    async def get_organization(self, db: AsyncSession, org_id: UUID) -> Optional[dict]:
        """Fetch organization with user count precomputed."""
        result = await db.execute(
            select(Organization).where(Organization.id == org_id)
        )
        organization = result.scalar_one_or_none()

        if not organization:
            return None

        # ✅ Count users explicitly
        user_count_result = await db.execute(
            select(func.count(User.id)).where(User.organization_id == org_id)
        )
        user_count = user_count_result.scalar() or 0

        # ✅ Return dict instead of raw ORM
        return {
            **organization.__dict__,
            "user_count": user_count
        }


    async def get_organization_by_slug(self, db: AsyncSession, slug: str) -> Optional[Organization]:
        """Fetch organization by slug (case-insensitive, exact match)."""
        if not slug:
            return None

        normalized_slug = slug.strip().lower()

        try:
            result = await db.execute(
                select(Organization).where(func.lower(Organization.slug) == normalized_slug)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"DB error while fetching organization by slug={normalized_slug}: {e}", exc_info=True)
            return None
    

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
    
        # If name is being updated, regenerate slug
        if org_data.name and org_data.name.strip() != organization.name:
            new_slug = self._generate_slug(org_data.name)
    
            # Ensure unique slug
            existing_org = await self.get_organization_by_slug(db, new_slug)
            counter = 1
            while existing_org and existing_org.id != org_id:
                new_slug = f"{new_slug}-{counter}"
                existing_org = await self.get_organization_by_slug(db, new_slug)
                counter += 1
    
            organization.slug = new_slug
    
        # Update other fields
        update_data = org_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(organization, field) and value is not None:
                setattr(organization, field, value)
    
        await db.commit()
        await db.refresh(organization)
        return organization

    async def delete_organization(self, db: AsyncSession, org_id: UUID) -> bool:
        """Hard delete organization from the database."""

        organization = await self.get_organization(db, org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Optionally, check if organization has users before deleting
        if organization.users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete organization with active users. Transfer or deactivate users first."
            )

        # Hard delete
        await db.delete(organization)
        await db.commit()

        logger.info(f"Organization permanently deleted: {organization.id} - {organization.name}")
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

    async def bulk_organization_action(
        self,
        db: AsyncSession,
        organization_ids: List[UUID],
        action: str,
        current_user_id: UUID
    ) -> int:
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

        for org in organizations:
            try:
                if action == "activate":
                    org.is_active = True
                    success_count += 1
                elif action == "deactivate":
                    org.is_active = False
                    success_count += 1
                elif action == "delete":
                    # Soft delete only if no users
                    if hasattr(org, "users") and org.users:
                        logger.warning(f"Org {org.id} not deleted - has users")
                    else:
                        org.is_active = False
                        success_count += 1
                else:
                    raise ValueError(f"Unsupported action: {action}")
    
            except Exception as e:
                logger.error(f"Error processing organization {org.id}: {e}")

        await db.commit()

        logger.info(
        f"Bulk action '{action}' by user {current_user_id}: "
            f"{success_count}/{len(organization_ids)} organizations updated"
        )
        return success_count

    # Helper methods

    def _generate_slug(self, name: str) -> str:
        """Generate a clean, lowercase, URL-friendly slug from organization name."""
        if not name:
            return ""
        slug = name.lower().strip()
        slug = re.sub(r"[^\w\s-]", "", slug)   # remove special chars
        slug = re.sub(r"[-\s]+", "-", slug)    # replace spaces & dashes with single dash
        return slug.strip("-")


    async def _get_by_name_or_slug(self, db: AsyncSession, name: str, slug: str) -> Optional[Organization]:
        """Check if organization exists by name or slug (case-insensitive)."""
        result = await db.execute(
            select(Organization).where(
                or_(
                    Organization.name.ilike(name),
                    func.lower(Organization.slug) == slug.lower()
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
