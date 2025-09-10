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
    OrganizationStats,
    OrganizationResponse,
)

logger = logging.getLogger(__name__)


class OrganizationService:
    """Service class for organization management operations."""

    async def create_organization(
        self,
        db: AsyncSession,
# <<<<<<< HEAD
        org_data: OrganizationCreate,
        creator_id: UUID
    ) -> Organization:
        """Create a new organization with validation."""
# =======
#         org_data: Dict[str, Any],
#         created_by: Optional[UUID] = None
#     ) -> OrganizationResponse:
#         """Create a new organization with comprehensive validation."""
#         logger.info(f"Creating organization: {org_data.get('name')}")

#         # Validate subscription tier
#         subscription_tier = org_data.get('subscription_tier', 'free')
#         if subscription_tier not in self.supported_subscription_tiers:
#             logger.warning(f"Invalid subscription tier: {subscription_tier}")
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail=f"Invalid subscription tier. Supported tiers: {', '.join(self.supported_subscription_tiers)}"
#             )
# >>>>>>> updation

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
# <<<<<<< HEAD
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
# =======
#             description=org_data.get('description'),
#             subscription_tier=subscription_tier,
#             max_users=org_data.get('max_users'),
#             max_locations=org_data.get('max_locations'),
#             email=org_data.get('email'),
#             phone=org_data.get('phone'),
#             website=org_data.get('website'),
#             logo_url=org_data.get('logo_url'),
#             address_line1=org_data.get('address_line1'),
#             address_line2=org_data.get('address_line2'),
#             city=org_data.get('city'),
#             state=org_data.get('state'),
#             postal_code=org_data.get('postal_code'),
#             country=org_data.get('country'),
#             billing_email=org_data.get('billing_email'),
# >>>>>>> updation
        )

        db.add(organization)
        await db.commit()
        await db.refresh(organization)

# <<<<<<< HEAD
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
# =======
#         # Create default organization settings
#         await self._create_default_settings(db, organization.id)

#         # Create default roles for the organization
#         await self._create_default_roles(db, organization.id)
#         user_count = await db.scalar(
#             select(func.count(User.id)).where(User.organization_id == organization.id)
#         )

#         logger.info(f"Organization created successfully: {organization.id}")
#         return OrganizationResponse(
#             id=organization.id,
#             name=organization.name,
#             slug=organization.slug,
#             description=organization.description,
#             email=organization.email,
#             phone=organization.phone,
#             website=organization.website,
#             address_line1=organization.address_line1,
#             address_line2=organization.address_line2,
#             city=organization.city,
#             state=organization.state,
#             postal_code=organization.postal_code,
#             country=organization.country,
#             is_active=organization.is_active,
#             max_users=organization.max_users,
#             max_locations=organization.max_locations,
#             logo_url=organization.logo_url,
#             subscription_tier=organization.subscription_tier,
#             billing_email=organization.billing_email,
#             created_at=organization.created_at,
#             updated_at=organization.updated_at,
#             user_count=user_count
#         )


#     async def get_organization_by_id(
#         self, db: AsyncSession, org_id: UUID
#     ) -> Optional[OrganizationResponse]:
#         """Get organization by ID with all relationships loaded safely."""
#         logger.debug(f"Fetching organization by ID: {org_id}")
    
#         result = await db.execute(select(Organization).where(Organization.id == org_id))
#         organization = result.scalar_one_or_none()
    
#         if not organization:
#             logger.debug(f"Organization not found with ID: {org_id}")
#             return None
    
#         # ✅ Explicit user count
#         user_count = await db.scalar(
#         select(func.count(User.id)).where(User.organization_id == organization.id)
#     )
    
#         return OrganizationResponse(
#             id=organization.id,
#             name=organization.name,
#             slug=organization.slug,
#             description=organization.description,
#             email=organization.email,
#             phone=organization.phone,
#             website=organization.website,
#             address_line1=organization.address_line1,
#             address_line2=organization.address_line2,
#             city=organization.city,
#             state=organization.state,
#             postal_code=organization.postal_code,
#             country=organization.country,
#             is_active=organization.is_active,
#             max_users=organization.max_users,
#             max_locations=organization.max_locations,
#             logo_url=organization.logo_url,
#             subscription_tier=organization.subscription_tier,
#             billing_email=organization.billing_email,
#             created_at=organization.created_at,
#             updated_at=organization.updated_at,
#             user_count=user_count,
#         )
# >>>>>>> updation

    async def get_organization_by_slug(self, db: AsyncSession, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        result = await db.execute(
            select(Organization).where(Organization.slug == slug)
        )
        return result.scalar_one_or_none()

# <<<<<<< HEAD
    async def get_organizations(
# =======
#     async def update_organization(
#         self,
#         db: AsyncSession,
#         org_id: UUID,
#         org_update: Dict[str, Any],
#         updated_by: Optional[UUID] = None
#     ) -> Optional[Organization]:
#         """Update organization with validation."""
#         logger.info(f"Updating organization: {org_id}")

#         # Get existing organization
#         organization = await self.get_organization_by_id(db, org_id)
#         if not organization:
#             logger.warning(f"Organization not found for update: {org_id}")
#             return None

#         # Validate subscription tier if being updated
#         subscription_tier = org_update.get('subscription_tier')
#         if subscription_tier and subscription_tier not in self.supported_subscription_tiers:
#             logger.warning(f"Invalid subscription tier: {subscription_tier}")
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail=f"Invalid subscription tier. Supported tiers: {', '.join(self.supported_subscription_tiers)}"
#             )

#         # Update allowed fields
#         allowed_fields = {
#             "name", "description", "subscription_tier", "max_users", "max_locations",
#             "email", "phone", "website", "logo_url", "address_line1", "address_line2",
#             "city", "state", "postal_code", "country", "billing_email", "is_active"
#         }

#         # Update slug if name is being changed
#         if 'name' in org_update and org_update['name'] != organization.name:
#             new_slug = self._generate_slug(org_update['name'])
#             existing_org = await self.get_organization_by_slug(db, new_slug)
#             if existing_org and existing_org.id != org_id:
#                 # Make slug unique
#                 counter = 1
#                 while existing_org:
#                     new_slug = f"{self._generate_slug(org_update['name'])}-{counter}"
#                     existing_org = await self.get_organization_by_slug(db, new_slug)
#                     counter += 1
#             organization.slug = new_slug

#         for field, value in org_update.items():
#             if field in allowed_fields and hasattr(organization, field):
#                 setattr(organization, field, value)
#                 logger.debug(f"Updated {field} for organization {org_id}")

#         organization.updated_at = datetime.utcnow()
#         await db.commit()
#         await db.refresh(organization)

#         logger.info(f"Organization updated successfully: {org_id}")
#         return organization

#     async def delete_organization(self, db: AsyncSession, org_id: UUID) -> bool:
#         """Delete organization with validation."""
#         logger.info(f"Deleting organization: {org_id}")

#         organization = await self.get_organization_by_id(db, org_id)
#         if not organization:
#             logger.warning(f"Organization not found for deletion: {org_id}")
#             return False

#         # Check if organization has active users
#         result = await db.execute(
#             select(func.count(User.id))
#             .where(and_(User.organization_id == org_id, User.is_active == True))
#         )
#         active_user_count = result.scalar()

#         if active_user_count > 0:
#             logger.warning(f"Cannot delete organization with active users: {active_user_count}")
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Cannot delete organization that has active users"
#             )

#         await db.execute(delete(Organization).where(Organization.id == org_id))
#         await db.commit()

#         logger.info(f"Organization deleted successfully: {org_id}")
#         return True

#     async def list_organizations(
# >>>>>>> updation
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

# <<<<<<< HEAD
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
# =======
#         return {
#             "total_users": total_users,
#             "active_users": active_users,
#             "total_locations": total_locations,
#             "total_roles": total_roles
#         }

#     async def _create_default_settings(self, db: AsyncSession, org_id: UUID):
#         """Create default organization settings."""
#         logger.debug(f"Creating default settings for organization: {org_id}")

#         settings = OrganizationSettings(
#             organization_id=org_id,
#             security_settings={
#                 "password_min_length": 8,
#                 "password_require_uppercase": True,
#                 "password_require_lowercase": True,
#                 "password_require_number": True,
#                 "password_require_special": True,
#                 "password_expiry_days": 90,
#                 "login_attempt_limit": 5,
#                 "mfa_required": False,
#                 "allowed_ip_ranges": [],
#                 "session_timeout_minutes": 60
#             },
#             branding_settings={
#                 "logo_url": None,
#                 "favicon_url": None,
#                 "primary_color": "#000000",
#                 "secondary_color": "#FFFFFF",
#                 "login_page_message": None,
#                 "custom_css": None
#             },
#             notification_settings={
#                 "email_notifications_enabled": True,
#                 "security_alert_contacts": [],
#                 "admin_alert_contacts": []
#             },
#             integration_settings={
#                 "sso_enabled": False,
#                 "sso_provider": None,
#                 "sso_config": {},
#                 "webhook_endpoints": [],
#                 "api_keys_enabled": False
#             },
#             feature_flags={
#                 "multi_factor_auth": False,
#                 "audit_logging": True,
#                 "api_access": True
#             },
#             custom_settings={}
#         )

#         db.add(settings)
#         await db.commit()
#         await db.refresh(settings)
    
#         logger.info(f"Default organization settings created for org {org_id}")
#         return settings
# >>>>>>> updation

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
