"""
Organization management API endpoints for AuthX.
Provides comprehensive organization CRUD operations and management functionality with full async support.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging
import math

from app.db.session import get_async_db
from app.models.user import User
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse,
    OrganizationStats,
    OrganizationSearchRequest,
    OrganizationBulkAction
)
from app.services.organization_service import organization_service
from app.api.deps import get_current_active_user, get_current_super_admin

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Create a new organization with comprehensive validation."""
    logger.info(f"Creating organization: {org_data.name} by user {current_user.id}")

    try:
        organization = await organization_service.create_organization(
            db, org_data, current_user.id
        )

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create organization"
            )

        logger.info(f"Organization created successfully: {organization.id}")

        return OrganizationResponse(
            id=str(organization.id),
            name=organization.name,
            slug=organization.slug,
            description=organization.description,
            domain=organization.domain,
            email=organization.email,
            phone=organization.phone,
            website=organization.website,
            address_line1=organization.address_line1,
            address_line2=organization.address_line2,
            city=organization.city,
            state=organization.state,
            postal_code=organization.postal_code,
            country=organization.country,
            max_users=organization.max_users,
            max_locations=organization.max_locations,
            logo_url=organization.logo_url,
            subscription_tier=organization.subscription_tier,
            billing_email=organization.billing_email,
            is_active=organization.is_active,
            created_at=organization.created_at,
            updated_at=organization.updated_at,
            user_count=0
        )

    except ValueError as e:
        logger.error(f"Validation error during organization creation: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization creation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create organization"
        )


@router.get("/", response_model=OrganizationListResponse)
async def list_organizations(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search term for name, description, or domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    subscription_tier: Optional[str] = Query(None, description="Filter by subscription tier"),
    domain: Optional[str] = Query(None, description="Filter by domain")
):
    """Get paginated list of organizations with optional filtering."""
    logger.info(f"Listing organizations: page={page}, per_page={per_page}")

    try:
        # Calculate skip from page
        skip = (page - 1) * per_page

        # Create search request if filters provided
        search_request = None
        if any([search, is_active is not None, subscription_tier, domain]):
            search_request = OrganizationSearchRequest(
                query=search,
                is_active=is_active,
                subscription_tier=subscription_tier,
                domain=domain
            )

        organizations, total = await organization_service.get_organizations(
            db, skip=skip, limit=per_page, search=search_request
        )

        # Calculate pagination info
        total_pages = (total + per_page - 1) // per_page if total > 0 else 0

        logger.info(f"Retrieved {len(organizations)} organizations out of {total} total")

        return OrganizationListResponse(
            organizations=[OrganizationResponse.model_validate(org) for org in organizations],
            total=total,
            page=page,
            per_page=per_page,
            total_pages=total_pages
        )

    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organizations"
        )


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific organization by ID with proper access control."""
    logger.info(f"Getting organization: {organization_id} for user {current_user.id}")

    try:
        organization = await organization_service.get_organization(db, organization_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check permissions - super admin or user belongs to organization
        if not current_user.is_superuser and current_user.organization_id != organization_id:
            logger.warning(f"User {current_user.id} attempted unauthorized access to org {organization_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this organization"
            )

        return OrganizationResponse.model_validate(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization"
        )


@router.get("/slug/{slug}", response_model=OrganizationResponse)
async def get_organization_by_slug(
    slug: str,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific organization by slug with proper validation."""
    logger.info(f"Getting organization by slug: {slug}")

    try:
        if not slug or len(slug.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization slug is required"
            )

        organization = await organization_service.get_organization_by_slug(db, slug.lower().strip())
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check permissions
        if not current_user.is_superuser and current_user.organization_id != organization.id:
            logger.warning(f"User {current_user.id} attempted unauthorized access to org {organization.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this organization"
            )

        return OrganizationResponse.model_validate(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization by slug: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization"
        )


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: UUID,
    org_data: OrganizationUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Update an organization with proper validation."""
    logger.info(f"Updating organization: {organization_id}")

    try:
        # First check if organization exists
        existing_org = await organization_service.get_organization(db, organization_id)
        if not existing_org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        organization = await organization_service.update_organization(
            db,
            organization_id,
            org_data
        )

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Update failed. No changes applied."
            )

        logger.info(f"Organization updated successfully: {organization.id}")
        return OrganizationResponse.model_validate(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization update failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update organization: {str(e)}"
        )


@router.delete("/{organization_id}", status_code=status.HTTP_200_OK)
async def delete_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Hard delete an organization with proper validation."""
    logger.info(f"Deleting organization: {organization_id}")

    success = await organization_service.delete_organization(db, organization_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delete operation failed"
        )

    return {"message": f"Organization {organization_id} deleted successfully"}

@router.get("/{organization_id}/stats", response_model=OrganizationStats)
async def get_organization_stats(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization statistics with proper access control."""
    logger.info(f"Getting stats for organization: {organization_id}")

    try:
        # Check permissions - super admin or user belongs to organization
        if not current_user.is_superuser and current_user.organization_id != organization_id:
            logger.warning(f"User {current_user.id} attempted unauthorized stats access to org {organization_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access organization statistics"
            )

        # Check if organization exists
        organization = await organization_service.get_organization(db, organization_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        stats = await organization_service.get_organization_stats(db, organization_id)

        if not stats:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve organization statistics"
            )

        return OrganizationStats.model_validate(stats)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization statistics"
        )


@router.post("/bulk-action", status_code=status.HTTP_200_OK)
async def bulk_organization_action(
    bulk_action: OrganizationBulkAction,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Perform bulk actions on organizations."""
    logger.info(f"Bulk action {bulk_action.action} on {len(bulk_action.organization_ids)} organizations")

    try:
        if not bulk_action.organization_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization IDs are required for bulk actions"
            )

        success_count = await organization_service.bulk_organization_action(
            db,
            bulk_action.organization_ids,
            bulk_action.action,
            current_user_id=current_user.id
        )

        logger.info(f"Bulk action completed: {success_count}/{len(bulk_action.organization_ids)} organizations processed")

        return {
            "message": f"Bulk action completed",
            "processed": success_count,
            "total": len(bulk_action.organization_ids)
        }

    except ValueError as e:
        logger.error(f"Validation error during bulk action: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Bulk action failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk action failed"
        )




# {
#   "error": "1 validation error for OrganizationResponse\nuser_count\n  Error extracting attribute: MissingGreenlet: greenlet_spawn has not been called; can't call await_only() here. Was IO attempted in an unexpected place? (Background on this error at: https://sqlalche.me/e/20/xd2s) [type=get_attribute_error, input_value=<Organization(id=3afe73e4...lug='bizclock-pvt-ltd')>, input_type=Organization]\n    For further information visit https://errors.pydantic.dev/2.11/v/get_attribute_error",
#   "status_code": 400,
#   "timestamp": 1757500384.7616715,
#   "path": "/api/v1/organizations/"
# }