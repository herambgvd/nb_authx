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

        logger.info(f"Organization created successfully: {organization.id}")
        return OrganizationResponse.from_orm(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create organization"
        )


@router.get("/", response_model=OrganizationListResponse)
async def list_organizations(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    search: Optional[str] = Query(None, description="Search term for name, description, or domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    subscription_tier: Optional[str] = Query(None, description="Filter by subscription tier"),
    domain: Optional[str] = Query(None, description="Filter by domain")
):
    """Get paginated list of organizations with optional filtering."""
    logger.info(f"Listing organizations: skip={skip}, limit={limit}")

    try:
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
            db, skip=skip, limit=limit, search=search_request
        )

        # Calculate pagination info
        total_pages = math.ceil(total / limit) if total > 0 else 0
        current_page = (skip // limit) + 1

        return OrganizationListResponse(
            organizations=[OrganizationResponse.from_orm(org) for org in organizations],
            total=total,
            page=current_page,
            per_page=limit,
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
    """Get a specific organization by ID."""
    logger.info(f"Getting organization: {organization_id}")

    organization = await organization_service.get_organization(db, organization_id)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check permissions - super admin or user belongs to organization
    if not current_user.is_superuser and current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization"
        )

    return OrganizationResponse.from_orm(organization)


@router.get("/slug/{slug}", response_model=OrganizationResponse)
async def get_organization_by_slug(
    slug: str,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific organization by slug."""
    logger.info(f"Getting organization by slug: {slug}")

    organization = await organization_service.get_organization_by_slug(db, slug)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check permissions
    if not current_user.is_superuser and current_user.organization_id != organization.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization"
        )

    return OrganizationResponse.from_orm(organization)


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: UUID,
    org_data: OrganizationUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Update an organization."""
    logger.info(f"Updating organization: {organization_id}")

    try:
        organization = await organization_service.update_organization(db, organization_id, org_data)
        logger.info(f"Organization updated successfully: {organization.id}")
        return OrganizationResponse.from_orm(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update organization"
        )


@router.delete("/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Soft delete an organization."""
    logger.info(f"Deleting organization: {organization_id}")

    try:
        await organization_service.delete_organization(db, organization_id)
        logger.info(f"Organization deleted successfully: {organization_id}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete organization"
        )


@router.get("/{organization_id}/stats", response_model=OrganizationStats)
async def get_organization_statistics(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get comprehensive statistics for an organization."""
    logger.info(f"Getting statistics for organization: {organization_id}")

    # Check permissions
    if not current_user.is_superuser and current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization's statistics"
        )

    try:
        stats = await organization_service.get_organization_stats(db, organization_id)
        return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization statistics"
        )


@router.post("/bulk-action")
async def bulk_organization_action(
    bulk_action: OrganizationBulkAction,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Perform bulk actions on multiple organizations."""
    logger.info(f"Performing bulk action '{bulk_action.action}' on {len(bulk_action.organization_ids)} organizations")

    try:
        result = await organization_service.bulk_action(
            db, bulk_action.organization_ids, bulk_action.action
        )

        logger.info(f"Bulk action completed: {result['success_count']}/{result['total_count']} successful")
        return {
            "message": f"Bulk action '{bulk_action.action}' completed",
            "success_count": result["success_count"],
            "total_count": result["total_count"],
            "errors": result["errors"]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk action failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk action"
        )


@router.post("/search", response_model=OrganizationListResponse)
async def search_organizations(
    search_request: OrganizationSearchRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
):
    """Advanced search for organizations with complex filtering."""
    logger.info(f"Advanced organization search with filters: {search_request.dict()}")

    try:
        organizations, total = await organization_service.get_organizations(
            db, skip=skip, limit=limit, search=search_request
        )

        total_pages = math.ceil(total / limit) if total > 0 else 0
        current_page = (skip // limit) + 1

        return OrganizationListResponse(
            organizations=[OrganizationResponse.from_orm(org) for org in organizations],
            total=total,
            page=current_page,
            per_page=limit,
            total_pages=total_pages
        )

    except Exception as e:
        logger.error(f"Organization search failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search organizations"
        )


@router.patch("/{organization_id}/activate", response_model=OrganizationResponse)
async def activate_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Activate an organization."""
    logger.info(f"Activating organization: {organization_id}")

    try:
        org_data = OrganizationUpdate(is_active=True)
        organization = await organization_service.update_organization(db, organization_id, org_data)
        logger.info(f"Organization activated: {organization.id}")
        return OrganizationResponse.from_orm(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization activation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate organization"
        )


@router.patch("/{organization_id}/deactivate", response_model=OrganizationResponse)
async def deactivate_organization(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Deactivate an organization."""
    logger.info(f"Deactivating organization: {organization_id}")

    try:
        org_data = OrganizationUpdate(is_active=False)
        organization = await organization_service.update_organization(db, organization_id, org_data)
        logger.info(f"Organization deactivated: {organization.id}")
        return OrganizationResponse.from_orm(organization)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization deactivation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate organization"
        )
