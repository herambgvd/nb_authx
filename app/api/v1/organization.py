"""
Organization management API endpoints for AuthX.
Provides comprehensive organization CRUD operations and management functionality with full async support.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationUpdate, OrganizationResponse
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
    logger.info(f"Creating organization: {org_data.name}")

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

@router.get("/")
async def list_organizations(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    subscription_tier: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None)
):
    """List organizations with filtering and pagination (superuser only)."""
    logger.info(f"Listing organizations - skip: {skip}, limit: {limit}")

    try:
        organizations, total = await organization_service.list_organizations(
            db, skip=skip, limit=limit, search=search,
            subscription_tier=subscription_tier, is_active=is_active
        )

        logger.info(f"Retrieved {len(organizations)} organizations out of {total} total")
        return {
            "organizations": [
                {
                    "id": str(org.id),
                    "name": org.name,
                    "slug": org.slug,
                    "description": org.description,
                    "subscription_tier": org.subscription_tier,
                    "max_users": org.max_users,
                    "contact_email": org.contact_email,
                    "is_active": org.is_active,
                    "created_at": org.created_at.isoformat() if org.created_at else None
                }
                for org in organizations
            ],
            "total": total,
            "skip": skip,
            "limit": limit
        }

    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organizations"
        )

@router.get("/current")
async def get_current_organization(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get current user's organization."""
    logger.info(f"Getting current organization for user: {current_user.id}")

    try:
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User is not associated with any organization"
            )

        organization = await organization_service.get_organization_by_id(
            db, current_user.organization_id
        )

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Current organization retrieved: {organization.name}")
        return {
            "id": str(organization.id),
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
            "subscription_tier": organization.subscription_tier,
            "max_users": organization.max_users,
            "contact_email": organization.contact_email,
            "contact_phone": organization.contact_phone,
            "website": organization.website,
            "industry": organization.industry,
            "timezone": organization.timezone,
            "is_active": organization.is_active,
            "created_at": organization.created_at.isoformat() if organization.created_at else None,
            "updated_at": organization.updated_at.isoformat() if organization.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve current organization: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization"
        )

@router.get("/current/stats")
async def get_current_organization_stats(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get current organization statistics."""
    logger.info(f"Getting organization stats for user: {current_user.id}")

    try:
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User is not associated with any organization"
            )

        stats = await organization_service.get_organization_stats(
            db, current_user.organization_id
        )

        return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve organization stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization statistics"
        )

@router.get("/{org_id}")
async def get_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization by ID."""
    logger.info(f"Retrieving organization: {org_id}")

    try:
        organization = await organization_service.get_organization_by_id(db, org_id)
        if not organization:
            logger.warning(f"Organization not found: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if user can access this organization
        if (not current_user.is_superuser and
            str(org_id) != str(current_user.organization_id)):
            logger.warning(f"Unauthorized organization access attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this organization"
            )

        logger.info(f"Organization retrieved successfully: {organization.name}")
        return {
            "id": str(organization.id),
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
            "subscription_tier": organization.subscription_tier,
            "max_users": organization.max_users,
            "contact_email": organization.contact_email,
            "contact_phone": organization.contact_phone,
            "website": organization.website,
            "industry": organization.industry,
            "timezone": organization.timezone,
            "is_active": organization.is_active,
            "created_at": organization.created_at.isoformat() if organization.created_at else None,
            "updated_at": organization.updated_at.isoformat() if organization.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization"
        )

@router.put("/{org_id}")
async def update_organization(
    org_id: UUID,
    org_update: OrganizationUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update organization information."""
    logger.info(f"Updating organization: {org_id}")

    # Check permissions - only super admins or organization admins can update
    if not current_user.is_superuser:
        if str(org_id) != str(current_user.organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this organization"
            )

        # Check if user has organization admin permission
        from app.services.role_service import role_service
        has_permission = await role_service.check_permission(
            db, current_user.id, 'organization', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized organization update attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update organization"
            )

    try:
        updated_organization = await organization_service.update_organization(
            db, org_id, org_update, current_user.id
        )

        if not updated_organization:
            logger.warning(f"Organization not found for update: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization updated successfully: {org_id}")
        return {
            "id": str(updated_organization.id),
            "name": updated_organization.name,
            "slug": updated_organization.slug,
            "description": updated_organization.description,
            "subscription_tier": updated_organization.subscription_tier,
            "max_users": updated_organization.max_users,
            "contact_email": updated_organization.contact_email,
            "contact_phone": updated_organization.contact_phone,
            "website": updated_organization.website,
            "industry": updated_organization.industry,
            "timezone": updated_organization.timezone,
            "is_active": updated_organization.is_active,
            "updated_at": updated_organization.updated_at.isoformat() if updated_organization.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update organization"
        )

@router.delete("/{org_id}")
async def delete_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """Delete organization (superuser only)."""
    logger.info(f"Deleting organization: {org_id}")

    try:
        success = await organization_service.delete_organization(db, org_id)
        if not success:
            logger.warning(f"Organization not found for deletion: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization deleted successfully: {org_id}")
        return {"message": "Organization deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete organization"
        )

@router.get("/{org_id}/stats")
async def get_organization_stats(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization statistics."""
    logger.info(f"Getting stats for organization: {org_id}")

    # Check permissions
    if (not current_user.is_superuser and
        str(org_id) != str(current_user.organization_id)):
        logger.warning(f"Unauthorized organization stats access attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this organization's statistics"
        )

    try:
        stats = await organization_service.get_organization_stats(db, org_id)
        return stats

    except Exception as e:
        logger.error(f"Failed to retrieve organization stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization statistics"
        )
