"""
Organization management API endpoints for AuthX.
Provides comprehensive organization CRUD operations and management functionality with full async support.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.models.user import User
from app.services.organization_service import organization_service
from app.api.deps import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new organization with comprehensive validation."""
    logger.info(f"Creating organization: {org_data.get('name')}")

    # Only superusers can create organizations
    if not current_user.is_superuser:
        logger.warning(f"Unauthorized organization creation attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can create organizations"
        )

    try:
        organization = await organization_service.create_organization(
            db, org_data, current_user.id
        )

        logger.info(f"Organization created successfully: {organization.id}")
        return {
            "id": str(organization.id),
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
            "is_active": organization.is_active,
            "subscription_tier": organization.subscription_tier,
            "created_at": organization.created_at.isoformat() if organization.created_at else None
        }

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
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None)
):
    """List organizations with filtering and pagination."""
    logger.info(f"Listing organizations - skip: {skip}, limit: {limit}")

    # Only superusers can list all organizations
    if not current_user.is_superuser:
        logger.warning(f"Unauthorized organization list attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can list organizations"
        )

    try:
        organizations, total = await organization_service.list_organizations(
            db, skip=skip, limit=limit, search=search, is_active=is_active
        )

        logger.info(f"Retrieved {len(organizations)} organizations out of {total} total")
        return {
            "organizations": [
                {
                    "id": str(org.id),
                    "name": org.name,
                    "slug": org.slug,
                    "description": org.description,
                    "is_active": org.is_active,
                    "subscription_tier": org.subscription_tier,
                    "max_users": org.max_users,
                    "max_locations": org.max_locations,
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

@router.get("/{org_id}")
async def get_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization by ID."""
    logger.info(f"Retrieving organization: {org_id}")

    # Check access permissions
    if not current_user.is_superuser and str(current_user.organization_id) != str(org_id):
        logger.warning(f"Unauthorized organization access attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization"
        )

    try:
        organization = await organization_service.get_organization_by_id(db, org_id)
        if not organization:
            logger.warning(f"Organization not found: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization retrieved successfully: {organization.name}")
        return {
            "id": str(organization.id),
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
            "email": organization.email,
            "phone": organization.phone,
            "website": organization.website,
            "address_line1": organization.address_line1,
            "address_line2": organization.address_line2,
            "city": organization.city,
            "state": organization.state,
            "postal_code": organization.postal_code,
            "country": organization.country,
            "is_active": organization.is_active,
            "max_users": organization.max_users,
            "max_locations": organization.max_locations,
            "subscription_tier": organization.subscription_tier,
            "billing_email": organization.billing_email,
            "logo_url": organization.logo_url,
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
    org_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update organization information."""
    logger.info(f"Updating organization: {org_id}")

    # Check access permissions
    if not current_user.is_superuser and str(current_user.organization_id) != str(org_id):
        logger.warning(f"Unauthorized organization update attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this organization"
        )

    try:
        updated_org = await organization_service.update_organization(
            db, org_id, org_update, current_user.id
        )

        if not updated_org:
            logger.warning(f"Organization not found for update: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization updated successfully: {org_id}")
        return {
            "id": str(updated_org.id),
            "name": updated_org.name,
            "slug": updated_org.slug,
            "description": updated_org.description,
            "is_active": updated_org.is_active,
            "updated_at": updated_org.updated_at.isoformat() if updated_org.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update organization"
        )

@router.post("/{org_id}/activate")
async def activate_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Activate organization."""
    logger.info(f"Activating organization: {org_id}")

    if not current_user.is_superuser:
        logger.warning(f"Unauthorized organization activation attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can activate organizations"
        )

    try:
        success = await organization_service.activate_organization(db, org_id)
        if not success:
            logger.warning(f"Organization not found for activation: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization activated successfully: {org_id}")
        return {"message": "Organization activated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate organization"
        )

@router.post("/{org_id}/deactivate")
async def deactivate_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Deactivate organization."""
    logger.info(f"Deactivating organization: {org_id}")

    if not current_user.is_superuser:
        logger.warning(f"Unauthorized organization deactivation attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can deactivate organizations"
        )

    try:
        success = await organization_service.deactivate_organization(db, org_id)
        if not success:
            logger.warning(f"Organization not found for deactivation: {org_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        logger.info(f"Organization deactivated successfully: {org_id}")
        return {"message": "Organization deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate organization {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate organization"
        )

@router.delete("/{org_id}")
async def delete_organization(
    org_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete organization (soft delete)."""
    logger.info(f"Deleting organization: {org_id}")

    if not current_user.is_superuser:
        logger.warning(f"Unauthorized organization deletion attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can delete organizations"
        )

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

    # Check access permissions
    if not current_user.is_superuser and str(current_user.organization_id) != str(org_id):
        logger.warning(f"Unauthorized organization stats access attempt by {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization's stats"
        )

    try:
        stats = await organization_service.get_organization_stats(db, org_id)

        logger.info(f"Organization stats retrieved successfully: {org_id}")
        return stats

    except Exception as e:
        logger.error(f"Failed to get organization stats {org_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve organization statistics"
        )
