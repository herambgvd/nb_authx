"""
Organization management API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from app.database import get_async_session
from app.schemas import (
    OrganizationCreate, OrganizationUpdate, OrganizationResponse,
    MessageResponse
)
from app.services.organization_service import OrganizationService
from app.dependencies import get_current_super_admin, get_current_org_user, get_current_user
from app.models import User
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_data: OrganizationCreate,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_session)
):
    """Create a new organization (Super Admin only)"""
    org_service = OrganizationService(db)

    try:
        organization = await org_service.create_organization(org_data, current_user.id)
        return OrganizationResponse.model_validate(organization)
    except Exception as e:
        logger.error(f"Organization creation failed: {e}")
        raise


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search by name or slug"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    List organizations with proper admin separation:
    - Super Admin (Overall Admin): Can see all organizations for onboarding management
    - Organization Admin/User: Can only see their own organization
    """
    org_service = OrganizationService(db)

    # Super admin can see all organizations (for organization onboarding management)
    if current_user.is_super_admin:
        organizations, total = await org_service.list_organizations(
            page=page, size=size, search=search, is_active=is_active, include_locations=True
        )
        return organizations
    
    # Organization users (including org admins) can only see their own organization
    elif current_user.organization_id:
        organizations, total = await org_service.list_user_organizations(
            user_org_id=current_user.organization_id, page=page, size=size
        )
        return organizations
    
    # Users without organization cannot see any organizations
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. User must be a super admin or belong to an organization."
        )


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get organization by ID with proper admin separation:
    - Super Admin: Can access any organization for onboarding management
    - Organization Admin/User: Can only access their own organization
    """
    org_service = OrganizationService(db)

    organization = await org_service.get_organization_for_user(
        org_id=organization_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin,
        is_org_admin=current_user.is_org_admin
    )
    
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found or access denied"
        )

    return organization


@router.get("/slug/{slug}", response_model=OrganizationResponse)
async def get_organization_by_slug(
    slug: str,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_session)
):
    """Get organization by slug (Super Admin only)"""
    org_service = OrganizationService(db)

    organization = await org_service.get_organization_by_slug(slug)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return organization


@router.put("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    organization_id: str,
    org_data: OrganizationUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Update organization with access control:
    - Super Admin: Can update any organization
    - Organization Admin: Can only update their own organization
    """
    org_service = OrganizationService(db)

    # Check access permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id or current_user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only update your own organization."
            )

    organization = await org_service.update_organization(organization_id, org_data, current_user.id)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return organization


@router.delete("/{organization_id}", response_model=MessageResponse)
async def delete_organization(
    organization_id: str,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_session)
):
    """Delete organization (Super Admin only)"""
    org_service = OrganizationService(db)

    success = await org_service.delete_organization(organization_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return MessageResponse(message="Organization deleted successfully")


@router.get("/{org_id}/stats")
async def get_organization_stats(
    org_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get organization statistics with access control:
    - Super Admin: Can access any organization stats
    - Organization User: Can only access their own organization stats
    """
    org_service = OrganizationService(db)

    # Check access permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id or current_user.organization_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only view your own organization stats."
            )

    try:
        stats = await org_service.get_organization_stats(org_id)
        return stats
    except Exception as e:
        logger.error(f"Organization stats failed: {e}")
        raise


@router.get("/my/info", response_model=OrganizationResponse)
async def get_my_organization(
    current_user_org: tuple[User, object] = Depends(get_current_org_user),
    db: AsyncSession = Depends(get_async_session)
):
    """Get current user's organization information with locations"""
    current_user, organization = current_user_org
    org_service = OrganizationService(db)

    # Get the organization with locations loaded
    org_with_locations = await org_service.get_organization_for_user(
        org_id=organization.id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not org_with_locations:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return OrganizationResponse.model_validate(org_with_locations)
