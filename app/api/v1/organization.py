"""
Organization API endpoints for the AuthX service.
This module provides API endpoints for organization management functionality.
"""
from typing import Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.deps import get_current_user, get_async_db, get_organization_admin, get_current_superuser
from app.models.user import User
from app.models.organization import Organization
from app.models.organization_settings import OrganizationSettings
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationUpdate,
    OrganizationResponse,
    OrganizationListResponse
)
from app.schemas.organization_settings import (
    OrganizationSettings as OrganizationSettingsSchema,
    OrganizationSettingsUpdate
)

router = APIRouter()

# Create a new organization
@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_data: OrganizationCreate
):
    """
    Create a new organization.
    This endpoint is typically used by administrators or during the signup process.
    """
    # Check if organization with the same domain already exists
    if organization_data.domain:
        result = await db.execute(
            select(Organization).where(Organization.domain == organization_data.domain)
        )
        existing_org = result.scalar_one_or_none()
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Organization with domain '{organization_data.domain}' already exists"
            )

    # Create new organization
    new_organization = Organization(**organization_data.dict())
    db.add(new_organization)
    await db.commit()
    await db.refresh(new_organization)

    # Create default organization settings
    default_settings = OrganizationSettings(organization_id=new_organization.id)
    db.add(default_settings)
    await db.commit()

    return new_organization

# Get all organizations (paginated)
@router.get("", response_model=OrganizationListResponse)
async def get_organizations(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_verified: Optional[bool] = None,
    subscription_plan: Optional[str] = None
):
    """
    Get a paginated list of organizations with optional filtering.
    Only superusers can view all organizations.
    """
    # Build query
    query = select(Organization)

    # Apply filters
    if name:
        query = query.where(Organization.name.ilike(f"%{name}%"))
    if is_active is not None:
        query = query.where(Organization.is_active == is_active)
    if is_verified is not None:
        query = query.where(Organization.is_verified == is_verified)
    if subscription_plan:
        query = query.where(Organization.subscription_plan == subscription_plan)

    # Get total count
    total_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(total_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    organizations = result.scalars().all()

    return OrganizationListResponse(
        organizations=[OrganizationResponse.from_orm(org) for org in organizations],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

# Get organization by ID
@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    organization_id: UUID
):
    """
    Get detailed information about a specific organization by ID.
    Users can only view their own organization unless they are superusers.
    """
    # Check permissions
    if not current_user.is_superadmin and current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this organization"
        )

    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    return organization

# Update organization
@router.patch("/{organization_id}", response_model=OrganizationResponse)
async def update_organization(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    organization_id: UUID,
    organization_data: OrganizationUpdate
):
    """
    Update an organization's details.
    Users can only update their own organization unless they are superadmins.
    Some fields may only be updated by superadmins.
    """
    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check permissions
    is_own_org = current_user.organization_id == organization_id
    if not current_user.is_superadmin and not is_own_org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this organization"
        )

    # Regular org admins can only update certain fields
    if not current_user.is_superadmin and is_own_org:
        restricted_fields = ["is_verified", "subscription_plan", "verification_status",
                            "data_isolation_level", "subscription_start_date", "subscription_end_date"]
        for field in restricted_fields:
            if getattr(organization_data, field, None) is not None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not authorized to update the '{field}' field"
                )

    # Check domain uniqueness if updating domain
    if organization_data.domain and organization_data.domain != organization.domain:
        result = await db.execute(
            select(Organization).where(
                Organization.domain == organization_data.domain,
                Organization.id != organization_id
            )
        )
        existing_org = result.scalar_one_or_none()
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Organization with domain '{organization_data.domain}' already exists"
            )

    # Update organization with provided data
    update_data = organization_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(organization, key, value)

    await db.commit()
    await db.refresh(organization)

    return organization

# Delete organization
@router.delete("/{organization_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_id: UUID
):
    """
    Delete an organization.
    Only superadmins can delete organizations.
    """
    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Delete organization (and all related entities through cascade)
    await db.delete(organization)
    await db.commit()

    return None

# Organization verification workflow
@router.post("/{organization_id}/verification/request", response_model=OrganizationResponse)
async def request_verification(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: UUID,
    verification_method: str = Body(..., embed=True)
):
    """
    Request organization verification.
    Organization admins can request verification for their organization.
    """
    # Check if user belongs to the organization
    if current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this organization"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Validate verification method
    valid_methods = ["domain", "document", "phone", "email"]
    if verification_method not in valid_methods:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification method. Must be one of: {', '.join(valid_methods)}"
        )

    # Update verification status and method
    organization.verification_status = "requested"
    organization.verification_method = verification_method
    await db.commit()
    await db.refresh(organization)

    # Here we would typically initiate the verification process based on the method
    # For example, sending a verification email, initiating a document review, etc.

    return organization

@router.post("/{organization_id}/verification/approve", response_model=OrganizationResponse)
async def approve_verification(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_id: UUID
):
    """
    Approve organization verification.
    Only superadmins can approve verification requests.
    """
    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Update verification status
    organization.verification_status = "approved"
    organization.is_verified = True
    organization.verification_date = datetime.now().strftime("%Y-%m-%d")
    await db.commit()
    await db.refresh(organization)

    return organization

@router.post("/{organization_id}/verification/reject", response_model=OrganizationResponse)
async def reject_verification(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_id: UUID,
    reason: str = Body(..., embed=True)
):
    """
    Reject organization verification.
    Only superadmins can reject verification requests.
    """
    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Update verification status
    organization.verification_status = "rejected"
    organization.is_verified = False
    await db.commit()
    await db.refresh(organization)

    # Here we would typically notify the organization about the rejection

    return organization

# Subscription management
@router.post("/{organization_id}/subscription", response_model=OrganizationResponse)
async def update_subscription(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_id: UUID,
    subscription_plan: str = Body(...),
    start_date: Optional[str] = Body(None),
    end_date: Optional[str] = Body(None)
):
    """
    Update an organization's subscription plan.
    Only superadmins can update subscription plans.
    """
    # Validate subscription plan
    valid_plans = ["free", "basic", "premium", "enterprise"]
    if subscription_plan not in valid_plans:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid subscription plan. Must be one of: {', '.join(valid_plans)}"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Update subscription plan and dates
    organization.subscription_plan = subscription_plan
    if start_date:
        organization.subscription_start_date = start_date
    if end_date:
        organization.subscription_end_date = end_date

    await db.commit()
    await db.refresh(organization)

    return organization

# Organization settings management
@router.get("/{organization_id}/settings", response_model=OrganizationSettingsSchema)
async def get_organization_settings(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    organization_id: UUID
):
    """
    Get an organization's settings.
    Users can only access settings for their own organization unless they are superadmins.
    """
    # Check permissions
    if not current_user.is_superadmin and current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization's settings"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Get or create settings
    settings = db.query(OrganizationSettings).filter(
        OrganizationSettings.organization_id == organization_id
    ).first()

    if not settings:
        settings = OrganizationSettings(organization_id=organization_id)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)

    # Convert database model to schema
    return OrganizationSettingsSchema(
        security=settings.security_settings,
        branding=settings.branding_settings,
        notifications=settings.notification_settings,
        integrations=settings.integration_settings,
        custom_settings=settings.custom_settings
    )

@router.patch("/{organization_id}/settings", response_model=OrganizationSettingsSchema)
async def update_organization_settings(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    organization_id: UUID,
    settings_data: OrganizationSettingsUpdate
):
    """
    Update an organization's settings.
    Users can only update settings for their own organization unless they are superadmins.
    """
    # Check permissions
    if not current_user.is_superadmin and current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this organization's settings"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Get or create settings
    settings = db.query(OrganizationSettings).filter(
        OrganizationSettings.organization_id == organization_id
    ).first()

    if not settings:
        settings = OrganizationSettings(organization_id=organization_id)
        db.add(settings)

    # Update settings with provided data
    update_data = settings_data.dict(exclude_unset=True)

    if "security" in update_data and update_data["security"]:
        if not settings.security_settings:
            settings.security_settings = {}
        settings.security_settings.update(update_data["security"].dict(exclude_unset=True))

    if "branding" in update_data and update_data["branding"]:
        if not settings.branding_settings:
            settings.branding_settings = {}
        settings.branding_settings.update(update_data["branding"].dict(exclude_unset=True))

    if "notifications" in update_data and update_data["notifications"]:
        if not settings.notification_settings:
            settings.notification_settings = {}
        settings.notification_settings.update(update_data["notifications"].dict(exclude_unset=True))

    if "integrations" in update_data and update_data["integrations"]:
        if not settings.integration_settings:
            settings.integration_settings = {}
        settings.integration_settings.update(update_data["integrations"].dict(exclude_unset=True))

    if "custom_settings" in update_data and update_data["custom_settings"]:
        if not settings.custom_settings:
            settings.custom_settings = {}
        settings.custom_settings.update(update_data["custom_settings"])

    await db.commit()
    await db.refresh(settings)

    # Convert database model to schema
    return OrganizationSettingsSchema(
        security=settings.security_settings,
        branding=settings.branding_settings,
        notifications=settings.notification_settings,
        integrations=settings.integration_settings,
        custom_settings=settings.custom_settings
    )

# Data isolation level management
@router.post("/{organization_id}/data-isolation", response_model=OrganizationResponse)
async def update_data_isolation(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    organization_id: UUID,
    isolation_level: str = Body(..., embed=True)
):
    """
    Update an organization's data isolation level.
    Only superadmins can update data isolation levels.
    """
    # Validate isolation level
    valid_levels = ["strict", "shared", "hybrid"]
    if isolation_level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid isolation level. Must be one of: {', '.join(valid_levels)}"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Update isolation level
    organization.data_isolation_level = isolation_level
    await db.commit()
    await db.refresh(organization)

    return organization
