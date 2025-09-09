"""
Admin Management API endpoints for AuthX.
Handles super admin and organization admin operations.
"""
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_current_super_admin, get_current_organization_admin
from app.db.session import get_async_db
from app.models.user import User
from app.schemas.admin_management import (
    AdminResponse,
    AdminListResponse,
    CreateSuperAdminRequest,
    CreateOrganizationAdminRequest,
    OnboardOrganizationRequest,
    AdminUpdate
)
from app.services.admin_management_service import admin_management_service

router = APIRouter()


@router.post("/bootstrap-super-admin", response_model=AdminResponse)
async def bootstrap_super_admin(
    request: CreateSuperAdminRequest,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Bootstrap the first super admin in the system.
    Only works when no super admins exist in the system.
    """
    # Check if any super admins already exist
    existing_super_admins = await admin_management_service.get_all_super_admins(db)

    if existing_super_admins:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Super admin already exists. Use the regular super admin creation endpoint."
        )

    user, admin = await admin_management_service.create_super_admin(
        db, request, None  # No creator for bootstrap admin
    )

    # Convert User object to dictionary for proper validation
    user_dict = {
        "id": str(user.id),
        "email": user.email,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "is_superuser": user.is_superuser,
        "organization_id": str(user.organization_id) if user.organization_id else None
    }

    # Create response data
    response_data = {
        "id": admin.id,
        "user_id": admin.user_id,
        "admin_level": admin.admin_level,
        "permissions": admin.permissions,
        "is_active": admin.is_active,
        "organization_id": admin.organization_id,
        "created_by": admin.created_by,
        "last_login": admin.last_login,
        "created_at": admin.created_at,
        "updated_at": admin.updated_at,
        "user": user_dict
    }

    return AdminResponse(**response_data)


@router.post("/super-admin", response_model=AdminResponse)
async def create_super_admin(
    request: CreateSuperAdminRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Create a new super admin.
    Only accessible by existing super admins.
    """
    user, admin = await admin_management_service.create_super_admin(
        db, request, current_user.id
    )
    return AdminResponse.model_validate(admin)


@router.post("/onboard-organization", response_model=dict)
async def onboard_organization(
    request: OnboardOrganizationRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Onboard a new organization with its admin.
    Only accessible by super admins.
    """
    org, admin_user, admin, license = await admin_management_service.onboard_organization_with_admin(
        db, request, current_user.id
    )

    return {
        "organization": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug
        },
        "admin": {
            "id": admin.id,
            "user_id": admin_user.id,
            "email": admin_user.email,
            "full_name": admin_user.full_name
        },
        "license": {
            "license_key": license.license_key,
            "valid_until": license.valid_until
        }
    }


@router.post("/organization-admin", response_model=AdminResponse)
async def create_organization_admin(
    request: CreateOrganizationAdminRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Create a new organization admin for an existing organization.
    Only accessible by super admins.
    """
    user, admin = await admin_management_service.create_organization_admin(
        db, request, current_user.id
    )
    return AdminResponse.model_validate(admin)


@router.get("/organization/{organization_id}/admins", response_model=AdminListResponse)
async def get_organization_admins(
    organization_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all admins for an organization.
    Accessible by super admins and organization admins of the same organization.
    """
    # Check permissions
    admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access admin information"
        )

    if not admin.is_super_admin and admin.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization's admins"
        )

    admins = await admin_management_service.get_organization_admins(db, organization_id)

    return AdminListResponse(
        items=[AdminResponse.model_validate(admin) for admin in admins],
        total=len(admins)
    )


@router.get("/super-admins", response_model=AdminListResponse)
async def get_super_admins(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Get all super admins.
    Only accessible by super admins.
    """
    admins = await admin_management_service.get_all_super_admins(db)

    return AdminListResponse(
        items=[AdminResponse.model_validate(admin) for admin in admins],
        total=len(admins)
    )


@router.put("/admin/{admin_id}", response_model=AdminResponse)
async def update_admin(
    admin_id: UUID,
    update_data: AdminUpdate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Update admin record.
    Only accessible by super admins.
    """
    admin = await admin_management_service.update_admin(db, admin_id, update_data)
    return AdminResponse.model_validate(admin)


@router.delete("/admin/{admin_id}")
async def deactivate_admin(
    admin_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    Deactivate admin record.
    Only accessible by super admins.
    """
    await admin_management_service.deactivate_admin(db, admin_id)
    return {"message": "Admin deactivated successfully"}


@router.get("/me", response_model=AdminResponse)
async def get_current_admin_info(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's admin information.
    """
    admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin record not found"
        )

    return AdminResponse.model_validate(admin)
