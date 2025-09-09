"""
User Location Access API endpoints for AuthX.
Manages user access to locations within organizations.
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_current_organization_admin
from app.db.session import get_async_db
from app.models.user import User
from app.schemas.user_location_access import (
    UserLocationAccessResponse,
    UserLocationAccessListResponse,
    GrantLocationAccessRequest,
    RevokeLocationAccessRequest
)
from app.services.user_location_access_service import user_location_access_service
from app.services.admin_management_service import admin_management_service

router = APIRouter()


@router.post("/grant-access")
async def grant_location_access(
    request: GrantLocationAccessRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Grant location access to users.
    Only accessible by organization admins.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    # Verify admin permissions
    has_permission = await admin_management_service.verify_admin_permissions(
        db, current_user.id, "manage_access", current_user.organization_id
    )
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access"
        )

    accesses = await user_location_access_service.grant_location_access(
        db, request, current_user.id, current_user.organization_id
    )

    return {
        "message": f"Access granted to {len(request.user_ids)} users for {len(request.location_ids)} locations",
        "total_grants": len(accesses)
    }


@router.post("/revoke-access")
async def revoke_location_access(
    request: RevokeLocationAccessRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Revoke location access from users.
    Only accessible by organization admins.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    # Verify admin permissions
    has_permission = await admin_management_service.verify_admin_permissions(
        db, current_user.id, "manage_access", current_user.organization_id
    )
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access"
        )

    revoked_count = await user_location_access_service.revoke_location_access(
        db, request, current_user.id, current_user.organization_id
    )

    return {
        "message": f"Access revoked for {revoked_count} user-location combinations"
    }


@router.get("/user/{user_id}/locations", response_model=UserLocationAccessListResponse)
async def get_user_location_accesses(
    user_id: UUID,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Get all location accesses for a specific user.
    Only accessible by organization admins within the same organization.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    accesses = await user_location_access_service.get_user_location_accesses(
        db, user_id, current_user.organization_id, include_expired
    )

    return UserLocationAccessListResponse(
        items=[UserLocationAccessResponse.model_validate(access) for access in accesses],
        total=len(accesses)
    )


@router.get("/location/{location_id}/users", response_model=UserLocationAccessListResponse)
async def get_location_user_accesses(
    location_id: UUID,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Get all user accesses for a specific location.
    Only accessible by organization admins within the same organization.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    accesses = await user_location_access_service.get_location_user_accesses(
        db, location_id, current_user.organization_id, include_expired
    )

    return UserLocationAccessListResponse(
        items=[UserLocationAccessResponse.model_validate(access) for access in accesses],
        total=len(accesses)
    )


@router.get("/user/{user_id}/accessible-locations")
async def get_user_accessible_locations(
    user_id: UUID,
    permission: str = Query("read", description="Permission level: read, write, delete, manage"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all locations that a user has access to.
    Users can access their own accessible locations, admins can access any user's in their org.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    # Check if user is requesting their own data or is an admin
    if user_id != current_user.id:
        admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
        if not admin or (admin.is_organization_admin and admin.organization_id != current_user.organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this user's location data"
            )

    locations = await user_location_access_service.get_accessible_locations_for_user(
        db, user_id, current_user.organization_id, permission
    )

    return {
        "user_id": user_id,
        "permission": permission,
        "accessible_locations": [
            {
                "id": loc.id,
                "name": loc.name,
                "location_type": loc.location_type,
                "code": loc.code,
                "is_active": loc.is_active
            }
            for loc in locations
        ],
        "total": len(locations)
    }


@router.get("/check-access/{user_id}/{location_id}")
async def check_user_location_access(
    user_id: UUID,
    location_id: UUID,
    permission: str = Query("read", description="Permission level: read, write, delete, manage"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Check if a user has specific permission for a location.
    Users can check their own access, admins can check any user's access in their org.
    """
    if not current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization"
        )

    # Check if user is requesting their own data or is an admin
    if user_id != current_user.id:
        admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
        if not admin or (admin.is_organization_admin and admin.organization_id != current_user.organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to check this user's access"
            )

    has_access = await user_location_access_service.check_user_location_access(
        db, user_id, location_id, current_user.organization_id, permission
    )

    return {
        "user_id": user_id,
        "location_id": location_id,
        "permission": permission,
        "has_access": has_access
    }
