"""
Location management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from app.database import get_async_session
from app.dependencies import get_current_user, get_current_super_admin
from app.models import User
from app.schemas import (
    LocationCreate, LocationUpdate, LocationResponse, LocationAssignRequest,
    LocationAssignResponse, UserLocationResponse, PaginatedResponse, MessageResponse
)
from app.services.location_service import LocationService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/locations", tags=["Locations"])


@router.post("", response_model=LocationResponse, status_code=status.HTTP_201_CREATED)
async def create_location(
    location_data: LocationCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Create a new location with access control:
    - Super Admin: Can create locations in any organization
    - Organization Admin: Can create locations in their organization only
    """
    location_service = LocationService(db)

    # Check permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership required to create locations"
            )
        organization_id = current_user.organization_id
    else:
        # Super admin can specify organization or default to their own
        organization_id = location_data.organization_id or current_user.organization_id

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is required"
        )

    location = await location_service.create_location(location_data, organization_id, current_user.id)
    return location


@router.get("", response_model=PaginatedResponse[LocationResponse])
async def list_locations(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    search: Optional[str] = Query(None, description="Search by name, code, or description"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    List locations with access control:
    - Super Admin: Can see all locations across organizations
    - Organization User: Can only see locations in their organization
    """
    location_service = LocationService(db)

    locations, total = await location_service.list_locations_with_access_control(
        page=page,
        size=size,
        is_active=is_active,
        search=search,
        organization_id=organization_id if current_user.is_super_admin else None,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    return PaginatedResponse(
        items=locations,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/{location_id}", response_model=LocationResponse)
async def get_location(
    location_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get location by ID with access control:
    - Super Admin: Can access any location
    - Organization User: Can only access locations in their organization
    """
    location_service = LocationService(db)

    location = await location_service.get_location_with_access_control(
        location_id=location_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found or access denied"
        )

    return location


@router.put("/{location_id}", response_model=LocationResponse)
async def update_location(
    location_id: str,
    location_data: LocationUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Update location with access control:
    - Super Admin: Can update any location
    - Organization Admin: Can update locations in their organization
    """
    location_service = LocationService(db)

    # Check if user can manage the location
    can_manage = await location_service.can_user_manage_location(
        location_id=location_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only update locations in your organization."
        )

    # Get the location to determine organization_id
    location = await location_service.get_location_by_id(location_id)
    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    updated_location = await location_service.update_location(
        location_id=location_id,
        location_data=location_data,
        organization_id=location.organization_id
    )

    if not updated_location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    return updated_location


@router.delete("/{location_id}", response_model=MessageResponse)
async def delete_location(
    location_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Delete location with access control:
    - Super Admin: Can delete any location
    - Organization Admin: Can delete locations in their organization
    """
    location_service = LocationService(db)

    # Check if user can manage the location
    can_manage = await location_service.can_user_manage_location(
        location_id=location_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not can_manage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only delete locations in your organization."
        )

    # Get the location to determine organization_id
    location = await location_service.get_location_by_id(location_id)
    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    success = await location_service.delete_location(
        location_id=location_id,
        organization_id=location.organization_id
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    return MessageResponse(message="Location deleted successfully")


@router.post("/assign", response_model=LocationAssignResponse)
async def assign_locations_to_user(
    assign_data: LocationAssignRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Assign locations to user with access control:
    - Super Admin: Can assign any locations to any user
    - Organization Admin: Can assign locations in their organization to users in their organization
    """
    location_service = LocationService(db)

    # Determine organization context
    if current_user.is_super_admin:
        # Super admin needs to work within a specific organization context
        # We'll use the user's organization from the assign_data
        from app.services.user_service import UserService
        user_service = UserService(db)
        target_user = await user_service.get_user_by_id(assign_data.user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        organization_id = target_user.organization_id
    else:
        # Organization admin can only assign within their organization
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership required"
            )
        organization_id = current_user.organization_id

    user_locations = await location_service.assign_locations_to_user(
        assign_data=assign_data,
        organization_id=organization_id
    )

    # Build response
    assigned_locations = []
    primary_location = None

    for ul in user_locations:
        location_response = LocationResponse.model_validate(ul.location)
        assigned_locations.append(location_response)

        if ul.is_primary:
            primary_location = location_response

    return LocationAssignResponse(
        user_id=assign_data.user_id,
        assigned_locations=assigned_locations,
        primary_location=primary_location
    )


@router.get("/user/{user_id}", response_model=List[UserLocationResponse])
async def get_user_locations(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get user's assigned locations with access control:
    - Super Admin: Can see any user's locations
    - Organization User: Can see locations of users in their organization
    - Users can see their own locations
    """
    location_service = LocationService(db)

    # Users can always see their own locations
    if user_id == current_user.id:
        organization_id = current_user.organization_id
    elif current_user.is_super_admin:
        # Super admin can see any user's locations, need to get user's org
        from app.services.user_service import UserService
        user_service = UserService(db)
        target_user = await user_service.get_user_by_id(user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        organization_id = target_user.organization_id
    else:
        # Organization users can only see users in their organization
        if not current_user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        organization_id = current_user.organization_id

    user_locations = await location_service.get_user_locations(
        user_id=user_id,
        organization_id=organization_id
    )

    return [
        UserLocationResponse(
            user_id=ul.user_id,
            location=LocationResponse.model_validate(ul.location),
            is_primary=ul.is_primary,
            assigned_at=ul.created_at
        )
        for ul in user_locations
    ]
