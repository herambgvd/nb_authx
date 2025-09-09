"""
Location API endpoints for AuthX with Google Maps integration.
Provides comprehensive location management with geocoding and validation.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.api.deps import get_current_active_user, get_current_organization_admin
from app.schemas.location import (
    LocationCreate, LocationUpdate, LocationResponse, LocationWithCoordinates,
    LocationSearchRequest, LocationValidationRequest
)
from app.schemas.user_location_access import (
    UserLocationAccessResponse,
    UserLocationAccessListResponse,
    GrantLocationAccessRequest,
    RevokeLocationAccessRequest
)
from app.services.location_service import location_service
from app.services.google_maps_service import google_maps_service
from app.services.user_location_access_service import user_location_access_service
from app.services.admin_management_service import admin_management_service
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter()

def _check_organization_access(current_user: User, target_organization_id: UUID) -> bool:
    """Check if current user can access resources in the target organization."""
    if current_user.is_superuser:
        return True

    # Organization admins and users can only access their own organization
    return current_user.organization_id == target_organization_id

@router.post("/{organization_id}/locations", response_model=LocationResponse)
async def create_location(
    organization_id: UUID,
    location_data: LocationCreate,
    current_user: User = Depends(get_current_organization_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Create a new location within the specified organization."""
    logger.info(f"Creating location: {location_data.name} in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create locations in this organization"
        )

    try:
        # Convert Pydantic model to dictionary for service
        location_dict = location_data.model_dump()

        # Use Google Maps API to get coordinates if not provided
        if not location_data.latitude or not location_data.longitude:
            full_address = f"{location_data.address_line1}, {location_data.city}, {location_data.state}, {location_data.country}"

            try:
                location_info = await google_maps_service.geocode_address(full_address)
                if location_info:
                    location_dict['latitude'] = location_info.latitude
                    location_dict['longitude'] = location_info.longitude
            except Exception as e:
                logger.warning(f"Geocoding failed: {e}")

        location = await location_service.create_location(
            db=db,
            location_data=location_dict,
            organization_id=organization_id,
            created_by=current_user.id
        )

        logger.info(f"Location created successfully: {location.id}")
        return LocationResponse.model_validate(location)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create location"
        )

@router.get("/{organization_id}/locations", response_model=List[LocationResponse])
async def get_locations(
    organization_id: UUID,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """Get all locations for the specified organization."""
    logger.info(f"Listing locations for organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access locations in this organization"
        )

    try:
        locations = await location_service.list_locations(
            db=db,
            organization_id=organization_id,
            skip=skip,
            limit=limit,
            search=search
        )

        logger.info(f"Retrieved {len(locations)} locations")
        return [LocationResponse.model_validate(location) for location in locations]

    except Exception as e:
        logger.error(f"Failed to list locations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve locations"
        )

@router.get("/{organization_id}/locations/{location_id}", response_model=LocationResponse)
async def get_location(
    organization_id: UUID,
    location_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """Get a specific location by ID within the organization."""
    logger.info(f"Getting location {location_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access locations in this organization"
        )

    try:
        location = await location_service.get_location(db, location_id)
        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Verify location belongs to the specified organization
        if location.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found in this organization"
            )

        return LocationResponse.model_validate(location)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get location: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve location"
        )

@router.put("/{organization_id}/locations/{location_id}", response_model=LocationResponse)
async def update_location(
    organization_id: UUID,
    location_id: UUID,
    location_update: LocationUpdate,
    current_user: User = Depends(get_current_organization_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Update a location within the organization."""
    logger.info(f"Updating location {location_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update locations in this organization"
        )

    try:
        # Verify location belongs to organization
        location = await location_service.get_location(db, location_id)
        if not location or location.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found in this organization"
            )

        # Update geocoding if address changed
        update_dict = location_update.model_dump(exclude_unset=True)

        # If address fields are being updated and coordinates are not provided, geocode
        address_fields = ['address_line1', 'city', 'state', 'country']
        if any(field in update_dict for field in address_fields) and not ('latitude' in update_dict and 'longitude' in update_dict):
            # Build address from updated and existing data
            current_address = {
                'address_line1': location.address_line1,
                'city': location.city,
                'state': location.state,
                'country': location.country
            }
            current_address.update({k: v for k, v in update_dict.items() if k in address_fields})

            full_address = f"{current_address['address_line1']}, {current_address['city']}, {current_address['state']}, {current_address['country']}"

            try:
                location_info = await google_maps_service.geocode_address(full_address)
                if location_info:
                    update_dict['latitude'] = location_info.latitude
                    update_dict['longitude'] = location_info.longitude
            except Exception as e:
                logger.warning(f"Geocoding failed during update: {e}")

        updated_location = await location_service.update_location(db, location_id, update_dict)
        logger.info(f"Location updated successfully: {location_id}")

        return LocationResponse.model_validate(updated_location)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location update failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update location"
        )

@router.delete("/{organization_id}/locations/{location_id}")
async def delete_location(
    organization_id: UUID,
    location_id: UUID,
    current_user: User = Depends(get_current_organization_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Delete a location within the organization."""
    logger.info(f"Deleting location {location_id} from organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete locations in this organization"
        )

    try:
        # Verify location belongs to organization
        location = await location_service.get_location(db, location_id)
        if not location or location.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found in this organization"
            )

        await location_service.delete_location(db, location_id)
        logger.info(f"Location deleted successfully: {location_id}")
        return {"message": "Location deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete location"
        )

@router.post("/{organization_id}/locations/validate", response_model=LocationWithCoordinates)
async def validate_location(
    organization_id: UUID,
    validation_request: LocationValidationRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """Validate and geocode a location address within the organization context."""
    logger.info(f"Validating location address for organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to validate locations in this organization"
        )

    try:
        full_address = f"{validation_request.address_line1}, {validation_request.city}, {validation_request.state}, {validation_request.country}"

        location_info = await google_maps_service.geocode_address(full_address)
        if not location_info:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not validate the provided address"
            )

        return LocationWithCoordinates(
            address_line1=validation_request.address_line1,
            address_line2=validation_request.address_line2,
            city=validation_request.city,
            state=validation_request.state,
            country=validation_request.country,
            postal_code=validation_request.postal_code,
            latitude=location_info.latitude,
            longitude=location_info.longitude,
            formatted_address=location_info.formatted_address
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate location"
        )

@router.post("/{organization_id}/locations/search", response_model=List[LocationResponse])
async def search_locations(
    organization_id: UUID,
    search_request: LocationSearchRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """Advanced search for locations within the organization."""
    logger.info(f"Searching locations in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to search locations in this organization"
        )

    try:
        locations = await location_service.search_locations(
            db, search_request, organization_id
        )

        logger.info(f"Found {len(locations)} locations matching search criteria")
        return [LocationResponse.model_validate(location) for location in locations]

    except Exception as e:
        logger.error(f"Location search failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search locations"
        )

# Location Access Control Endpoints
@router.post("/{organization_id}/access/grant")
async def grant_location_access(
    organization_id: UUID,
    request: GrantLocationAccessRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Grant location access to users within the organization.
    Only accessible by organization admins.
    """
    logger.info(f"Granting location access in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access in this organization"
        )

    # Verify admin permissions
    has_permission = await admin_management_service.verify_admin_permissions(
        db, current_user.id, "manage_access", organization_id
    )
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access"
        )

    try:
        accesses = await user_location_access_service.grant_location_access(
            db, request, current_user.id, organization_id
        )

        return {
            "message": f"Access granted to {len(request.user_ids)} users for {len(request.location_ids)} locations",
            "total_grants": len(accesses)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location access grant failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to grant location access"
        )

@router.post("/{organization_id}/access/revoke")
async def revoke_location_access(
    organization_id: UUID,
    request: RevokeLocationAccessRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Revoke location access from users within the organization.
    Only accessible by organization admins.
    """
    logger.info(f"Revoking location access in organization: {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access in this organization"
        )

    # Verify admin permissions
    has_permission = await admin_management_service.verify_admin_permissions(
        db, current_user.id, "manage_access", organization_id
    )
    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage location access"
        )

    try:
        revoked_count = await user_location_access_service.revoke_location_access(
            db, request, current_user.id, organization_id
        )

        return {
            "message": f"Access revoked for {revoked_count} user-location combinations"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location access revocation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke location access"
        )

@router.get("/{organization_id}/locations/{location_id}/users", response_model=UserLocationAccessListResponse)
async def get_location_user_accesses(
    organization_id: UUID,
    location_id: UUID,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Get all user accesses for a specific location within the organization.
    Only accessible by organization admins.
    """
    logger.info(f"Getting user accesses for location {location_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access location data in this organization"
        )

    try:
        # Verify location belongs to organization
        location = await location_service.get_location(db, location_id)
        if not location or location.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found in this organization"
            )

        accesses = await user_location_access_service.get_location_user_accesses(
            db, location_id, organization_id, include_expired
        )

        return UserLocationAccessListResponse(
            items=[UserLocationAccessResponse.model_validate(access) for access in accesses],
            total=len(accesses)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get location user accesses: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve location user accesses"
        )

@router.get("/{organization_id}/users/{user_id}/locations", response_model=UserLocationAccessListResponse)
async def get_user_location_accesses(
    organization_id: UUID,
    user_id: UUID,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_organization_admin)
):
    """
    Get all location accesses for a specific user within the organization.
    Only accessible by organization admins.
    """
    logger.info(f"Getting location accesses for user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access user data in this organization"
        )

    try:
        accesses = await user_location_access_service.get_user_location_accesses(
            db, user_id, organization_id, include_expired
        )

        return UserLocationAccessListResponse(
            items=[UserLocationAccessResponse.model_validate(access) for access in accesses],
            total=len(accesses)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user location accesses: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user location accesses"
        )

@router.get("/{organization_id}/users/{user_id}/accessible-locations")
async def get_user_accessible_locations(
    organization_id: UUID,
    user_id: UUID,
    permission: str = Query("read", description="Permission level: read, write, delete, manage"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all locations that a user has access to within the organization.
    Users can access their own accessible locations, admins can access any user's in their org.
    """
    logger.info(f"Getting accessible locations for user {user_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access data in this organization"
        )

    # Check if user is requesting their own data or is an admin
    if user_id != current_user.id:
        admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
        if not admin or (admin.is_organization_admin and admin.organization_id != organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this user's location data"
            )

    try:
        locations = await user_location_access_service.get_accessible_locations_for_user(
            db, user_id, organization_id, permission
        )

        return {
            "user_id": user_id,
            "organization_id": str(organization_id),
            "permission": permission,
            "accessible_locations": [
                {
                    "id": str(loc.id),
                    "name": loc.name,
                    "location_type": loc.location_type,
                    "code": loc.code,
                    "is_active": loc.is_active
                }
                for loc in locations
            ],
            "total": len(locations)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get accessible locations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve accessible locations"
        )

@router.get("/{organization_id}/check-access/{user_id}/{location_id}")
async def check_user_location_access(
    organization_id: UUID,
    user_id: UUID,
    location_id: UUID,
    permission: str = Query("read", description="Permission level: read, write, delete, manage"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Check if a user has specific permission for a location within the organization.
    Users can check their own access, admins can check any user's access in their org.
    """
    logger.info(f"Checking access for user {user_id} to location {location_id} in organization {organization_id}")

    # Check organization access
    if not _check_organization_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to check access in this organization"
        )

    # Check if user is requesting their own data or is an admin
    if user_id != current_user.id:
        admin = await admin_management_service.get_admin_by_user_id(db, current_user.id)
        if not admin or (admin.is_organization_admin and admin.organization_id != organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to check this user's access"
            )

    try:
        # Verify location belongs to organization
        location = await location_service.get_location(db, location_id)
        if not location or location.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found in this organization"
            )

        has_access = await user_location_access_service.check_user_location_access(
            db, user_id, location_id, organization_id, permission
        )

        return {
            "user_id": str(user_id),
            "location_id": str(location_id),
            "organization_id": str(organization_id),
            "permission": permission,
            "has_access": has_access
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check user location access: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check access"
        )
