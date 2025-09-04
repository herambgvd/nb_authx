"""
Location management API endpoints for AuthX.
Provides comprehensive location CRUD operations and management functionality with full async support.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import logging

from app.db.session import get_async_db
from app.models.user import User
from app.services.location_service import location_service
from app.services.role_service import role_service
from app.api.deps import get_current_active_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_location(
    location_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new location with comprehensive validation."""
    logger.info(f"Creating location: {location_data.get('name')}")

    # Check if user has permission to create locations
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'locations', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized location creation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to create locations"
            )

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization to create locations"
            )

        location = await location_service.create_location(
            db, location_data, organization_id, current_user.id
        )

        logger.info(f"Location created successfully: {location.id}")
        return {
            "id": str(location.id),
            "name": location.name,
            "description": location.description,
            "location_type": location.location_type,
            "code": location.code,
            "address_line1": location.address_line1,
            "address_line2": location.address_line2,
            "city": location.city,
            "state": location.state,
            "postal_code": location.postal_code,
            "country": location.country,
            "latitude": location.latitude,
            "longitude": location.longitude,
            "phone": location.phone,
            "email": location.email,
            "is_active": location.is_active,
            "is_primary": location.is_primary,
            "parent_location_id": str(location.parent_location_id) if location.parent_location_id else None,
            "organization_id": str(location.organization_id),
            "created_at": location.created_at.isoformat() if location.created_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Location creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create location"
        )

@router.get("/")
async def list_locations(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    location_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    parent_location_id: Optional[UUID] = Query(None)
):
    """List locations with filtering and pagination."""
    logger.info(f"Listing locations - skip: {skip}, limit: {limit}")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        locations, total = await location_service.list_locations(
            db, organization_id, skip=skip, limit=limit, search=search,
            location_type=location_type, is_active=is_active, parent_location_id=parent_location_id
        )

        logger.info(f"Retrieved {len(locations)} locations out of {total} total")
        return {
            "locations": [
                {
                    "id": str(location.id),
                    "name": location.name,
                    "description": location.description,
                    "location_type": location.location_type,
                    "code": location.code,
                    "city": location.city,
                    "state": location.state,
                    "country": location.country,
                    "is_active": location.is_active,
                    "is_primary": location.is_primary,
                    "parent_location_id": str(location.parent_location_id) if location.parent_location_id else None,
                    "created_at": location.created_at.isoformat() if location.created_at else None
                }
                for location in locations
            ],
            "total": total,
            "skip": skip,
            "limit": limit
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list locations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve locations"
        )

@router.get("/hierarchy")
async def get_location_hierarchy(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get location hierarchy for organization."""
    logger.info(f"Getting location hierarchy for organization: {current_user.organization_id}")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        hierarchy = await location_service.get_location_hierarchy(db, organization_id)

        logger.info(f"Retrieved location hierarchy with {len(hierarchy)} root locations")
        return {"hierarchy": hierarchy}

    except Exception as e:
        logger.error(f"Failed to get location hierarchy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve location hierarchy"
        )

@router.get("/types/{location_type}")
async def get_locations_by_type(
    location_type: str,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all locations of specific type."""
    logger.info(f"Getting locations of type: {location_type}")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        locations = await location_service.get_locations_by_type(
            db, organization_id, location_type
        )

        logger.info(f"Retrieved {len(locations)} locations of type {location_type}")
        return {
            "locations": [
                {
                    "id": str(location.id),
                    "name": location.name,
                    "description": location.description,
                    "code": location.code,
                    "address_line1": location.address_line1,
                    "city": location.city,
                    "state": location.state,
                    "country": location.country,
                    "latitude": location.latitude,
                    "longitude": location.longitude,
                    "is_primary": location.is_primary
                }
                for location in locations
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get locations by type: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve locations by type"
        )

@router.get("/primary")
async def get_primary_location(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get the primary location for organization."""
    logger.info(f"Getting primary location for organization: {current_user.organization_id}")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        primary_location = await location_service.get_primary_location(db, organization_id)

        if not primary_location:
            return {"primary_location": None}

        logger.info(f"Retrieved primary location: {primary_location.name}")
        return {
            "primary_location": {
                "id": str(primary_location.id),
                "name": primary_location.name,
                "description": primary_location.description,
                "location_type": primary_location.location_type,
                "code": primary_location.code,
                "address_line1": primary_location.address_line1,
                "city": primary_location.city,
                "state": primary_location.state,
                "country": primary_location.country,
                "latitude": primary_location.latitude,
                "longitude": primary_location.longitude
            }
        }

    except Exception as e:
        logger.error(f"Failed to get primary location: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve primary location"
        )

@router.get("/{location_id}")
async def get_location(
    location_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get location by ID."""
    logger.info(f"Retrieving location: {location_id}")

    try:
        location = await location_service.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Check if user can access this location
        if (not current_user.is_superuser and
            str(location.organization_id) != str(current_user.organization_id)):
            logger.warning(f"Unauthorized location access attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this location"
            )

        logger.info(f"Location retrieved successfully: {location.name}")
        return {
            "id": str(location.id),
            "name": location.name,
            "description": location.description,
            "location_type": location.location_type,
            "code": location.code,
            "address_line1": location.address_line1,
            "address_line2": location.address_line2,
            "city": location.city,
            "state": location.state,
            "postal_code": location.postal_code,
            "country": location.country,
            "latitude": location.latitude,
            "longitude": location.longitude,
            "phone": location.phone,
            "email": location.email,
            "is_active": location.is_active,
            "is_primary": location.is_primary,
            "parent_location_id": str(location.parent_location_id) if location.parent_location_id else None,
            "organization_id": str(location.organization_id),
            "created_at": location.created_at.isoformat() if location.created_at else None,
            "updated_at": location.updated_at.isoformat() if location.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve location {location_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve location"
        )

@router.put("/{location_id}")
async def update_location(
    location_id: UUID,
    location_update: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update location information."""
    logger.info(f"Updating location: {location_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'locations', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized location update attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update locations"
            )

    try:
        updated_location = await location_service.update_location(
            db, location_id, location_update, current_user.id
        )

        if not updated_location:
            logger.warning(f"Location not found for update: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        logger.info(f"Location updated successfully: {location_id}")
        return {
            "id": str(updated_location.id),
            "name": updated_location.name,
            "description": updated_location.description,
            "location_type": updated_location.location_type,
            "is_active": updated_location.is_active,
            "is_primary": updated_location.is_primary,
            "updated_at": updated_location.updated_at.isoformat() if updated_location.updated_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update location {location_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update location"
        )

@router.post("/{location_id}/activate")
async def activate_location(
    location_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Activate location."""
    logger.info(f"Activating location: {location_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'locations', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized location activation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to activate locations"
            )

    try:
        success = await location_service.activate_location(db, location_id)
        if not success:
            logger.warning(f"Location not found for activation: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        logger.info(f"Location activated successfully: {location_id}")
        return {"message": "Location activated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate location {location_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate location"
        )

@router.post("/{location_id}/deactivate")
async def deactivate_location(
    location_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Deactivate location."""
    logger.info(f"Deactivating location: {location_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'locations', 'write'
        )
        if not has_permission:
            logger.warning(f"Unauthorized location deactivation attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to deactivate locations"
            )

    try:
        success = await location_service.deactivate_location(db, location_id)
        if not success:
            logger.warning(f"Location not found for deactivation: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        logger.info(f"Location deactivated successfully: {location_id}")
        return {"message": "Location deactivated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate location {location_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate location"
        )

@router.delete("/{location_id}")
async def delete_location(
    location_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete location (soft delete)."""
    logger.info(f"Deleting location: {location_id}")

    # Check permissions
    if not current_user.is_superuser:
        has_permission = await role_service.check_permission(
            db, current_user.id, 'locations', 'delete'
        )
        if not has_permission:
            logger.warning(f"Unauthorized location deletion attempt by {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete locations"
            )

    try:
        success = await location_service.delete_location(db, location_id)
        if not success:
            logger.warning(f"Location not found for deletion: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        logger.info(f"Location deleted successfully: {location_id}")
        return {"message": "Location deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete location {location_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete location"
        )

@router.post("/search/nearby")
async def search_nearby_locations(
    search_data: dict,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user)
):
    """Search for locations within a radius."""
    logger.info(f"Searching for nearby locations")

    try:
        organization_id = current_user.organization_id
        if not organization_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User must belong to an organization"
            )

        latitude = search_data.get('latitude')
        longitude = search_data.get('longitude')
        radius_km = search_data.get('radius_km', 50.0)

        if latitude is None or longitude is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Latitude and longitude are required"
            )

        locations = await location_service.search_locations_by_distance(
            db, organization_id, latitude, longitude, radius_km
        )

        logger.info(f"Found {len(locations)} locations within {radius_km}km radius")
        return {
            "locations": [
                {
                    "id": str(location.id),
                    "name": location.name,
                    "location_type": location.location_type,
                    "code": location.code,
                    "city": location.city,
                    "state": location.state,
                    "latitude": location.latitude,
                    "longitude": location.longitude
                }
                for location in locations
            ],
            "search_criteria": {
                "latitude": latitude,
                "longitude": longitude,
                "radius_km": radius_km
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to search nearby locations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to search nearby locations"
        )
