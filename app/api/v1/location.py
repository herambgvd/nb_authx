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
from app.api.deps import get_current_active_user, get_current_organization_admin, get_current_user_organization
from app.schemas.location import (
    LocationCreate, LocationUpdate, LocationResponse, LocationWithCoordinates,
    LocationSearchRequest, LocationValidationRequest
)
from app.services.location_service import location_service
from app.services.google_maps_service import google_maps_service
from app.models.user import User
from app.models.organization import Organization

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/", response_model=LocationResponse)
async def create_location(
    location_data: LocationCreate,
    current_user: User = Depends(get_current_organization_admin),
    organization: Organization = Depends(get_current_user_organization),
    db: AsyncSession = Depends(get_async_db)
):
    """Create a new location with automatic geocoding."""
    logger.info(f"Creating location: {location_data.get('name')}")

    try:
        # Use Google Maps API to get coordinates if not provided
        if not location_data.latitude or not location_data.longitude:
            full_address = f"{location_data.address_line1}, {location_data.city}, {location_data.state}, {location_data.country}"

            async with google_maps_service as gms:
                location_info = await gms.geocode_address(full_address)

                if location_info:
                    location_data.latitude = location_info.latitude
                    location_data.longitude = location_info.longitude
                    # Update address fields with formatted data if available
                    if location_info.formatted_address:
                        location_data.formatted_address = location_info.formatted_address
                    if location_info.place_id:
                        location_data.google_place_id = location_info.place_id
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Unable to geocode the provided address"
                    )

        location = await location_service.create_location(
            db=db,
            location_data=location_data,
            organization_id=organization.id,
            created_by=current_user.id
        )

        logger.info(f"Location created successfully: {location.id}")
        return {
            "id": str(location.id),
            "name": location.name,
            "description": location.description,
            "location_type": location.location_type,
            "code": location.code,
            "organization_id": str(location.organization_id),
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
            "is_primary": location.is_primary,
            "is_active": location.is_active,
            "parent_location_id": str(location.parent_location_id) if location.parent_location_id else None,
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

@router.get("/", response_model=List[LocationResponse])
async def get_organization_locations(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user),
    organization: Organization = Depends(get_current_user_organization),
    db: AsyncSession = Depends(get_async_db)
):
    """Get all locations for the current organization."""
    logger.info(f"Listing locations - skip: {skip}, limit: {limit}")

    try:
        locations, total = await location_service.get_organization_locations(
            db=db,
            organization_id=organization.id,
            skip=skip,
            limit=limit,
            search=search
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
                    "is_primary": location.is_primary,
                    "is_active": location.is_active,
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

@router.get("/{location_id}", response_model=LocationResponse)
async def get_location(
    location_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """Get a specific location by ID."""
    logger.info(f"Retrieving location: {location_id}")

    try:
        location = await location_service.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found: {location_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Check if user has access to this location's organization
        if (not current_user.is_superuser and
            location.organization_id != current_user.organization_id):
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
            "organization_id": str(location.organization_id),
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
            "is_primary": location.is_primary,
            "is_active": location.is_active,
            "parent_location_id": str(location.parent_location_id) if location.parent_location_id else None,
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

@router.put("/{location_id}", response_model=LocationResponse)
async def update_location(
    location_id: UUID,
    location_data: LocationUpdate,
    current_user: User = Depends(get_current_organization_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Update a location."""
    logger.info(f"Updating location: {location_id}")

    try:
        location = await location_service.get_location_by_id(db, location_id)
        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Check if user has access to this location's organization
        if (not current_user.is_superuser and
            location.organization_id != current_user.organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this location"
            )

        # Re-geocode if address changed and no new coordinates provided
        if (location_data.address_line1 or location_data.city or
            location_data.state or location_data.country) and \
           not (location_data.latitude and location_data.longitude):

            # Build address from update data or existing data
            address_parts = [
                location_data.address_line1 or location.address_line1,
                location_data.city or location.city,
                location_data.state or location.state,
                location_data.country or location.country
            ]
            full_address = ", ".join(filter(None, address_parts))

            async with google_maps_service as gms:
                location_info = await gms.geocode_address(full_address)

                if location_info:
                    location_data.latitude = location_info.latitude
                    location_data.longitude = location_info.longitude
                    if location_info.formatted_address:
                        location_data.formatted_address = location_info.formatted_address

        updated_location = await location_service.update_location(
            db=db,
            location_id=location_id,
            location_data=location_data,
            updated_by=current_user.id
        )

        logger.info(f"Location updated successfully: {location_id}")
        return {
            "id": str(updated_location.id),
            "name": updated_location.name,
            "description": updated_location.description,
            "location_type": updated_location.location_type,
            "code": updated_location.code,
            "address_line1": updated_location.address_line1,
            "address_line2": updated_location.address_line2,
            "city": updated_location.city,
            "state": updated_location.state,
            "postal_code": updated_location.postal_code,
            "country": updated_location.country,
            "latitude": updated_location.latitude,
            "longitude": updated_location.longitude,
            "phone": updated_location.phone,
            "email": updated_location.email,
            "is_primary": updated_location.is_primary,
            "is_active": updated_location.is_active,
            "parent_location_id": str(updated_location.parent_location_id) if updated_location.parent_location_id else None,
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

@router.delete("/{location_id}")
async def delete_location(
    location_id: UUID,
    current_user: User = Depends(get_current_organization_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Delete a location."""
    logger.info(f"Deleting location: {location_id}")

    try:
        location = await location_service.get_location_by_id(db, location_id)
        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Check if user has access to this location's organization
        if (not current_user.is_superuser and
            location.organization_id != current_user.organization_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this location"
            )

        success = await location_service.delete_location(db, location_id, current_user.id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to delete location"
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

@router.post("/geocode", response_model=LocationWithCoordinates)
async def geocode_address(
    address: str = Query(..., min_length=5),
    current_user: User = Depends(get_current_active_user)
):
    """Geocode an address to get coordinates."""
    try:
        async with google_maps_service as gms:
            location_info = await gms.geocode_address(address)

            if not location_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Address not found"
                )

            return LocationWithCoordinates(
                address=location_info.address,
                latitude=location_info.latitude,
                longitude=location_info.longitude,
                place_id=location_info.place_id,
                formatted_address=location_info.formatted_address,
                country=location_info.country,
                state=location_info.state,
                city=location_info.city,
                postal_code=location_info.postal_code,
                place_types=location_info.place_types or []
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Geocoding failed: {str(e)}"
        )

@router.post("/reverse-geocode", response_model=LocationWithCoordinates)
async def reverse_geocode(
    latitude: float = Query(..., ge=-90, le=90),
    longitude: float = Query(..., ge=-180, le=180),
    current_user: User = Depends(get_current_active_user)
):
    """Reverse geocode coordinates to get address."""
    try:
        async with google_maps_service as gms:
            location_info = await gms.reverse_geocode(latitude, longitude)

            if not location_info:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Location not found for these coordinates"
                )

            return LocationWithCoordinates(
                address=location_info.address,
                latitude=location_info.latitude,
                longitude=location_info.longitude,
                place_id=location_info.place_id,
                formatted_address=location_info.formatted_address,
                country=location_info.country,
                state=location_info.state,
                city=location_info.city,
                postal_code=location_info.postal_code,
                place_types=location_info.place_types or []
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Reverse geocoding failed: {str(e)}"
        )

@router.post("/validate-coordinates")
async def validate_coordinates(
    latitude: float = Query(..., ge=-90, le=90),
    longitude: float = Query(..., ge=-180, le=180),
    current_user: User = Depends(get_current_active_user)
):
    """Validate if coordinates are valid and return location info."""
    try:
        async with google_maps_service as gms:
            is_valid = await gms.validate_coordinates(latitude, longitude)

            return {
                "valid": is_valid,
                "latitude": latitude,
                "longitude": longitude
            }

    except Exception as e:
        return {
            "valid": False,
            "latitude": latitude,
            "longitude": longitude,
            "error": str(e)
        }

@router.get("/search/places")
async def search_places(
    query: str = Query(..., min_length=2),
    latitude: Optional[float] = Query(None, ge=-90, le=90),
    longitude: Optional[float] = Query(None, ge=-180, le=180),
    radius: int = Query(50000, ge=1000, le=100000),  # 1km to 100km
    current_user: User = Depends(get_current_active_user)
):
    """Search for places using Google Places API."""
    try:
        location = (latitude, longitude) if latitude and longitude else None

        async with google_maps_service as gms:
            places = await gms.search_places(query, location, radius)

            return {
                "query": query,
                "location": {"latitude": latitude, "longitude": longitude} if location else None,
                "radius": radius,
                "results": [
                    {
                        "place_id": place.place_id,
                        "name": place.name,
                        "formatted_address": place.formatted_address,
                        "latitude": place.latitude,
                        "longitude": place.longitude,
                        "rating": place.rating,
                        "types": place.types,
                        "business_status": place.business_status
                    }
                    for place in places
                ]
            }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Place search failed: {str(e)}"
        )

@router.get("/distance")
async def calculate_distance(
    origin_lat: float = Query(..., ge=-90, le=90),
    origin_lng: float = Query(..., ge=-180, le=180),
    dest_lat: float = Query(..., ge=-90, le=90),
    dest_lng: float = Query(..., ge=-180, le=180),
    current_user: User = Depends(get_current_active_user)
):
    """Calculate distance and duration between two points."""
    try:
        origin = (origin_lat, origin_lng)
        destination = (dest_lat, dest_lng)

        async with google_maps_service as gms:
            distance_info = await gms.calculate_distance(origin, destination)

            if not distance_info:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unable to calculate distance"
                )

            return {
                "origin": {"latitude": origin_lat, "longitude": origin_lng},
                "destination": {"latitude": dest_lat, "longitude": dest_lng},
                "distance": distance_info["distance"],
                "duration": distance_info["duration"]
            }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Distance calculation failed: {str(e)}"
        )
