"""
Location API endpoints for the AuthX service.
This module provides API endpoints for location management functionality.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
import math
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.api.deps import get_current_user, get_db, get_organization_admin, get_current_superadmin
from app.models.user import User
from app.models.location import Location
from app.models.location_group import LocationGroup
from app.schemas.location import (
    LocationCreate,
    LocationUpdate,
    LocationResponse,
    LocationListResponse,
    LocationHierarchyItem,
    GeoFenceCheckRequest,
    GeoFenceCheckResponse,
    LocationGroupCreate,
    LocationGroupUpdate,
    LocationGroupResponse,
    LocationGroupListResponse
)

router = APIRouter()

# Helper function to calculate distance between two coordinates (haversine formula)
def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371000  # Radius of earth in meters
    return c * r

# Location CRUD Operations
@router.post("", response_model=LocationResponse, status_code=status.HTTP_201_CREATED)
async def create_location(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    location_data: LocationCreate
):
    """
    Create a new location.
    Organization admins can create locations within their organization.
    """
    # Set organization_id from current user if not provided
    if not location_data.organization_id:
        location_data.organization_id = current_user.organization_id

    # Check if user has access to the organization
    if current_user.organization_id != location_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create locations for this organization"
        )

    # Validate parent location if provided
    if location_data.parent_id:
        parent_location = db.query(Location).filter(
            Location.id == location_data.parent_id,
            Location.organization_id == location_data.organization_id
        ).first()

        if not parent_location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent location not found or belongs to a different organization"
            )

    # Create new location
    new_location = Location(**location_data.dict())
    db.add(new_location)
    db.commit()
    db.refresh(new_location)

    return new_location

@router.get("", response_model=LocationListResponse)
async def get_locations(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    parent_id: Optional[UUID] = None,
    is_active: Optional[bool] = None,
    geo_fencing_enabled: Optional[bool] = None,
    country: Optional[str] = None,
    state: Optional[str] = None,
    city: Optional[str] = None
):
    """
    Get a paginated list of locations with optional filtering.
    Users can only view locations within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view locations for this organization"
        )

    # Build query
    query = db.query(Location).filter(Location.organization_id == organization_id)

    # Apply filters
    if name:
        query = query.filter(Location.name.ilike(f"%{name}%"))
    if parent_id:
        query = query.filter(Location.parent_id == parent_id)
    if is_active is not None:
        query = query.filter(Location.is_active == is_active)
    if geo_fencing_enabled is not None:
        query = query.filter(Location.geo_fencing_enabled == geo_fencing_enabled)
    if country:
        query = query.filter(Location.country.ilike(f"%{country}%"))
    if state:
        query = query.filter(Location.state.ilike(f"%{state}%"))
    if city:
        query = query.filter(Location.city.ilike(f"%{city}%"))

    # Get total count
    total = query.count()

    # Apply pagination
    locations = query.offset(skip).limit(limit).all()

    return {
        "items": locations,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/hierarchy", response_model=List[LocationHierarchyItem])
async def get_location_hierarchy(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None
):
    """
    Get locations organized in a hierarchical structure.
    Users can only view locations within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view locations for this organization"
        )

    # Get all locations for the organization
    locations = db.query(Location).filter(
        Location.organization_id == organization_id
    ).all()

    # Create a mapping of ID to location data
    location_map = {location.id: LocationHierarchyItem.from_orm(location) for location in locations}

    # Build the hierarchy
    root_locations = []
    for location_id, location_data in location_map.items():
        # If the location has a parent, add it as a child to the parent
        if location_data.parent_id and location_data.parent_id in location_map:
            parent = location_map[location_data.parent_id]
            parent.children.append(location_data)
        else:
            # Top-level location (no parent)
            root_locations.append(location_data)

    return root_locations

@router.get("/{location_id}", response_model=LocationResponse)
async def get_location(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    location_id: UUID
):
    """
    Get detailed information about a specific location by ID.
    Users can only view locations within their organization unless they are superadmins.
    """
    # Get location
    location = db.query(Location).filter(Location.id == location_id).first()

    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    # Check if user has permission to view this location
    if current_user.organization_id != location.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this location"
        )

    return location

@router.patch("/{location_id}", response_model=LocationResponse)
async def update_location(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    location_id: UUID,
    location_data: LocationUpdate
):
    """
    Update a location's details.
    Organization admins can only update locations within their organization.
    """
    # Get location
    location = db.query(Location).filter(Location.id == location_id).first()

    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    # Check if user has permission to update this location
    if current_user.organization_id != location.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this location"
        )

    # Validate parent location if provided
    if location_data.parent_id and location_data.parent_id != location.parent_id:
        # Check that the parent ID is not the location itself
        if location_data.parent_id == location_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A location cannot be its own parent"
            )

        parent_location = db.query(Location).filter(
            Location.id == location_data.parent_id,
            Location.organization_id == location.organization_id
        ).first()

        if not parent_location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent location not found or belongs to a different organization"
            )

        # Check for circular references in the hierarchy
        current_parent_id = parent_location.parent_id
        while current_parent_id:
            if current_parent_id == location_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Circular reference detected in location hierarchy"
                )

            parent = db.query(Location).filter(Location.id == current_parent_id).first()
            if not parent:
                break
            current_parent_id = parent.parent_id

    # Validate geo-fencing settings
    geo_enabled = location_data.geo_fencing_enabled
    if geo_enabled is not None and geo_enabled:
        has_coords = (
            (location_data.latitude is not None or location.latitude is not None) and
            (location_data.longitude is not None or location.longitude is not None)
        )
        has_radius = location_data.geo_fencing_radius is not None or location.geo_fencing_radius is not None

        if not has_coords:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Latitude and longitude must be provided when geo-fencing is enabled"
            )

        if not has_radius:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Geo-fencing radius must be provided when geo-fencing is enabled"
            )

    # Update location with provided data
    update_data = location_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(location, key, value)

    db.commit()
    db.refresh(location)

    return location

@router.delete("/{location_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_location(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    location_id: UUID,
    recursive: bool = Query(False)
):
    """
    Delete a location.
    Organization admins can only delete locations within their organization.
    If recursive=True, child locations will also be deleted.
    """
    # Get location
    location = db.query(Location).filter(Location.id == location_id).first()

    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    # Check if user has permission to delete this location
    if current_user.organization_id != location.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this location"
        )

    # Check if location has children
    has_children = db.query(Location).filter(Location.parent_id == location_id).first() is not None

    if has_children and not recursive:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Location has child locations. Set recursive=true to delete them as well."
        )

    if recursive:
        # Recursively delete all child locations
        def delete_children(parent_id):
            children = db.query(Location).filter(Location.parent_id == parent_id).all()
            for child in children:
                delete_children(child.id)
                db.delete(child)

        delete_children(location_id)

    # Delete the location
    db.delete(location)
    db.commit()

    return None

# Geo-fencing endpoints
@router.post("/{location_id}/geo-fence/check", response_model=GeoFenceCheckResponse)
async def check_geo_fence(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    location_id: UUID,
    coordinates: GeoFenceCheckRequest
):
    """
    Check if coordinates are within a location's geo-fence.
    Users can only check locations within their organization unless they are superadmins.
    """
    # Get location
    location = db.query(Location).filter(Location.id == location_id).first()

    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location not found"
        )

    # Check if user has permission to access this location
    if current_user.organization_id != location.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this location"
        )

    # Check if geo-fencing is enabled for this location
    if not location.geo_fencing_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Geo-fencing is not enabled for this location"
        )

    # Calculate distance from location center to the provided coordinates
    distance = calculate_distance(
        location.latitude, location.longitude,
        coordinates.latitude, coordinates.longitude
    )

    # Check if coordinates are within the geo-fence
    inside_fence = distance <= location.geo_fencing_radius

    return {
        "inside_fence": inside_fence,
        "distance": distance
    }

# Location Group Endpoints
@router.post("/groups", response_model=LocationGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_location_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    group_data: LocationGroupCreate
):
    """
    Create a new location group.
    Organization admins can create location groups within their organization.
    """
    # Set organization_id from current user if not provided
    if not group_data.organization_id:
        group_data.organization_id = current_user.organization_id

    # Check if user has access to the organization
    if current_user.organization_id != group_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create location groups for this organization"
        )

    # Validate that all locations exist and belong to the organization
    location_ids = group_data.location_ids or []
    if location_ids:
        locations = db.query(Location).filter(
            Location.id.in_(location_ids),
            Location.organization_id == group_data.organization_id
        ).all()

        if len(locations) != len(location_ids):
            found_ids = {str(location.id) for location in locations}
            missing_ids = [str(id) for id in location_ids if str(id) not in found_ids]
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Some locations not found or belong to a different organization: {', '.join(missing_ids)}"
            )

    # Create new location group
    group_dict = group_data.dict(exclude={"location_ids"})
    new_group = LocationGroup(**group_dict)
    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    # Add locations to the group
    if location_ids:
        for location in locations:
            new_group.locations.append(location)
        db.commit()
        db.refresh(new_group)

    return new_group

@router.get("/groups", response_model=LocationGroupListResponse)
async def get_location_groups(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    name: Optional[str] = None,
    location_id: Optional[UUID] = None
):
    """
    Get a paginated list of location groups with optional filtering.
    Users can only view location groups within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view location groups for this organization"
        )

    # Build query
    query = db.query(LocationGroup).filter(LocationGroup.organization_id == organization_id)

    # Apply filters
    if name:
        query = query.filter(LocationGroup.name.ilike(f"%{name}%"))

    # Filter by location membership
    if location_id:
        query = query.filter(LocationGroup.locations.any(Location.id == location_id))

    # Get total count
    total = query.count()

    # Apply pagination
    groups = query.offset(skip).limit(limit).all()

    return {
        "items": groups,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/groups/{group_id}", response_model=LocationGroupResponse)
async def get_location_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    group_id: UUID
):
    """
    Get detailed information about a specific location group by ID.
    Users can only view location groups within their organization unless they are superadmins.
    """
    # Get location group
    group = db.query(LocationGroup).filter(LocationGroup.id == group_id).first()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location group not found"
        )

    # Check if user has permission to view this location group
    if current_user.organization_id != group.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this location group"
        )

    return group

@router.patch("/groups/{group_id}", response_model=LocationGroupResponse)
async def update_location_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    group_id: UUID,
    group_data: LocationGroupUpdate
):
    """
    Update a location group's details.
    Organization admins can only update location groups within their organization.
    """
    # Get location group
    group = db.query(LocationGroup).filter(LocationGroup.id == group_id).first()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location group not found"
        )

    # Check if user has permission to update this location group
    if current_user.organization_id != group.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this location group"
        )

    # Update basic information
    if group_data.name is not None:
        group.name = group_data.name
    if group_data.description is not None:
        group.description = group_data.description

    # Update location membership if provided
    if group_data.location_ids is not None:
        # Validate that all locations exist and belong to the organization
        locations = db.query(Location).filter(
            Location.id.in_(group_data.location_ids),
            Location.organization_id == group.organization_id
        ).all()

        if len(locations) != len(group_data.location_ids):
            found_ids = {str(location.id) for location in locations}
            missing_ids = [str(id) for id in group_data.location_ids if str(id) not in found_ids]
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Some locations not found or belong to a different organization: {', '.join(missing_ids)}"
            )

        # Replace existing locations
        group.locations = locations

    db.commit()
    db.refresh(group)

    return group

@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_location_group(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    group_id: UUID
):
    """
    Delete a location group.
    Organization admins can only delete location groups within their organization.
    """
    # Get location group
    group = db.query(LocationGroup).filter(LocationGroup.id == group_id).first()

    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Location group not found"
        )

    # Check if user has permission to delete this location group
    if current_user.organization_id != group.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this location group"
        )

    # Delete the location group
    db.delete(group)
    db.commit()

    return None
