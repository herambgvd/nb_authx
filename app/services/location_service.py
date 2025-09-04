"""
Location management service for the AuthX microservice.
This module provides comprehensive location management functionality with full async support.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.models.location import Location
from app.models.location_group import LocationGroup
from app.models.organization import Organization

logger = logging.getLogger(__name__)

class LocationService:
    """Comprehensive location management service with full async support."""

    def __init__(self):
        self.supported_location_types = [
            'office', 'warehouse', 'store', 'factory', 'datacenter',
            'branch', 'headquarters', 'remote', 'virtual', 'other'
        ]

    async def create_location(
        self,
        db: AsyncSession,
        location_data: Dict[str, Any],
        organization_id: UUID,
        created_by: Optional[UUID] = None
    ) -> Location:
        """Create a new location with comprehensive validation."""
        logger.info(f"Creating location: {location_data.get('name')} for organization: {organization_id}")

        # Validate location type
        location_type = location_data.get('location_type')
        if location_type and location_type not in self.supported_location_types:
            logger.warning(f"Invalid location type: {location_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid location type. Supported types: {', '.join(self.supported_location_types)}"
            )

        # Check if location with same code already exists in organization
        if location_data.get('code'):
            existing_location = await self.get_location_by_code(
                db, location_data.get('code'), organization_id
            )
            if existing_location:
                logger.warning(f"Location creation failed - code already exists: {location_data.get('code')}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Location with this code already exists in the organization"
                )

        # Create location
        location = Location(
            name=location_data['name'],
            description=location_data.get('description'),
            location_type=location_data.get('location_type', 'office'),
            code=location_data.get('code'),
            organization_id=organization_id,
            address_line1=location_data.get('address_line1'),
            address_line2=location_data.get('address_line2'),
            city=location_data.get('city'),
            state=location_data.get('state'),
            postal_code=location_data.get('postal_code'),
            country=location_data.get('country'),
            latitude=location_data.get('latitude'),
            longitude=location_data.get('longitude'),
            phone=location_data.get('phone'),
            email=location_data.get('email'),
            is_primary=location_data.get('is_primary', False),
            parent_location_id=location_data.get('parent_location_id')
        )

        # If this is marked as primary, unmark other primary locations
        if location.is_primary:
            await self._unmark_other_primary_locations(db, organization_id)

        db.add(location)
        await db.commit()
        await db.refresh(location)

        logger.info(f"Location created successfully: {location.id}")
        return location

    async def get_location_by_id(self, db: AsyncSession, location_id: UUID) -> Optional[Location]:
        """Get location by ID with all relationships loaded."""
        logger.debug(f"Fetching location by ID: {location_id}")

        result = await db.execute(
            select(Location)
            .options(
                selectinload(Location.organization),
                selectinload(Location.parent_location),
                selectinload(Location.child_locations),
                selectinload(Location.location_groups)
            )
            .where(Location.id == location_id)
        )
        location = result.scalar_one_or_none()

        if location:
            logger.debug(f"Location found: {location.name}")
        else:
            logger.debug(f"Location not found with ID: {location_id}")

        return location

    async def get_location_by_code(
        self,
        db: AsyncSession,
        code: str,
        organization_id: UUID
    ) -> Optional[Location]:
        """Get location by code within organization."""
        logger.debug(f"Fetching location by code: {code} in organization: {organization_id}")

        result = await db.execute(
            select(Location)
            .where(
                and_(
                    Location.code == code,
                    Location.organization_id == organization_id
                )
            )
        )
        return result.scalar_one_or_none()

    async def update_location(
        self,
        db: AsyncSession,
        location_id: UUID,
        location_update: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> Optional[Location]:
        """Update location with validation and audit logging."""
        logger.info(f"Updating location: {location_id}")

        # Get existing location
        location = await self.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found for update: {location_id}")
            return None

        # Validate location type if being updated
        location_type = location_update.get('location_type')
        if location_type and location_type not in self.supported_location_types:
            logger.warning(f"Invalid location type: {location_type}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid location type. Supported types: {', '.join(self.supported_location_types)}"
            )

        # Update allowed fields
        allowed_fields = {
            'name', 'description', 'location_type', 'code',
            'address_line1', 'address_line2', 'city', 'state',
            'postal_code', 'country', 'latitude', 'longitude',
            'phone', 'email', 'is_primary', 'parent_location_id'
        }

        # If marking as primary, unmark other primary locations
        if location_update.get('is_primary') and not location.is_primary:
            await self._unmark_other_primary_locations(db, location.organization_id)

        for field, value in location_update.items():
            if field in allowed_fields and hasattr(location, field):
                setattr(location, field, value)
                logger.debug(f"Updated {field} for location {location_id}")

        location.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(location)

        logger.info(f"Location updated successfully: {location_id}")
        return location

    async def delete_location(self, db: AsyncSession, location_id: UUID) -> bool:
        """Delete location with validation."""
        logger.info(f"Deleting location: {location_id}")

        location = await self.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found for deletion: {location_id}")
            return False

        # Check if location has child locations
        result = await db.execute(
            select(func.count(Location.id)).where(Location.parent_location_id == location_id)
        )
        child_count = result.scalar()

        if child_count > 0:
            logger.warning(f"Cannot delete location with child locations: {child_count}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete location with {child_count} child locations"
            )

        # Soft delete by deactivating
        location.is_active = False
        location.updated_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Location deleted successfully: {location_id}")
        return True

    async def list_locations(
        self,
        db: AsyncSession,
        organization_id: UUID,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        location_type: Optional[str] = None,
        is_active: Optional[bool] = None,
        parent_location_id: Optional[UUID] = None
    ) -> Tuple[List[Location], int]:
        """List locations with pagination and filtering."""
        logger.debug(f"Listing locations for organization: {organization_id}")

        query = select(Location).options(
            selectinload(Location.parent_location),
            selectinload(Location.child_locations)
        ).where(Location.organization_id == organization_id)

        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    Location.name.ilike(search_term),
                    Location.code.ilike(search_term),
                    Location.description.ilike(search_term),
                    Location.city.ilike(search_term)
                )
            )

        if location_type:
            query = query.where(Location.location_type == location_type)

        if is_active is not None:
            query = query.where(Location.is_active == is_active)

        if parent_location_id:
            query = query.where(Location.parent_location_id == parent_location_id)

        # Get total count
        count_query = select(func.count(Location.id)).where(Location.organization_id == organization_id)
        if search:
            count_query = count_query.where(
                or_(
                    Location.name.ilike(search_term),
                    Location.code.ilike(search_term),
                    Location.description.ilike(search_term),
                    Location.city.ilike(search_term)
                )
            )
        if location_type:
            count_query = count_query.where(Location.location_type == location_type)
        if is_active is not None:
            count_query = count_query.where(Location.is_active == is_active)
        if parent_location_id:
            count_query = count_query.where(Location.parent_location_id == parent_location_id)

        count_result = await db.execute(count_query)
        total = count_result.scalar()

        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(Location.created_at.desc())
        result = await db.execute(query)
        locations = result.scalars().all()

        logger.debug(f"Found {len(locations)} locations out of {total} total")
        return list(locations), total

    async def get_location_hierarchy(
        self,
        db: AsyncSession,
        organization_id: UUID
    ) -> List[Dict[str, Any]]:
        """Get location hierarchy for organization."""
        logger.debug(f"Getting location hierarchy for organization: {organization_id}")

        # Get all locations
        result = await db.execute(
            select(Location)
            .options(selectinload(Location.child_locations))
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.is_active == True
                )
            )
            .order_by(Location.name)
        )
        all_locations = result.scalars().all()

        # Build hierarchy starting with root locations (no parent)
        hierarchy = []
        location_map = {loc.id: loc for loc in all_locations}

        for location in all_locations:
            if location.parent_location_id is None:
                hierarchy.append(self._build_location_tree(location, location_map))

        logger.debug(f"Built hierarchy with {len(hierarchy)} root locations")
        return hierarchy

    async def get_locations_by_type(
        self,
        db: AsyncSession,
        organization_id: UUID,
        location_type: str
    ) -> List[Location]:
        """Get all locations of specific type."""
        logger.debug(f"Getting locations of type: {location_type}")

        result = await db.execute(
            select(Location)
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.location_type == location_type,
                    Location.is_active == True
                )
            )
            .order_by(Location.name)
        )
        locations = result.scalars().all()

        logger.debug(f"Found {len(locations)} locations of type {location_type}")
        return list(locations)

    async def get_primary_location(self, db: AsyncSession, organization_id: UUID) -> Optional[Location]:
        """Get the primary location for organization."""
        logger.debug(f"Getting primary location for organization: {organization_id}")

        result = await db.execute(
            select(Location)
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.is_primary == True,
                    Location.is_active == True
                )
            )
        )
        return result.scalar_one_or_none()

    async def search_locations_by_distance(
        self,
        db: AsyncSession,
        organization_id: UUID,
        latitude: float,
        longitude: float,
        radius_km: float = 50.0
    ) -> List[Location]:
        """Search locations within a radius (basic implementation)."""
        logger.debug(f"Searching locations within {radius_km}km of ({latitude}, {longitude})")

        # Note: This is a basic implementation. For production, you'd use PostGIS
        # or more sophisticated geographic search
        result = await db.execute(
            select(Location)
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.latitude.isnot(None),
                    Location.longitude.isnot(None),
                    Location.is_active == True
                )
            )
        )
        all_locations = result.scalars().all()

        # Filter by approximate distance (simplified calculation)
        nearby_locations = []
        for location in all_locations:
            if location.latitude and location.longitude:
                distance = self._calculate_distance(
                    latitude, longitude, location.latitude, location.longitude
                )
                if distance <= radius_km:
                    nearby_locations.append(location)

        logger.debug(f"Found {len(nearby_locations)} locations within radius")
        return nearby_locations

    async def activate_location(self, db: AsyncSession, location_id: UUID) -> bool:
        """Activate location."""
        logger.info(f"Activating location: {location_id}")

        location = await self.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found for activation: {location_id}")
            return False

        location.is_active = True
        await db.commit()

        logger.info(f"Location activated successfully: {location_id}")
        return True

    async def deactivate_location(self, db: AsyncSession, location_id: UUID) -> bool:
        """Deactivate location."""
        logger.info(f"Deactivating location: {location_id}")

        location = await self.get_location_by_id(db, location_id)
        if not location:
            logger.warning(f"Location not found for deactivation: {location_id}")
            return False

        location.is_active = False
        await db.commit()

        logger.info(f"Location deactivated successfully: {location_id}")
        return True

    async def _unmark_other_primary_locations(self, db: AsyncSession, organization_id: UUID):
        """Unmark other primary locations in the organization."""
        await db.execute(
            update(Location)
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.is_primary == True
                )
            )
            .values(is_primary=False)
        )

    def _build_location_tree(self, location: Location, location_map: Dict[UUID, Location]) -> Dict[str, Any]:
        """Build location tree recursively."""
        tree = {
            'id': str(location.id),
            'name': location.name,
            'location_type': location.location_type,
            'code': location.code,
            'is_primary': location.is_primary,
            'children': []
        }

        # Add children
        for child_location in location.child_locations:
            if child_location.is_active:
                tree['children'].append(
                    self._build_location_tree(child_location, location_map)
                )

        return tree

    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate approximate distance between two points in kilometers."""
        import math

        # Approximate distance calculation (not for production use)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) * math.sin(dlat / 2) +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon / 2) * math.sin(dlon / 2))
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = 6371 * c  # Earth's radius in kilometers

        return distance

# Create singleton instance
location_service = LocationService()
