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
                detail="Cannot delete location that has child locations"
            )

        await db.execute(delete(Location).where(Location.id == location_id))
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
        parent_id: Optional[UUID] = None
    ) -> Tuple[List[Location], int]:
        """List locations with filtering, search, and pagination."""
        logger.info(f"Listing locations for organization: {organization_id}")

        # Build query
        query = select(Location).where(Location.organization_id == organization_id)

        # Apply filters
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                or_(
                    Location.name.ilike(search_pattern),
                    Location.description.ilike(search_pattern),
                    Location.code.ilike(search_pattern),
                    Location.city.ilike(search_pattern)
                )
            )

        if location_type:
            query = query.where(Location.location_type == location_type)

        if is_active is not None:
            query = query.where(Location.is_active == is_active)

        if parent_id:
            query = query.where(Location.parent_location_id == parent_id)

        # Get total count
        count_result = await db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar()

        # Apply pagination and ordering
        query = query.order_by(Location.name).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        locations = result.scalars().all()

        logger.info(f"Retrieved {len(locations)} locations out of {total} total")
        return locations, total

    async def get_location_hierarchy(
        self,
        db: AsyncSession,
        organization_id: UUID,
        root_location_id: Optional[UUID] = None
    ) -> List[Dict[str, Any]]:
        """Get location hierarchy for organization."""
        logger.info(f"Getting location hierarchy for organization: {organization_id}")

        # Get all locations for the organization
        query = select(Location).where(Location.organization_id == organization_id)

        if root_location_id:
            query = query.where(Location.parent_location_id == root_location_id)
        else:
            query = query.where(Location.parent_location_id.is_(None))

        result = await db.execute(query.order_by(Location.name))
        root_locations = result.scalars().all()

        hierarchy = []
        for location in root_locations:
            location_dict = {
                "id": str(location.id),
                "name": location.name,
                "code": location.code,
                "location_type": location.location_type,
                "is_primary": location.is_primary,
                "children": await self._get_child_locations(db, location.id)
            }
            hierarchy.append(location_dict)

        return hierarchy

    async def _get_child_locations(self, db: AsyncSession, parent_id: UUID) -> List[Dict[str, Any]]:
        """Recursively get child locations."""
        result = await db.execute(
            select(Location)
            .where(Location.parent_location_id == parent_id)
            .order_by(Location.name)
        )
        children = result.scalars().all()

        child_list = []
        for child in children:
            child_dict = {
                "id": str(child.id),
                "name": child.name,
                "code": child.code,
                "location_type": child.location_type,
                "is_primary": child.is_primary,
                "children": await self._get_child_locations(db, child.id)
            }
            child_list.append(child_dict)

        return child_list

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

    async def get_primary_location(self, db: AsyncSession, organization_id: UUID) -> Optional[Location]:
        """Get the primary location for an organization."""
        result = await db.execute(
            select(Location)
            .where(
                and_(
                    Location.organization_id == organization_id,
                    Location.is_primary == True
                )
            )
        )
        return result.scalar_one_or_none()

    async def assign_location_group(
        self,
        db: AsyncSession,
        location_id: UUID,
        group_id: UUID
    ) -> bool:
        """Assign location to a location group."""
        logger.info(f"Assigning location {location_id} to group {group_id}")

        location = await self.get_location_by_id(db, location_id)
        if not location:
            return False

        # Check if group exists
        result = await db.execute(
            select(LocationGroup).where(LocationGroup.id == group_id)
        )
        group = result.scalar_one_or_none()
        if not group:
            return False

        # Add location to group if not already assigned
        if group not in location.location_groups:
            location.location_groups.append(group)
            await db.commit()

        return True

    async def remove_location_group(
        self,
        db: AsyncSession,
        location_id: UUID,
        group_id: UUID
    ) -> bool:
        """Remove location from a location group."""
        logger.info(f"Removing location {location_id} from group {group_id}")

        location = await self.get_location_by_id(db, location_id)
        if not location:
            return False

        # Check if group exists
        result = await db.execute(
            select(LocationGroup).where(LocationGroup.id == group_id)
        )
        group = result.scalar_one_or_none()
        if not group:
            return False

        # Remove location from group if assigned
        if group in location.location_groups:
            location.location_groups.remove(group)
            await db.commit()

        return True

# Create singleton instance
location_service = LocationService()
