"""
Location service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, and_, func
from sqlalchemy.orm import selectinload
from typing import Optional, List, Tuple
from app.models import Location, UserLocation, User
from app.schemas import LocationCreate, LocationUpdate, LocationAssignRequest
from fastapi import HTTPException, status
import logging
import re

logger = logging.getLogger(__name__)


class LocationService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_location(
        self,
        location_data: LocationCreate,
        organization_id: str,
        created_by_user_id: Optional[str] = None
    ) -> Location:
        """Create a new location within an organization"""

        # Validate code format (uppercase alphanumeric, underscore, and hyphen only)
        if not re.match(r'^[A-Z0-9_-]+$', location_data.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Location code must contain only uppercase letters, numbers, underscores, and hyphens"
            )

        # Check if location with code already exists in the organization
        stmt = select(Location).where(
            and_(
                Location.code == location_data.code,
                Location.organization_id == organization_id
            )
        )
        existing_location = await self.db.execute(stmt)
        if existing_location.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Location with this code already exists in the organization"
            )

        # Create location
        location = Location(
            name=location_data.name,
            code=location_data.code,
            description=location_data.description,
            address=location_data.address,
            city=location_data.city,
            state=location_data.state,
            country=location_data.country,
            postal_code=location_data.postal_code,
            organization_id=organization_id
        )

        self.db.add(location)
        await self.db.commit()
        await self.db.refresh(location)

        logger.info(f"Location created: {location.id} in organization {organization_id}")
        return location

    async def get_location_by_id(self, location_id: str, organization_id: Optional[str] = None) -> Optional[Location]:
        """Get location by ID, optionally scoped to organization"""
        stmt = select(Location).where(Location.id == location_id)

        if organization_id:
            stmt = stmt.where(Location.organization_id == organization_id)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_locations(
        self,
        organization_id: str,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[List[Location], int]:
        """Get paginated list of locations for an organization"""

        # Build base query
        query = select(Location).where(Location.organization_id == organization_id)

        # Apply filters
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                Location.name.ilike(search_pattern) |
                Location.code.ilike(search_pattern) |
                Location.city.ilike(search_pattern)
            )

        if is_active is not None:
            query = query.where(Location.is_active == is_active)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination and ordering
        query = query.order_by(Location.name).offset(skip).limit(limit)

        # Execute query
        result = await self.db.execute(query)
        locations = result.scalars().all()

        return list(locations), total

    async def update_location(
        self,
        location_id: str,
        location_data: LocationUpdate,
        organization_id: str
    ) -> Optional[Location]:
        """Update a location"""

        # Get existing location
        location = await self.get_location_by_id(location_id, organization_id)
        if not location:
            return None

        # Update fields
        update_data = location_data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            setattr(location, field, value)

        await self.db.commit()
        await self.db.refresh(location)

        logger.info(f"Location updated: {location_id}")
        return location

    async def delete_location(self, location_id: str, organization_id: str) -> bool:
        """Delete a location"""

        # Check if location exists and belongs to organization
        location = await self.get_location_by_id(location_id, organization_id)
        if not location:
            return False

        # Check if location has assigned users
        stmt = select(func.count(UserLocation.id)).where(UserLocation.location_id == location_id)
        result = await self.db.execute(stmt)
        user_count = result.scalar()

        if user_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete location. It has {user_count} assigned users."
            )

        await self.db.delete(location)
        await self.db.commit()

        logger.info(f"Location deleted: {location_id}")
        return True

    async def assign_locations_to_user(
        self,
        assign_data: LocationAssignRequest,
        organization_id: str
    ) -> List[UserLocation]:
        """Assign multiple locations to a user"""

        # Verify user exists and belongs to organization
        stmt = select(User).where(
            and_(
                User.id == assign_data.user_id,
                User.organization_id == organization_id
            )
        )
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or doesn't belong to this organization"
            )

        # Verify all locations exist and belong to organization
        stmt = select(Location).where(
            and_(
                Location.id.in_(assign_data.location_ids),
                Location.organization_id == organization_id,
                Location.is_active == True
            )
        )
        result = await self.db.execute(stmt)
        locations = result.scalars().all()

        if len(locations) != len(assign_data.location_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more locations not found or inactive"
            )

        # Validate primary location
        if assign_data.primary_location_id and assign_data.primary_location_id not in assign_data.location_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Primary location must be included in the location list"
            )

        # Remove existing location assignments for the user
        stmt = delete(UserLocation).where(UserLocation.user_id == assign_data.user_id)
        await self.db.execute(stmt)

        # Create new assignments
        user_locations = []
        for location_id in assign_data.location_ids:
            is_primary = location_id == assign_data.primary_location_id
            user_location = UserLocation(
                user_id=assign_data.user_id,
                location_id=location_id,
                is_primary=is_primary
            )
            self.db.add(user_location)
            user_locations.append(user_location)

        await self.db.commit()

        # Refresh objects with relationships
        for ul in user_locations:
            await self.db.refresh(ul)

        logger.info(f"Assigned {len(assign_data.location_ids)} locations to user {assign_data.user_id}")
        return user_locations

    async def get_user_locations(self, user_id: str, organization_id: str) -> List[UserLocation]:
        """Get all locations assigned to a user"""

        # Verify user belongs to organization
        stmt = select(User).where(
            and_(
                User.id == user_id,
                User.organization_id == organization_id
            )
        )
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or doesn't belong to this organization"
            )

        # Get user locations with location details
        stmt = select(UserLocation).options(
            selectinload(UserLocation.location)
        ).where(UserLocation.user_id == user_id)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def remove_user_from_location(
        self,
        user_id: str,
        location_id: str,
        organization_id: str
    ) -> bool:
        """Remove a user from a specific location"""

        # Verify location belongs to organization
        location = await self.get_location_by_id(location_id, organization_id)
        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Remove user location assignment
        stmt = delete(UserLocation).where(
            and_(
                UserLocation.user_id == user_id,
                UserLocation.location_id == location_id
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        deleted_count = result.rowcount
        if deleted_count > 0:
            logger.info(f"Removed user {user_id} from location {location_id}")
            return True

        return False

    async def get_location_users(
        self,
        location_id: str,
        organization_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> Tuple[List[UserLocation], int]:
        """Get all users assigned to a location"""

        # Verify location belongs to organization
        location = await self.get_location_by_id(location_id, organization_id)
        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Location not found"
            )

        # Get total count
        count_stmt = select(func.count(UserLocation.id)).where(UserLocation.location_id == location_id)
        total_result = await self.db.execute(count_stmt)
        total = total_result.scalar()

        # Get user locations with user details
        stmt = select(UserLocation).options(
            selectinload(UserLocation.user)
        ).where(UserLocation.location_id == location_id).offset(skip).limit(limit)

        result = await self.db.execute(stmt)
        user_locations = list(result.scalars().all())

        return user_locations, total

    async def list_locations_with_access_control(
        self,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        organization_id: Optional[str] = None,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Tuple[List[Location], int]:
        """List locations with access control"""

        # Super admin can see all locations
        if is_super_admin:
            stmt = select(Location).options(selectinload(Location.organization))

            # Apply filters
            if organization_id:
                stmt = stmt.where(Location.organization_id == organization_id)
            if is_active is not None:
                stmt = stmt.where(Location.is_active == is_active)
            if search:
                search_pattern = f"%{search}%"
                stmt = stmt.where(
                    Location.name.ilike(search_pattern) |
                    Location.code.ilike(search_pattern) |
                    Location.description.ilike(search_pattern)
                )

            # Get total count
            count_stmt = select(func.count()).select_from(stmt.subquery())
            count_result = await self.db.execute(count_stmt)
            total = count_result.scalar()

            # Apply pagination
            offset = (page - 1) * size
            stmt = stmt.offset(offset).limit(size).order_by(Location.created_at.desc())

            result = await self.db.execute(stmt)
            locations = result.scalars().all()

            return list(locations), total

        # Organization users can only see locations in their organization
        elif user_org_id:
            return await self.list_organization_locations(
                organization_id=user_org_id,
                page=page,
                size=size,
                is_active=is_active,
                search=search
            )

        # No access
        else:
            return [], 0

    async def get_location_with_access_control(
        self,
        location_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Optional[Location]:
        """Get location with access control"""

        location = await self.get_location_by_id(location_id)
        if not location:
            return None

        # Super admin can access any location
        if is_super_admin:
            return location

        # Organization users can only access locations in their organization
        if user_org_id and location.organization_id == user_org_id:
            return location

        # No access
        return None

    async def can_user_manage_location(
        self,
        location_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> bool:
        """Check if a user can manage a location"""

        # Super admin can manage any location
        if is_super_admin:
            return True

        # Get location
        location = await self.get_location_by_id(location_id)
        if not location:
            return False

        # Organization users can only manage locations in their organization
        if user_org_id and location.organization_id == user_org_id:
            return True

        return False

    async def list_organization_locations(
        self,
        organization_id: str,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None
    ) -> Tuple[List[Location], int]:
        """List locations in an organization"""

        # Build query
        stmt = select(Location).where(Location.organization_id == organization_id)

        # Apply filters
        if is_active is not None:
            stmt = stmt.where(Location.is_active == is_active)

        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                Location.name.ilike(search_pattern) |
                Location.code.ilike(search_pattern) |
                Location.description.ilike(search_pattern)
            )

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(Location.created_at.desc())

        result = await self.db.execute(stmt)
        locations = result.scalars().all()

        return list(locations), total
