"""
User Location Access Service for AuthX system.
Manages user access to locations within organizations.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from app.models.user import User
from app.models.location import Location
from app.models.user_location_access import UserLocationAccess
from app.schemas.user_location_access import (
    UserLocationAccessCreate,
    UserLocationAccessUpdate,
    GrantLocationAccessRequest,
    RevokeLocationAccessRequest
)


class UserLocationAccessService:
    """Service for managing user location access."""

    async def grant_location_access(
        self,
        db: AsyncSession,
        request: GrantLocationAccessRequest,
        granted_by: UUID,
        organization_id: UUID
    ) -> List[UserLocationAccess]:
        """Grant location access to multiple users for multiple locations."""
        # Verify all users belong to the organization
        user_query = select(User).where(
            and_(
                User.id.in_(request.user_ids),
                User.organization_id == organization_id,
                User.is_active == True
            )
        )
        result = await db.execute(user_query)
        users = result.scalars().all()

        if len(users) != len(request.user_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more users not found or don't belong to the organization"
            )

        # Verify all locations belong to the organization
        location_query = select(Location).where(
            and_(
                Location.id.in_(request.location_ids),
                Location.organization_id == organization_id,
                Location.is_active == True
            )
        )
        result = await db.execute(location_query)
        locations = result.scalars().all()

        if len(locations) != len(request.location_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more locations not found or don't belong to the organization"
            )

        created_accesses = []

        for user_id in request.user_ids:
            for location_id in request.location_ids:
                # Check if access already exists
                existing_query = select(UserLocationAccess).where(
                    and_(
                        UserLocationAccess.user_id == user_id,
                        UserLocationAccess.location_id == location_id,
                        UserLocationAccess.organization_id == organization_id
                    )
                )
                result = await db.execute(existing_query)
                existing_access = result.scalar_one_or_none()

                if existing_access:
                    # Update existing access
                    existing_access.can_read = request.can_read
                    existing_access.can_write = request.can_write
                    existing_access.can_delete = request.can_delete
                    existing_access.can_manage = request.can_manage
                    existing_access.access_expires_at = request.access_expires_at
                    existing_access.is_active = True
                    existing_access.notes = request.notes
                    existing_access.granted_by = granted_by
                    existing_access.access_granted_at = datetime.utcnow()
                    created_accesses.append(existing_access)
                else:
                    # Create new access
                    access_data = UserLocationAccessCreate(
                        user_id=user_id,
                        location_id=location_id,
                        can_read=request.can_read,
                        can_write=request.can_write,
                        can_delete=request.can_delete,
                        can_manage=request.can_manage,
                        access_expires_at=request.access_expires_at,
                        notes=request.notes,
                        granted_by=granted_by
                    )

                    new_access = UserLocationAccess(
                        organization_id=organization_id,
                        **access_data.model_dump()
                    )
                    db.add(new_access)
                    created_accesses.append(new_access)

        await db.commit()
        return created_accesses

    async def revoke_location_access(
        self,
        db: AsyncSession,
        request: RevokeLocationAccessRequest,
        revoked_by: UUID,
        organization_id: UUID
    ) -> int:
        """Revoke location access for multiple users from multiple locations."""
        # Find all matching access records
        query = select(UserLocationAccess).where(
            and_(
                UserLocationAccess.user_id.in_(request.user_ids),
                UserLocationAccess.location_id.in_(request.location_ids),
                UserLocationAccess.organization_id == organization_id,
                UserLocationAccess.is_active == True
            )
        )
        result = await db.execute(query)
        access_records = result.scalars().all()

        revoked_count = 0
        for access in access_records:
            access.is_active = False
            access.notes = f"Revoked by admin. Reason: {request.reason or 'No reason provided'}"
            revoked_count += 1

        await db.commit()
        return revoked_count

    async def get_user_location_accesses(
        self,
        db: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
        include_expired: bool = False
    ) -> List[UserLocationAccess]:
        """Get all location accesses for a specific user."""
        query = select(UserLocationAccess).options(
            selectinload(UserLocationAccess.location),
            selectinload(UserLocationAccess.granter)
        ).where(
            and_(
                UserLocationAccess.user_id == user_id,
                UserLocationAccess.organization_id == organization_id
            )
        )

        if not include_expired:
            query = query.where(
                and_(
                    UserLocationAccess.is_active == True,
                    or_(
                        UserLocationAccess.access_expires_at.is_(None),
                        UserLocationAccess.access_expires_at > datetime.utcnow()
                    )
                )
            )

        result = await db.execute(query)
        return result.scalars().all()

    async def get_location_user_accesses(
        self,
        db: AsyncSession,
        location_id: UUID,
        organization_id: UUID,
        include_expired: bool = False
    ) -> List[UserLocationAccess]:
        """Get all user accesses for a specific location."""
        query = select(UserLocationAccess).options(
            selectinload(UserLocationAccess.user),
            selectinload(UserLocationAccess.granter)
        ).where(
            and_(
                UserLocationAccess.location_id == location_id,
                UserLocationAccess.organization_id == organization_id
            )
        )

        if not include_expired:
            query = query.where(
                and_(
                    UserLocationAccess.is_active == True,
                    or_(
                        UserLocationAccess.access_expires_at.is_(None),
                        UserLocationAccess.access_expires_at > datetime.utcnow()
                    )
                )
            )

        result = await db.execute(query)
        return result.scalars().all()

    async def check_user_location_access(
        self,
        db: AsyncSession,
        user_id: UUID,
        location_id: UUID,
        organization_id: UUID,
        permission: str = "read"
    ) -> bool:
        """Check if user has specific permission for a location."""
        query = select(UserLocationAccess).where(
            and_(
                UserLocationAccess.user_id == user_id,
                UserLocationAccess.location_id == location_id,
                UserLocationAccess.organization_id == organization_id,
                UserLocationAccess.is_active == True,
                or_(
                    UserLocationAccess.access_expires_at.is_(None),
                    UserLocationAccess.access_expires_at > datetime.utcnow()
                )
            )
        )

        result = await db.execute(query)
        access = result.scalar_one_or_none()

        if not access:
            return False

        permission_map = {
            "read": access.can_read,
            "write": access.can_write,
            "delete": access.can_delete,
            "manage": access.can_manage
        }

        return permission_map.get(permission, False)

    async def get_accessible_locations_for_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
        permission: str = "read"
    ) -> List[Location]:
        """Get all locations that a user has access to."""
        query = select(Location).join(UserLocationAccess).where(
            and_(
                UserLocationAccess.user_id == user_id,
                UserLocationAccess.organization_id == organization_id,
                UserLocationAccess.is_active == True,
                Location.is_active == True,
                or_(
                    UserLocationAccess.access_expires_at.is_(None),
                    UserLocationAccess.access_expires_at > datetime.utcnow()
                )
            )
        )

        # Add permission filter
        if permission == "write":
            query = query.where(UserLocationAccess.can_write == True)
        elif permission == "delete":
            query = query.where(UserLocationAccess.can_delete == True)
        elif permission == "manage":
            query = query.where(UserLocationAccess.can_manage == True)
        else:  # default to read
            query = query.where(UserLocationAccess.can_read == True)

        result = await db.execute(query)
        return result.scalars().all()


# Create service instance
user_location_access_service = UserLocationAccessService()
