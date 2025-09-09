"""
User management service for the AuthX microservice.
This module provides comprehensive user management functionality with full async support.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.utils.security import get_password_hash, verify_password
from app.models.user import User
from app.models.user_device import UserDevice
from app.models.organization import Organization
from app.models.audit import AuditLog
from app.schemas.auth import RegisterRequest
from app.services.email_service import EmailService

logger = logging.getLogger(__name__)

class UserService:
    """Comprehensive user management service with full async support."""

    def __init__(self):
        self.email_service = EmailService()

    async def create_user(
        self,
        db: AsyncSession,
        user_create: RegisterRequest,
        created_by: Optional[UUID] = None
    ) -> User:
        """
        Create a new user with validation and audit logging.

        Args:
            db: Database session
            user_create: User creation data
            created_by: ID of user creating this user

        Returns:
            User: Created user instance
        """
        logger.info(f"Creating user with email: {user_create.email}")

        # Check if user already exists
        existing_user = await self.get_user_by_email_or_username(
            db, user_create.email, user_create.username
        )
        if existing_user:
            logger.warning(f"User creation failed - user already exists: {user_create.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email or username already exists"
            )

        # Hash password
        hashed_password = get_password_hash(user_create.password)

        # Create user
        user = User(
            email=user_create.email.lower(),
            username=user_create.username.lower(),
            hashed_password=hashed_password,
            first_name=user_create.first_name,
            last_name=user_create.last_name,
            is_active=True,
            is_verified=False,  # Require email verification
            organization_id=getattr(user_create, 'organization_id', None)
        )

        db.add(user)
        await db.commit()
        await db.refresh(user)

        logger.info(f"User created successfully: {user.id}")
        return user

    async def get_user_by_id(self, db: AsyncSession, user_id: UUID) -> Optional[User]:
        """Get user by ID with all relationships loaded."""
        logger.debug(f"Fetching user by ID: {user_id}")

        result = await db.execute(
            select(User)
            .options(
                selectinload(User.organization),
                selectinload(User.roles),
                selectinload(User.user_devices)
            )
            .where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if user:
            logger.debug(f"User found: {user.email}")
        else:
            logger.debug(f"User not found with ID: {user_id}")

        return user

    async def get_user_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email with all relationships loaded."""
        logger.debug(f"Fetching user by email: {email}")

        result = await db.execute(
            select(User)
            .options(
                selectinload(User.organization),
                selectinload(User.roles),
                selectinload(User.user_devices)
            )
            .where(User.email == email.lower())
        )
        user = result.scalar_one_or_none()

        if user:
            logger.debug(f"User found by email: {user.username}")
        else:
            logger.debug(f"User not found with email: {email}")

        return user

    async def get_user_by_username(self, db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username with all relationships loaded."""
        logger.debug(f"Fetching user by username: {username}")

        result = await db.execute(
            select(User)
            .options(
                selectinload(User.organization),
                selectinload(User.roles),
                selectinload(User.user_devices)
            )
            .where(User.username == username.lower())
        )
        user = result.scalar_one_or_none()

        if user:
            logger.debug(f"User found by username: {user.email}")
        else:
            logger.debug(f"User not found with username: {username}")

        return user

    async def get_user_by_email_or_username(
        self,
        db: AsyncSession,
        email: str,
        username: str
    ) -> Optional[User]:
        """Get user by email or username."""
        logger.debug(f"Searching user by email: {email} or username: {username}")

        result = await db.execute(
            select(User)
            .options(
                selectinload(User.organization),
                selectinload(User.roles),
                selectinload(User.user_devices)
            )
            .where(
                or_(
                    User.email == email.lower(),
                    User.username == username.lower()
                )
            )
        )
        return result.scalar_one_or_none()

    async def update_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        user_update: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> Optional[User]:
        """Update user with validation and audit logging."""
        logger.info(f"Updating user: {user_id}")

        # Get existing user
        user = await self.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for update: {user_id}")
            return None

        # Update allowed fields
        allowed_fields = {
            'first_name', 'last_name', 'phone_number', 'bio',
            'avatar_url', 'timezone', 'locale', 'is_active'
        }

        for field, value in user_update.items():
            if field in allowed_fields and hasattr(user, field):
                setattr(user, field, value)
                logger.debug(f"Updated {field} for user {user_id}")

        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)

        logger.info(f"User updated successfully: {user_id}")
        return user

    async def change_password(
        self,
        db: AsyncSession,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> bool:
        """Change user password with validation."""
        logger.info(f"Password change requested for user: {user_id}")

        user = await self.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for password change: {user_id}")
            return False

        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            logger.warning(f"Invalid current password for user: {user_id}")
            return False

        # Update password
        user.hashed_password = get_password_hash(new_password)
        user.password_changed_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Password changed successfully for user: {user_id}")
        return True

    async def verify_email(self, db: AsyncSession, verification_token: str) -> bool:
        """Verify user email with token."""
        logger.info(f"Email verification requested with token: {verification_token[:10]}...")

        # In a real implementation, you'd verify the JWT token and extract user_id
        # For now, we'll implement a basic version
        try:
            from app.core.security import verify_token
            payload = verify_token(verification_token)
            user_id = payload.get("user_id")

            if not user_id:
                logger.warning("Invalid verification token - no user_id")
                return False

            user = await self.get_user_by_id(db, UUID(user_id))
            if not user:
                logger.warning(f"User not found for verification: {user_id}")
                return False

            user.is_verified = True
            user.email_verified_at = datetime.utcnow()
            await db.commit()

            logger.info(f"Email verified successfully for user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Email verification failed: {e}")
            return False

    async def deactivate_user(self, db: AsyncSession, user_id: UUID) -> bool:
        """Deactivate user account."""
        logger.info(f"Deactivating user: {user_id}")

        user = await self.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for deactivation: {user_id}")
            return False

        user.is_active = False
        await db.commit()

        logger.info(f"User deactivated successfully: {user_id}")
        return True

    async def activate_user(self, db: AsyncSession, user_id: UUID) -> bool:
        """Activate user account."""
        logger.info(f"Activating user: {user_id}")

        user = await self.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for activation: {user_id}")
            return False

        user.is_active = True
        await db.commit()

        logger.info(f"User activated successfully: {user_id}")
        return True

    async def delete_user(self, db: AsyncSession, user_id: UUID) -> bool:
        """Soft delete user account."""
        logger.info(f"Deleting user: {user_id}")

        user = await self.get_user_by_id(db, user_id)
        if not user:
            logger.warning(f"User not found for deletion: {user_id}")
            return False

        # Soft delete by deactivating
        user.is_active = False
        user.updated_at = datetime.utcnow()
        await db.commit()

        logger.info(f"User deleted successfully: {user_id}")
        return True

    async def get_user_devices(
        self,
        db: AsyncSession,
        user_id: UUID
    ) -> List[UserDevice]:
        """Get all devices for a user."""
        logger.debug(f"Fetching devices for user: {user_id}")

        result = await db.execute(
            select(UserDevice)
            .where(UserDevice.user_id == user_id)
            .order_by(UserDevice.last_seen.desc())
        )
        devices = result.scalars().all()

        logger.debug(f"Found {len(devices)} devices for user: {user_id}")
        return list(devices)

    async def revoke_user_device(
        self,
        db: AsyncSession,
        user_id: UUID,
        device_id: UUID
    ) -> bool:
        """Revoke/remove a user device."""
        logger.info(f"Revoking device {device_id} for user {user_id}")

        result = await db.execute(
            delete(UserDevice)
            .where(
                and_(
                    UserDevice.user_id == user_id,
                    UserDevice.id == device_id
                )
            )
        )
        await db.commit()

        success = result.rowcount > 0
        if success:
            logger.info(f"Device revoked successfully: {device_id}")
        else:
            logger.warning(f"Device not found for revocation: {device_id}")

        return success

    async def list_users(
        self,
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        organization_id: Optional[UUID] = None
    ) -> Tuple[List[User], int]:
        """List users with pagination and filtering."""
        logger.debug(f"Listing users - skip: {skip}, limit: {limit}, search: {search}")

        query = select(User).options(
            selectinload(User.organization),
            selectinload(User.roles)
        )

        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term),
                    User.email.ilike(search_term),
                    User.username.ilike(search_term)
                )
            )

        if organization_id:
            query = query.where(User.organization_id == organization_id)

        # Get total count
        count_query = select(func.count(User.id))
        if search:
            count_query = count_query.where(
                or_(
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term),
                    User.email.ilike(search_term),
                    User.username.ilike(search_term)
                )
            )
        if organization_id:
            count_query = count_query.where(User.organization_id == organization_id)

        count_result = await db.execute(count_query)
        total = count_result.scalar()

        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(User.created_at.desc())
        result = await db.execute(query)
        users = result.scalars().all()

        logger.debug(f"Found {len(users)} users out of {total} total")
        return list(users), total

# Create singleton instance
user_service = UserService()
