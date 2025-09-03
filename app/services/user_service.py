"""
User management service for the AuthX microservice.
This module provides comprehensive user management functionality.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.utils.security import get_password_hash, verify_password
from app.core.utils import validate_password, generate_correlation_id
from app.db.session import get_async_db
from app.models.user import User
from app.models.user_device import UserDevice
from app.models.organization import Organization
from app.models.audit import AuditLog
from app.schemas.user import UserCreate, UserUpdate, UserResponse
from app.services.email_service import EmailService

class UserService:
    """Comprehensive user management service."""

    def __init__(self):
        self.email_service = EmailService()

    async def create_user(
        self,
        db: AsyncSession,
        user_create: UserCreate,
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
        # Validate password
        password_validation = validate_password(user_create.password)
        if not password_validation['valid']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Check if user already exists
        existing_user = await self.get_user_by_email_or_username(
            db, user_create.email, user_create.username
        )
        if existing_user:
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
            phone_number=user_create.phone_number,
            bio=user_create.bio,
            avatar_url=user_create.avatar_url,
            timezone=user_create.timezone,
            locale=user_create.locale,
            organization_id=user_create.organization_id,
            is_active=user_create.is_active
        )

        db.add(user)
        await db.commit()
        await db.refresh(user)

        # Log user creation
        await self._log_user_action(
            db, user.id, created_by, "create", "success",
            f"User {user.email} created successfully"
        )

        # Send verification email if needed
        if not user.is_verified:
            verification_token = await self._generate_verification_token(db, user.id)
            await self.email_service.send_verification_email(
                user.email, user.full_name, verification_token
            )

        return user

    async def get_user_by_id(
        self,
        db: AsyncSession,
        user_id: UUID,
        include_organization: bool = False
    ) -> Optional[User]:
        """Get user by ID with optional organization data."""
        query = select(User).where(User.id == user_id)

        if include_organization:
            query = query.options(selectinload(User.organization))

        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_user_by_email_or_username(
        self,
        db: AsyncSession,
        email: str,
        username: str
    ) -> Optional[User]:
        """Get user by email or username."""
        result = await db.execute(
            select(User).where(
                or_(User.email == email.lower(), User.username == username.lower())
            )
        )
        return result.scalar_one_or_none()

    async def update_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        user_update: UserUpdate,
        updated_by: Optional[UUID] = None
    ) -> User:
        """Update user with validation and audit logging."""
        user = await self.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check for email/username conflicts
        if user_update.email or user_update.username:
            existing_user = await db.execute(
                select(User).where(
                    and_(
                        User.id != user_id,
                        or_(
                            User.email == (user_update.email or user.email).lower(),
                            User.username == (user_update.username or user.username).lower()
                        )
                    )
                )
            )
            if existing_user.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email or username already in use"
                )

        # Update fields
        update_data = user_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field in ['email', 'username'] and value:
                value = value.lower()
            setattr(user, field, value)

        await db.commit()
        await db.refresh(user)

        # Log update
        await self._log_user_action(
            db, user.id, updated_by, "update", "success",
            f"User {user.email} updated successfully"
        )

        return user

    async def delete_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        deleted_by: Optional[UUID] = None
    ) -> bool:
        """Soft delete user (deactivate) with audit logging."""
        user = await self.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Soft delete by deactivating
        user.is_active = False
        await db.commit()

        # Log deletion
        await self._log_user_action(
            db, user.id, deleted_by, "delete", "success",
            f"User {user.email} deactivated"
        )

        return True

    async def list_users(
        self,
        db: AsyncSession,
        organization_id: Optional[UUID] = None,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[List[User], int]:
        """List users with filtering and pagination."""
        query = select(User)
        count_query = select(func.count(User.id))

        # Apply filters
        if organization_id:
            query = query.where(User.organization_id == organization_id)
            count_query = count_query.where(User.organization_id == organization_id)

        if is_active is not None:
            query = query.where(User.is_active == is_active)
            count_query = count_query.where(User.is_active == is_active)

        if search:
            search_filter = or_(
                User.email.ilike(f"%{search}%"),
                User.username.ilike(f"%{search}%"),
                User.first_name.ilike(f"%{search}%"),
                User.last_name.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)

        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Get users with pagination
        query = query.offset(skip).limit(limit).order_by(User.created_at.desc())
        result = await db.execute(query)
        users = result.scalars().all()

        return list(users), total

    async def activate_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        activated_by: Optional[UUID] = None
    ) -> User:
        """Activate a user account."""
        user = await self.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user.is_active = True
        await db.commit()

        await self._log_user_action(
            db, user.id, activated_by, "activate", "success",
            f"User {user.email} activated"
        )

        return user

    async def deactivate_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        deactivated_by: Optional[UUID] = None
    ) -> User:
        """Deactivate a user account."""
        user = await self.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user.is_active = False
        await db.commit()

        await self._log_user_action(
            db, user.id, deactivated_by, "deactivate", "success",
            f"User {user.email} deactivated"
        )

        return user

    async def verify_email(
        self,
        db: AsyncSession,
        verification_token: str
    ) -> bool:
        """Verify user email with token."""
        # In a real implementation, you'd store and validate tokens
        # For now, we'll implement a basic version
        try:
            from app.core.security import verify_token
            payload = verify_token(verification_token)
            user_id = payload.get("user_id")

            if not user_id:
                return False

            user = await self.get_user_by_id(db, UUID(user_id))
            if not user:
                return False

            user.is_verified = True
            user.email_verified_at = datetime.utcnow()
            await db.commit()

            await self._log_user_action(
                db, user.id, None, "verify_email", "success",
                f"Email verified for user {user.email}"
            )

            return True

        except Exception:
            return False

    async def get_user_devices(
        self,
        db: AsyncSession,
        user_id: UUID
    ) -> List[UserDevice]:
        """Get all devices for a user."""
        result = await db.execute(
            select(UserDevice)
            .where(UserDevice.user_id == user_id)
            .order_by(UserDevice.last_seen.desc())
        )
        return list(result.scalars().all())

    async def revoke_user_device(
        self,
        db: AsyncSession,
        user_id: UUID,
        device_id: UUID
    ) -> bool:
        """Revoke/deactivate a user device."""
        result = await db.execute(
            select(UserDevice).where(
                and_(
                    UserDevice.user_id == user_id,
                    UserDevice.id == device_id
                )
            )
        )
        device = result.scalar_one_or_none()

        if not device:
            return False

        device.is_active = False
        await db.commit()

        await self._log_user_action(
            db, user_id, user_id, "revoke_device", "success",
            f"Device {device_id} revoked for user {user_id}"
        )

        return True

    async def get_user_statistics(
        self,
        db: AsyncSession,
        organization_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Get user statistics."""
        base_query = select(func.count(User.id))

        if organization_id:
            base_query = base_query.where(User.organization_id == organization_id)

        # Total users
        total_result = await db.execute(base_query)
        total_users = total_result.scalar()

        # Active users
        active_result = await db.execute(
            base_query.where(User.is_active == True)
        )
        active_users = active_result.scalar()

        # Verified users
        verified_result = await db.execute(
            base_query.where(User.is_verified == True)
        )
        verified_users = verified_result.scalar()

        # Users with MFA
        mfa_result = await db.execute(
            base_query.where(User.mfa_enabled == True)
        )
        mfa_enabled_users = mfa_result.scalar()

        # Recent registrations (last 30 days)
        recent_result = await db.execute(
            base_query.where(
                User.created_at >= datetime.utcnow() - timedelta(days=30)
            )
        )
        recent_registrations = recent_result.scalar()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "verified_users": verified_users,
            "mfa_enabled_users": mfa_enabled_users,
            "recent_registrations": recent_registrations,
            "verification_rate": (verified_users / total_users * 100) if total_users > 0 else 0,
            "mfa_adoption_rate": (mfa_enabled_users / total_users * 100) if total_users > 0 else 0
        }

    async def _generate_verification_token(
        self,
        db: AsyncSession,
        user_id: UUID
    ) -> str:
        """Generate email verification token."""
        from app.core.security import create_access_token

        token_data = {
            "user_id": str(user_id),
            "type": "email_verification"
        }

        return create_access_token(
            data=token_data,
            expires_delta=timedelta(hours=24)
        )

    async def _log_user_action(
        self,
        db: AsyncSession,
        user_id: UUID,
        performed_by: Optional[UUID],
        action: str,
        status: str,
        description: str
    ):
        """Log user management action."""
        audit_log = AuditLog(
            user_id=performed_by,
            event_type="user_management",
            resource_type="user",
            resource_id=str(user_id),
            action=action,
            status=status,
            description=description,
            source="api"
        )
        db.add(audit_log)
        await db.commit()

# Global user service instance
user_service = UserService()
