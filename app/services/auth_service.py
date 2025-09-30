"""
Authentication service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from typing import Optional, Tuple
from app.models import User, Organization, RefreshToken, PasswordResetToken, AuditLog
from app.schemas import UserCreate, LoginRequest
from app.security import (
    hash_password, verify_password, create_access_token,
    create_refresh_token, create_reset_token, create_token_data,
    generate_token
)
from fastapi import HTTPException, status
import logging
import json

logger = logging.getLogger(__name__)


class AuthService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register_user(
        self,
        user_data: UserCreate,
        organization_id: Optional[str] = None,
        created_by_user_id: Optional[str] = None
    ) -> User:
        """Register a new user"""

        # Check if user already exists
        stmt = select(User).where(User.email == user_data.email)
        existing_user = await self.db.execute(stmt)
        if existing_user.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # If organization_id provided, validate it
        if organization_id:
            org_stmt = select(Organization).where(
                and_(Organization.id == organization_id, Organization.is_active == True)
            )
            org_result = await self.db.execute(org_stmt)
            organization = org_result.scalar_one_or_none()
            if not organization:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Organization not found or inactive"
                )

            # Check username uniqueness within organization
            username_stmt = select(User).where(
                and_(
                    User.username == user_data.username,
                    User.organization_id == organization_id
                )
            )
            username_result = await self.db.execute(username_stmt)
            if username_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists in this organization"
                )

        # Create new user
        user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=hash_password(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            organization_id=organization_id,
            is_verified=False  # Require email verification
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        # Log the registration
        await self._log_audit(
            user_id=user.id,
            organization_id=organization_id,
            action="user_register",
            resource="user",
            resource_id=user.id,
            status="success",
            details=json.dumps({
                "email": user.email,
                "created_by": created_by_user_id
            })
        )

        logger.info(f"User registered: {user.email}")
        return user

    async def authenticate_user(
        self,
        login_data: LoginRequest,
        ip_address: str,
        user_agent: str
    ) -> Tuple[User, str, str]:
        """Authenticate user and return user with tokens"""

        # Find user by email
        stmt = select(User).options(selectinload(User.organization)).where(User.email == login_data.email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            await self._log_audit(
                action="login_failed",
                resource="user",
                status="failure",
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps({"reason": "user_not_found", "email": login_data.email})
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if organization slug matches (if provided)
        if login_data.organization_slug:
            if not user.organization or user.organization.slug != login_data.organization_slug:
                await self._log_audit(
                    user_id=user.id,
                    organization_id=user.organization_id,
                    action="login_failed",
                    resource="user",
                    status="failure",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details=json.dumps({"reason": "organization_mismatch"})
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials"
                )

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            await self._log_audit(
                user_id=user.id,
                organization_id=user.organization_id,
                action="login_failed",
                resource="user",
                status="failure",
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps({"reason": "account_locked"})
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked due to failed login attempts"
            )

        # Verify password
        if not verify_password(login_data.password, user.password_hash):
            # Increment failed login attempts
            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)

            await self.db.commit()

            await self._log_audit(
                user_id=user.id,
                organization_id=user.organization_id,
                action="login_failed",
                resource="user",
                status="failure",
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps({"reason": "invalid_password", "attempts": user.failed_login_attempts})
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if user is active
        if not user.is_active:
            await self._log_audit(
                user_id=user.id,
                organization_id=user.organization_id,
                action="login_failed",
                resource="user",
                status="failure",
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps({"reason": "account_inactive"})
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive"
            )

        # Check if organization is active (if user belongs to one)
        if user.organization and not user.organization.is_active:
            await self._log_audit(
                user_id=user.id,
                organization_id=user.organization_id,
                action="login_failed",
                resource="user",
                status="failure",
                ip_address=ip_address,
                user_agent=user_agent,
                details=json.dumps({"reason": "organization_inactive"})
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Organization is inactive"
            )

        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()

        # Create tokens
        token_data = create_token_data(
            user_id=user.id,
            email=user.email,
            org_id=user.organization_id,
            is_super_admin=user.is_super_admin
        )

        access_token = create_access_token(token_data)
        refresh_token_str, refresh_expires_at = create_refresh_token(user.id)

        # Store refresh token
        refresh_token = RefreshToken(
            token=refresh_token_str,
            user_id=user.id,
            expires_at=refresh_expires_at
        )
        self.db.add(refresh_token)

        await self.db.commit()
        await self.db.refresh(user)

        # Log successful login
        await self._log_audit(
            user_id=user.id,
            organization_id=user.organization_id,
            action="login_success",
            resource="user",
            status="success",
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps({"login_time": datetime.utcnow().isoformat()})
        )

        logger.info(f"User authenticated: {user.email}")
        return user, access_token, refresh_token_str

    async def refresh_access_token(self, refresh_token: str) -> Tuple[str, str]:
        """Refresh access token using refresh token"""

        # Find refresh token
        stmt = select(RefreshToken).options(selectinload(RefreshToken.user)).where(
            and_(
                RefreshToken.token == refresh_token,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.utcnow()
            )
        )
        result = await self.db.execute(stmt)
        token_record = result.scalar_one_or_none()

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

        user = token_record.user
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive"
            )

        # Create new access token
        token_data = create_token_data(
            user_id=user.id,
            email=user.email,
            org_id=user.organization_id,
            is_super_admin=user.is_super_admin
        )

        new_access_token = create_access_token(token_data)

        # Create new refresh token and revoke old one
        new_refresh_token, new_expires_at = create_refresh_token(user.id)

        # Revoke old refresh token
        token_record.is_revoked = True

        # Create new refresh token record
        new_token_record = RefreshToken(
            token=new_refresh_token,
            user_id=user.id,
            expires_at=new_expires_at
        )
        self.db.add(new_token_record)

        await self.db.commit()

        return new_access_token, new_refresh_token

    async def logout_user(self, user_id: str, refresh_token: Optional[str] = None):
        """Logout user and revoke refresh tokens"""

        if refresh_token:
            # Revoke specific refresh token
            stmt = update(RefreshToken).where(
                and_(
                    RefreshToken.token == refresh_token,
                    RefreshToken.user_id == user_id
                )
            ).values(is_revoked=True)
        else:
            # Revoke all refresh tokens for user
            stmt = update(RefreshToken).where(
                RefreshToken.user_id == user_id
            ).values(is_revoked=True)

        await self.db.execute(stmt)
        await self.db.commit()

        # Log logout
        await self._log_audit(
            user_id=user_id,
            action="logout",
            resource="user",
            status="success"
        )

        logger.info(f"User logged out: {user_id}")

    async def request_password_reset(self, email: str, organization_slug: Optional[str] = None) -> str:
        """Request password reset and return reset token"""

        # Find user
        stmt = select(User).options(selectinload(User.organization)).where(User.email == email)
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal that user doesn't exist
            logger.warning(f"Password reset requested for non-existent email: {email}")
            return generate_token()  # Return dummy token

        # Check organization if specified
        if organization_slug:
            if not user.organization or user.organization.slug != organization_slug:
                logger.warning(f"Password reset requested with wrong organization: {email}")
                return generate_token()  # Return dummy token

        # Create reset token
        reset_token, expires_at = create_reset_token(email)

        # Store reset token
        reset_token_record = PasswordResetToken(
            token=reset_token,
            email=email,
            expires_at=expires_at
        )
        self.db.add(reset_token_record)
        await self.db.commit()

        # Log password reset request
        await self._log_audit(
            user_id=user.id,
            organization_id=user.organization_id,
            action="password_reset_requested",
            resource="user",
            status="success"
        )

        logger.info(f"Password reset requested: {email}")
        return reset_token

    async def reset_password(self, token: str, new_password: str) -> User:
        """Reset password using reset token"""

        # Find valid reset token
        stmt = select(PasswordResetToken).where(
            and_(
                PasswordResetToken.token == token,
                PasswordResetToken.is_used == False,
                PasswordResetToken.expires_at > datetime.utcnow()
            )
        )
        result = await self.db.execute(stmt)
        reset_token = result.scalar_one_or_none()

        if not reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )

        # Find user
        user_stmt = select(User).where(User.email == reset_token.email)
        user_result = await self.db.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Update password
        user.password_hash = hash_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None

        # Mark reset token as used
        reset_token.is_used = True

        # Revoke all refresh tokens for security
        revoke_stmt = update(RefreshToken).where(
            RefreshToken.user_id == user.id
        ).values(is_revoked=True)
        await self.db.execute(revoke_stmt)

        await self.db.commit()
        await self.db.refresh(user)

        # Log password reset
        await self._log_audit(
            user_id=user.id,
            organization_id=user.organization_id,
            action="password_reset_completed",
            resource="user",
            status="success"
        )

        logger.info(f"Password reset completed: {user.email}")
        return user

    async def _log_audit(
        self,
        action: str,
        resource: str,
        status: str,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[str] = None
    ):
        """Create audit log entry"""

        audit_log = AuditLog(
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            status=status
        )

        self.db.add(audit_log)
        # Note: We don't commit here to allow batching with main operation
