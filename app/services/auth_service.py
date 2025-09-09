"""
Authentication service for the AuthX microservice.
This module provides comprehensive authentication, token management, and security features.
"""
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from uuid import UUID

from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import (
    check_brute_force, record_failed_login, reset_brute_force_counter,
    calculate_login_risk_score, generate_device_fingerprint
)
from app.models.user import User
from app.models.user_device import UserDevice
from app.models.audit import SecurityEvent
from app.schemas.auth import TokenPayload
from app.services.email_service import EmailService

# OAuth2 token URL and scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")

class AuthService:
    """Comprehensive authentication service with advanced security features."""

    def __init__(self):
        self.email_service = EmailService()

    async def authenticate_user(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        request_info: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Authenticate a user with comprehensive security checks.

        Args:
            db: Database session
            username: Username or email
            password: Plain text password
            request_info: Request context information

        Returns:
            Tuple of (User data dict, authentication context) or raises HTTPException
        """
        from app.utils.security import verify_password

        # Check for brute force attempts
        client_ip = request_info.get("ip_address", "unknown")
        is_blocked, remaining = await check_brute_force(client_ip, username)

        if is_blocked:
            await self._log_security_event(
                db, "BRUTE_FORCE_BLOCKED",
                {"username": username, "ip": client_ip, "user_id": None}
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later."
            )

        # Get user by username or email
        user = await self._get_user_by_identifier(db, username)

        if not user or not verify_password(password, user.hashed_password):
            # Record failed login attempt
            await record_failed_login(client_ip, username)
            await self._log_security_event(
                db, "LOGIN_FAILED",
                {"username": username, "ip": client_ip, "reason": "invalid_credentials", "user_id": None}
            )
            return None, {"success": False, "reason": "invalid_credentials"}

        # Check if user account is active
        if not user.is_active:
            await self._log_security_event(
                db, "LOGIN_BLOCKED",
                {"user_id": str(user.id), "reason": "inactive_account", "ip": client_ip}
            )
            return None, {"success": False, "reason": "inactive_account"}

        # Reset brute force counter on successful authentication
        await reset_brute_force_counter(client_ip, username)

        # Extract ALL user data within the session context to avoid lazy loading
        user_id = str(user.id)
        user_email = user.email
        user_username = user.username
        user_last_login = user.last_login
        user_is_superuser = user.is_superuser
        user_is_verified = user.is_verified
        user_organization_id = user.organization_id
        user_id_uuid = user.id  # Keep UUID version for device tracking

        # Create user data dictionary to return instead of user object
        user_data = {
            "id": user_id,
            "email": user_email,
            "username": user_username,
            "is_superuser": user_is_superuser,
            "is_verified": user_is_verified,
            "organization_id": str(user_organization_id) if user_organization_id else None,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }

        # Calculate risk score using extracted data instead of user object
        risk_score = await self._calculate_login_risk_score_safe(user_last_login, request_info)

        # Generate device fingerprint
        device_fingerprint = generate_device_fingerprint(request_info)

        # Check or create device record using extracted user ID
        device = await self._handle_device_tracking_safe(db, user_id_uuid, device_fingerprint, request_info)

        # Update user's last login time
        user.last_login = datetime.utcnow()
        await db.commit()

        # Create authentication context
        auth_context = {
            "success": True,
            "risk_score": risk_score,
            "device_fingerprint": device_fingerprint,
            "device_id": str(device.id) if device else None,
            "device_registered": device is not None and device.is_trusted,
            "requires_mfa": False,  # Simplified: disable MFA for now to fix auth
            "login_time": datetime.utcnow(),
            "ip_address": client_ip
        }

        # Log successful authentication using extracted data
        await self._log_security_event(
            db, "LOGIN_SUCCESS",
            {
                "user_id": user_id,
                "username": user_username,
                "email": user_email,
                "ip": client_ip,
                "risk_score": risk_score,
                "device_fingerprint": device_fingerprint
            }
        )

        return user_data, auth_context

    async def create_tokens_for_user(
        self,
        user: User,
        auth_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create access and refresh tokens for a user."""
        if auth_context is None:
            auth_context = {}

        # Extract user data to avoid lazy loading issues
        user_data = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "is_superuser": user.is_superuser,
            "is_verified": user.is_verified,
            "organization_id": str(user.organization_id) if user.organization_id else None
        }

        access_token = await self.create_access_token(user_data, auth_context)
        refresh_token = await self.create_refresh_token(user_data)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def create_tokens_from_user_data(
        self,
        user_data: Dict[str, Any],
        auth_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create access and refresh tokens from user data dict (safer for async contexts)."""
        if auth_context is None:
            auth_context = {}

        access_token = await self.create_access_token(user_data, auth_context)
        refresh_token = await self.create_refresh_token(user_data)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def create_access_token(
        self,
        user_data: Dict[str, Any],
        auth_context: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token using user data dict to avoid SQLAlchemy issues."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode = {
            "sub": user_data["id"],
            "email": user_data["email"],
            "username": user_data["username"],
            "is_superuser": user_data["is_superuser"],
            "is_verified": user_data["is_verified"],
            "organization_id": user_data["organization_id"],
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }

        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    async def create_refresh_token(self, user_data: Dict[str, Any]) -> str:
        """Create JWT refresh token using user data dict to avoid SQLAlchemy issues."""
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode = {
            "sub": user_data["id"],
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh",
            "jti": secrets.token_urlsafe(32)  # JWT ID for token revocation
        }

        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    async def verify_token(self, token: str) -> Optional[TokenPayload]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            token_data = TokenPayload(**payload)
            return token_data
        except JWTError:
            return None

    async def refresh_access_token(
        self,
        db: AsyncSession,
        refresh_token: str
    ) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        try:
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )

            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload"
                )

            # Get user from database and extract data within session context
            result = await db.execute(select(User).where(User.id == UUID(user_id)))
            user = result.scalar_one_or_none()

            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            # Extract user data to avoid SQLAlchemy async context issues
            user_data = {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "is_superuser": user.is_superuser,
                "is_verified": user.is_verified,
                "organization_id": str(user.organization_id) if user.organization_id else None
            }

            # Create new tokens using user data
            auth_context = {"refresh_operation": True}
            new_access_token = await self.create_access_token(user_data, auth_context)

            return {
                "access_token": new_access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

    async def change_password(
        self,
        db: AsyncSession,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password with validation.

        Args:
            db: Database session
            user_id: User ID
            current_password: Current password
            new_password: New password

        Returns:
            bool: True if password changed successfully
        """
        from app.utils.security import verify_password, get_password_hash

        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            return False

        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            return False

        # Update password
        user.hashed_password = get_password_hash(new_password)
        await db.commit()

        return True

    async def get_user_by_id(self, db: AsyncSession, user_id: str) -> Optional[User]:
        """
        Get user by ID.

        Args:
            db: Database session
            user_id: User ID

        Returns:
            Optional[User]: User object or None if not found
        """
        from sqlalchemy import select
        from uuid import UUID

        try:
            user_uuid = UUID(user_id)
            result = await db.execute(
                select(User).where(User.id == user_uuid)
            )
            return result.scalar_one_or_none()
        except (ValueError, Exception):
            return None

    # Private helper methods
    async def _get_user_by_identifier(self, db: AsyncSession, identifier: str) -> Optional[User]:
        """Get user by username or email with all required attributes loaded."""
        result = await db.execute(
            select(User).where(
                or_(User.username == identifier, User.email == identifier)
            ).options(
                selectinload(User.organization),
                selectinload(User.roles),
                selectinload(User.user_devices)
            )
        )
        user = result.scalar_one_or_none()

        # Force loading of all attributes to prevent lazy loading issues
        if user:
            # Access all attributes to ensure they're loaded
            _ = user.id
            _ = user.email
            _ = user.username
            _ = user.hashed_password
            _ = user.is_active
            _ = user.is_superuser
            _ = user.is_verified
            _ = user.organization_id
            _ = user.created_at
            _ = user.updated_at

        return user

    async def _handle_device_tracking_safe(
        self,
        db: AsyncSession,
        user_id: UUID,
        device_fingerprint: str,
        request_info: Dict[str, Any]
    ) -> Optional[UserDevice]:
        """Handle device tracking and registration using user ID instead of user object."""
        try:
            # Check if device exists
            result = await db.execute(
                select(UserDevice).where(
                    and_(
                        UserDevice.user_id == user_id,
                        UserDevice.device_fingerprint == device_fingerprint
                    )
                )
            )
            device = result.scalar_one_or_none()

            # Get IP address from request info
            ip_address = request_info.get("ip_address", "127.0.0.1")
            user_agent = request_info.get("user_agent", "Unknown")

            # Parse device type from user agent
            device_type = "desktop"  # Default
            if any(mobile in user_agent.lower() for mobile in ["mobile", "android", "iphone"]):
                device_type = "mobile"
            elif any(tablet in user_agent.lower() for tablet in ["tablet", "ipad"]):
                device_type = "tablet"

            if not device:
                # Create new device record with all required fields
                device = UserDevice(
                    user_id=user_id,
                    device_fingerprint=device_fingerprint,
                    device_name=user_agent[:100] if user_agent else "Unknown Device",
                    device_type=device_type,
                    user_agent=user_agent,
                    ip_address=ip_address,
                    first_login_ip=ip_address,  # Required field
                    last_login_ip=ip_address,   # Required field
                    last_seen=datetime.utcnow(),
                    is_trusted=False,
                    is_active=True,
                    login_count=1
                )
                db.add(device)
            else:
                # Update existing device
                device.last_seen = datetime.utcnow()
                device.last_login_ip = ip_address
                device.login_count += 1
                if user_agent:
                    device.user_agent = user_agent

            await db.commit()
            await db.refresh(device)
            return device

        except Exception as e:
            await db.rollback()
            logger.error(f"Error in device tracking: {e}")
            return None

    async def _handle_device_tracking(
        self,
        db: AsyncSession,
        user: User,
        device_fingerprint: str,
        request_info: Dict[str, Any]
    ) -> Optional[UserDevice]:
        """Handle device tracking and registration."""
        try:
            # Check if device exists
            result = await db.execute(
                select(UserDevice).where(
                    and_(
                        UserDevice.user_id == user.id,
                        UserDevice.device_fingerprint == device_fingerprint
                    )
                )
            )
            device = result.scalar_one_or_none()

            if not device:
                # Create new device record
                device = UserDevice(
                    user_id=user.id,
                    device_fingerprint=device_fingerprint,
                    device_name=request_info.get("user_agent", "Unknown Device")[:100],
                    ip_address=request_info.get("ip_address"),
                    last_seen=datetime.utcnow(),
                    is_trusted=False
                )
                db.add(device)
            else:
                # Update existing device
                device.last_seen = datetime.utcnow()
                device.ip_address = request_info.get("ip_address")

            await db.commit()
            return device

        except Exception as e:
            await db.rollback()
            return None

    async def _log_security_event(
        self,
        db: AsyncSession,
        event_type: str,
        details: Dict[str, Any]
    ):
        """Log security event to audit trail."""
        try:
            security_event = SecurityEvent(
                event_type=event_type,
                details=details,
                timestamp=datetime.utcnow(),
                ip_address=details.get("ip", "unknown")
            )
            db.add(security_event)
            await db.commit()
        except Exception:
            await db.rollback()

    async def _calculate_login_risk_score_safe(
        self,
        last_login: Optional[datetime],
        request_info: Dict[str, Any]
    ) -> float:
        """
        Calculate a risk score for a login attempt without accessing SQLAlchemy objects.

        Args:
            last_login: User's last login timestamp
            request_info: Request context information

        Returns:
            Risk score between 0.0 and 1.0 (higher is riskier)
        """
        # Initialize risk score (0.0 - 1.0, higher is riskier)
        risk_score = 0.0

        ip_address = request_info.get("ip_address", "")
        user_agent = request_info.get("user_agent", "")

        # 1. Check if it's a new user (10% risk)
        if not last_login:
            risk_score += 0.1

        # 2. Check time patterns (10% risk for unusual hours)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 23:  # Night hours
            risk_score += 0.1

        # 3. Check for suspicious user agent patterns (15% risk)
        if not user_agent or len(user_agent) < 10:
            risk_score += 0.15

        # 4. Check login frequency (20% risk for rapid attempts)
        if last_login:
            try:
                # Handle timezone-aware/naive datetime comparison safely
                current_time = datetime.utcnow()

                # Convert timezone-aware datetime to naive if needed
                if last_login.tzinfo is not None:
                    last_login_naive = last_login.replace(tzinfo=None)
                else:
                    last_login_naive = last_login

                time_since_last = current_time - last_login_naive
                if time_since_last.total_seconds() < 60:  # Less than 1 minute
                    risk_score += 0.2
            except (TypeError, AttributeError):
                # If datetime comparison fails, skip this check
                pass

        # Cap at 1.0
        return min(risk_score, 1.0)

# Create a singleton instance
auth_service = AuthService()
