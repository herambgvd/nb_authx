"""
Authentication service for the AuthX microservice.
This module provides comprehensive authentication, token management, and security features.
"""
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import (
    check_brute_force, record_failed_login, reset_brute_force_counter,
    calculate_login_risk_score, detect_bot, generate_device_fingerprint
)
from app.db.session import get_async_db
from app.models.user import User
from app.models.user_device import UserDevice
from app.models.organization import Organization
from app.models.audit import AuditLog, SecurityEvent
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
    ) -> Tuple[Optional[User], Dict[str, Any]]:
        """
        Authenticate a user with comprehensive security checks.

        Args:
            db: Database session
            username: Username or email
            password: Plain text password
            request_info: Request context information

        Returns:
            Tuple of (User object, authentication context) or raises HTTPException
        """
        from app.core.security import verify_password

        # Check for brute force attempts
        client_ip = request_info.get("ip_address", "unknown")
        if await check_brute_force(client_ip, username):
            await self._log_security_event(
                db, "BRUTE_FORCE_BLOCKED",
                {"username": username, "ip": client_ip}
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
                {"username": username, "ip": client_ip, "reason": "invalid_credentials"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if user account is active
        if not user.is_active:
            await self._log_security_event(
                db, "LOGIN_BLOCKED",
                {"user_id": str(user.id), "reason": "inactive_account"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is disabled"
            )

        # Reset brute force counter on successful authentication
        await reset_brute_force_counter(client_ip, username)

        # Calculate risk score
        risk_score = await calculate_login_risk_score(user, request_info, db)

        # Generate device fingerprint
        device_fingerprint = generate_device_fingerprint(request_info)

        # Check or create device record
        device = await self._handle_device_tracking(db, user, device_fingerprint, request_info)

        # Create authentication context
        auth_context = {
            "risk_score": risk_score,
            "device_fingerprint": device_fingerprint,
            "device_id": str(device.id) if device else None,
            "requires_mfa": user.mfa_enabled or risk_score > 0.7,
            "login_time": datetime.utcnow(),
            "ip_address": client_ip
        }

        # Log successful authentication
        await self._log_security_event(
            db, "LOGIN_SUCCESS",
            {
                "user_id": str(user.id),
                "ip": client_ip,
                "risk_score": risk_score,
                "device_fingerprint": device_fingerprint
            }
        )

        return user, auth_context

    async def create_access_token(
        self,
        user: User,
        auth_context: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode = {
            "sub": str(user.id),
            "email": user.email,
            "username": user.username,
            "is_superuser": user.is_superuser,
            "is_verified": user.is_verified,
            "organization_id": str(user.organization_id) if user.organization_id else None,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }

        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    async def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token."""
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        to_encode = {
            "sub": str(user.id),
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
        refresh_token: str,
        db: AsyncSession
    ) -> Tuple[str, str]:
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

            # Get user from database
            result = await db.execute(select(User).where(User.id == UUID(user_id)))
            user = result.scalar_one_or_none()

            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            # Create new tokens
            auth_context = {"refresh_operation": True}
            new_access_token = await self.create_access_token(user, auth_context)
            new_refresh_token = await self.create_refresh_token(user)

            return new_access_token, new_refresh_token

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

    async def verify_mfa_code(
        self,
        db: AsyncSession,
        user_id: UUID,
        code: str,
        mfa_type: str = "totp"
    ) -> bool:
        """
        Verify MFA code for a user.

        Args:
            db: Database session
            user_id: User ID
            code: MFA code
            mfa_type: Type of MFA (totp, sms, email)

        Returns:
            bool: True if code is valid
        """
        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.mfa_enabled:
            return False

        if mfa_type == "totp":
            # Verify TOTP code
            import pyotp
            totp = pyotp.TOTP(user.mfa_secret)
            return totp.verify(code, valid_window=1)

        # Add support for SMS/Email MFA here
        return False

    async def setup_mfa(
        self,
        db: AsyncSession,
        user_id: UUID,
        mfa_type: str = "totp"
    ) -> Dict[str, Any]:
        """
        Set up MFA for a user.

        Args:
            db: Database session
            user_id: User ID
            mfa_type: Type of MFA to set up

        Returns:
            Dict containing MFA setup information
        """
        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if mfa_type == "totp":
            import pyotp
            import qrcode
            import io
            import base64

            # Generate secret
            secret = pyotp.random_base32()

            # Create TOTP URI
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user.email,
                issuer_name=settings.MFA_ISSUER
            )

            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qr_code_data = base64.b64encode(buf.getvalue()).decode()

            # Save secret (but don't enable MFA yet)
            user.mfa_secret = secret
            await db.commit()

            return {
                "secret": secret,
                "qr_code": f"data:image/png;base64,{qr_code_data}",
                "manual_entry_key": secret,
                "totp_uri": totp_uri
            }

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported MFA type"
        )

    async def get_current_user(
        self,
        db: AsyncSession = Depends(get_async_db),
        token: str = Depends(oauth2_scheme)
    ) -> User:
        """
        Get the current authenticated user from JWT token.

        Args:
            db: Database session
            token: JWT access token

        Returns:
            User: Current authenticated user
        """
        from app.core.security import verify_token

        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = verify_token(token)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise credentials_exception
        except JWTError:
            raise credentials_exception

        # Get user from database
        result = await db.execute(
            select(User)
            .options(selectinload(User.organization))
            .where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if user is None:
            raise credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive"
            )

        return user

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
        from app.core.utils import validate_password

        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            return False

        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            return False

        # Validate new password
        validation = validate_password(new_password)
        if not validation['valid']:
            return False

        # Update password
        user.hashed_password = get_password_hash(new_password)
        await db.commit()

        return True

    # Private helper methods
    async def _get_user_by_identifier(self, db: AsyncSession, identifier: str) -> Optional[User]:
        """Get user by username or email."""
        result = await db.execute(
            select(User).where(
                or_(User.username == identifier, User.email == identifier)
            ).options(selectinload(User.organization))
        )
        return result.scalar_one_or_none()

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
            # Log error but don't fail authentication
            import logging
            logging.error(f"Device tracking error: {e}")
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
        except Exception as e:
            await db.rollback()
            import logging
            logging.error(f"Failed to log security event: {e}")

# Create global auth service instance
auth_service = AuthService()

# Export the service
__all__ = ["auth_service", "AuthService"]
