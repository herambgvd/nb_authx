"""
Authentication API endpoints for AuthX.
Provides comprehensive authentication, registration, and token management endpoints.
"""
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user
from app.db.session import get_async_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest, LoginResponse, TokenRefreshRequest, TokenRefreshResponse,
    PasswordResetRequest, PasswordResetConfirm, PasswordChangeRequest,
    RegisterRequest, RegisterResponse, EmailVerificationRequest, EmailVerificationConfirm,
    LogoutRequest, LogoutResponse,
    SessionListResponse, SessionRevokeRequest
)
from app.schemas.user import UserResponse
from app.services.auth_service import auth_service
from app.services.user_service import user_service
from app.services.email_service import email_service

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Authenticate user with comprehensive security checks.
    """
    try:
        # Safely extract request info
        client_ip = "127.0.0.1"
        user_agent = "Unknown"

        if hasattr(request, 'client') and request.client:
            client_ip = getattr(request.client, 'host', '127.0.0.1')

        if hasattr(request, 'headers'):
            user_agent = request.headers.get("user-agent", "Unknown")

        request_info = {
            "ip_address": client_ip,
            "user_agent": user_agent,
            "headers": dict(request.headers) if hasattr(request, 'headers') else {}
        }

        # Authenticate user using form data with proper validation
        if not form_data.username or not form_data.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username and password are required"
            )

        user_data, auth_context = await auth_service.authenticate_user(
            db, form_data.username, form_data.password, request_info
        )

        if not user_data or not auth_context.get('success', False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create tokens using user data
        tokens = await auth_service.create_tokens_from_user_data(user_data)

        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token creation failed"
            )

        # Create user response data safely
        user_response_data = {
            "id": user_data["id"],
            "email": user_data["email"],
            "username": user_data.get("username", ""),
            "first_name": user_data.get("first_name", ""),
            "last_name": user_data.get("last_name", ""),
            "is_verified": user_data.get("is_verified", False),
            "is_active": user_data.get("is_active", False),
            "organization_id": user_data.get("organization_id"),
            "is_superuser": user_data.get("is_superuser", False),
            "is_organization_admin": user_data.get("is_organization_admin", False),
            "created_at": user_data.get("created_at"),
            "updated_at": user_data.get("updated_at"),
            "last_login": user_data.get("last_login"),
            "full_name": f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip()
        }

        logger.info(f"User {user_data['email']} logged in successfully from {client_ip}")

        return LoginResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type="bearer",
            expires_in=tokens["expires_in"],
            user=user_response_data,
            message="Login successful"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    register_data: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Register a new user account with proper validation.
    """
    try:
        # Create user with comprehensive validation
        user = await user_service.create_user(db, register_data)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User creation failed"
            )

        # Send verification email in background if user needs verification
        if not user.is_verified:
            background_tasks.add_task(
                _send_verification_email,
                user.email,
                user.first_name or user.username,
                str(user.id)
            )

        # Create safe user response
        user_data = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username or "",
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "is_verified": user.is_verified,
            "is_active": user.is_active,
            "organization_id": str(user.organization_id) if user.organization_id else None,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "full_name": f"{user.first_name or ''} {user.last_name or ''}".strip()
        }

        logger.info(f"User registered successfully: {user.email}")

        return RegisterResponse(
            user=user_data,
            verification_required=not user.is_verified,
            message="Registration successful. Please check your email for verification." if not user.is_verified else "Registration successful."
        )

    except ValueError as e:
        logger.error(f"Validation error during registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

async def _send_verification_email(email: str, name: str, user_id: str):
    """Background task to send verification email."""
    try:
        # Generate verification URL (in a real app, you'd generate a secure token)
        verification_url = f"https://yourapp.com/verify-email?token={user_id}"

        success = await email_service.send_verification_email(
            user_email=email,
            user_name=name,
            verification_url=verification_url
        )

        if success:
            logger.info(f"Verification email sent to {email}")
        else:
            logger.error(f"Failed to send verification email to {email}")

    except Exception as e:
        logger.error(f"Error sending verification email: {e}")

@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
    refresh_data: TokenRefreshRequest,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Refresh access token using refresh token with proper validation.
    """
    try:
        if not refresh_data.refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required"
            )

        tokens = await auth_service.refresh_access_token(db, refresh_data.refresh_token)

        if not tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        return TokenRefreshResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens.get("refresh_token"),  # May or may not rotate
            token_type="bearer",
            expires_in=tokens["expires_in"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@router.post("/logout", response_model=LogoutResponse)
async def logout(
    logout_data: LogoutRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Logout user and optionally revoke all sessions.
    """
    try:
        sessions_revoked = await auth_service.logout_user(
            db,
            current_user.id,
            revoke_all=logout_data.revoke_all_sessions
        )

        logger.info(f"User {current_user.email} logged out, {sessions_revoked} sessions revoked")

        return LogoutResponse(
            message="Successfully logged out",
            sessions_revoked=sessions_revoked
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        # Don't fail logout even if session revocation fails
        return LogoutResponse(
            message="Logged out (some sessions may still be active)",
            sessions_revoked=0
        )

@router.post("/password/reset")
async def request_password_reset(
    reset_data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Request password reset email with security best practices.
    """
    try:
        if not reset_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required"
            )

        # Find user by email
        result = await db.execute(select(User).where(User.email == reset_data.email.lower()))
        user = result.scalar_one_or_none()

        # Always return success for security (don't reveal if email exists)
        if user and user.is_active:
            background_tasks.add_task(
                _send_password_reset_email,
                user.email,
                user.first_name or user.username,
                str(user.id)
            )
            logger.info(f"Password reset requested for {reset_data.email}")

        return {"message": "If the email exists, a password reset link has been sent"}

    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        # Don't reveal errors for security
        return {"message": "If the email exists, a password reset link has been sent"}

async def _send_password_reset_email(email: str, name: str, user_id: str):
    """Background task to send password reset email."""
    try:
        # Generate reset URL (in a real app, you'd generate a secure token with expiration)
        reset_url = f"https://yourapp.com/reset-password?token={user_id}"

        success = await email_service.send_password_reset_email(
            user_email=email,
            user_name=name,
            reset_url=reset_url
        )

        if success:
            logger.info(f"Password reset email sent to {email}")
        else:
            logger.error(f"Failed to send password reset email to {email}")

    except Exception as e:
        logger.error(f"Error sending password reset email: {e}")

@router.post("/password/reset/confirm")
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Confirm password reset with token validation.
    """
    try:
        if not reset_data.token or not reset_data.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token and new password are required"
            )

        success = await auth_service.reset_password_with_token(
            db,
            reset_data.token,
            reset_data.new_password
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )

        logger.info("Password reset completed successfully")
        return {"message": "Password reset successful"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirmation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

@router.post("/me/change-password")
async def change_password(
    change_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Change current user password with proper validation.
    """
    try:
        if not change_data.current_password or not change_data.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password and new password are required"
            )

        success = await auth_service.change_password(
            db, current_user.id, change_data.current_password, change_data.new_password
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )

        logger.info(f"Password changed for user {current_user.email}")
        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )

@router.post("/email/verify")
async def request_email_verification(
    verify_data: EmailVerificationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Request email verification with proper validation.
    """
    try:
        if not verify_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required"
            )

        # Find user and send verification email
        result = await db.execute(select(User).where(User.email == verify_data.email.lower()))
        user = result.scalar_one_or_none()

        if user and not user.is_verified:
            background_tasks.add_task(
                _send_verification_email,
                user.email,
                user.first_name or user.username,
                str(user.id)
            )

        return {"message": "Verification email sent if account exists and is not already verified"}

    except Exception as e:
        logger.error(f"Email verification request failed: {e}")
        return {"message": "Verification email sent if account exists and is not already verified"}

@router.post("/email/verify/confirm")
async def confirm_email_verification(
    confirm_data: EmailVerificationConfirm,
    db: AsyncSession = Depends(get_async_db)
):
    """
    Confirm email verification with token validation.
    """
    try:
        if not confirm_data.token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification token is required"
            )

        success = await user_service.verify_email(db, confirm_data.token)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )

        logger.info("Email verification completed successfully")
        return {"message": "Email verified successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user information safely.
    """
    try:
        return UserResponse.model_validate(current_user)
    except Exception as e:
        logger.error(f"Failed to get current user info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user information"
        )

@router.get("/sessions", response_model=SessionListResponse)
async def get_user_sessions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get user's active sessions with proper error handling.
    """
    try:
        # Get user devices (sessions)
        devices = await user_service.get_user_devices(db, current_user.id)

        # Convert to session info format safely
        sessions = []
        for device in devices:
            session_data = {
                "session_id": str(device.id),
                "device_info": f"{device.device_type} - {device.device_name}" if device.device_name else device.device_type,
                "ip_address": device.ip_address or "Unknown",
                "user_agent": device.user_agent or "Unknown",
                "created_at": device.created_at,
                "last_active": device.last_seen or device.created_at,
                "is_current": True  # Would determine from current session in real implementation
            }
            sessions.append(session_data)

        return SessionListResponse(sessions=sessions, total=len(sessions))

    except Exception as e:
        logger.error(f"Failed to get user sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions"
        )

@router.post("/sessions/revoke")
async def revoke_session(
    revoke_data: SessionRevokeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Revoke a specific session with proper validation.
    """
    try:
        if not revoke_data.session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session ID is required"
            )

        # Validate UUID format
        try:
            session_uuid = UUID(revoke_data.session_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid session ID format"
            )

        success = await user_service.revoke_user_device(
            db, current_user.id, session_uuid
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )

        logger.info(f"Session {revoke_data.session_id} revoked for user {current_user.email}")
        return {"message": "Session revoked successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )
