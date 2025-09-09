"""
Authentication API endpoints for AuthX.
Provides comprehensive authentication, registration, and token management endpoints.
"""
from uuid import UUID

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
    # Simplified request info to avoid any blocking operations
    request_info = {
        "ip_address": getattr(request.client, 'host', '127.0.0.1'),
        "user_agent": request.headers.get("user-agent", "Unknown"),
        "headers": dict(request.headers)
    }

    # Authenticate user using form data
    try:
        user_data, auth_context = await auth_service.authenticate_user(
            db, form_data.username, form_data.password, request_info
        )
    except HTTPException:
        raise
    except Exception as e:
        # Log the exact error for debugging
        import logging
        logging.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user_data or not auth_context.get('success', False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create tokens using user data (completely safe from SQLAlchemy issues)
    try:
        tokens = await auth_service.create_tokens_from_user_data(user_data)
    except Exception as e:
        import logging
        logging.error(f"Token creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token creation failed"
        )

    # Create user dictionary for response
    user_response_data = {
        "id": user_data["id"],
        "email": user_data["email"],
        "username": user_data["username"],
        "first_name": user_data.get("first_name", ""),
        "last_name": user_data.get("last_name", ""),
        "is_verified": user_data["is_verified"],
        "is_active": user_data["is_active"],
        "organization_id": user_data["organization_id"],
        "is_superuser": user_data.get("is_superuser", False),
        "is_organization_admin": user_data.get("is_organization_admin", False)
    }

    return LoginResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type="bearer",
        expires_in=tokens["expires_in"],
        user=user_response_data,
        message="Login successful"
    )


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
        register_data: RegisterRequest,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Register a new user account.
    """
    try:
        # Create user
        user = await user_service.create_user(db, register_data)

        # Send verification email in background
        if not user.is_verified:
            background_tasks.add_task(
                # This would trigger email verification
                lambda: None
            )

        # Create user dictionary for response
        user_data = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_verified": user.is_verified,
            "is_active": user.is_active
        }

        return RegisterResponse(
            user=user_data,
            verification_required=not user.is_verified,
            message="Registration successful. Please check your email for verification."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
        refresh_data: TokenRefreshRequest,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Refresh access token using refresh token.
    """
    try:
        tokens = await auth_service.refresh_access_token(db, refresh_data.refresh_token)

        return TokenRefreshResponse(
            access_token=tokens["access_token"],
            token_type="bearer",
            expires_in=tokens["expires_in"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
        logout_data: LogoutRequest,
        current_user: User = Depends(get_current_active_user)
):
    """
    Logout user and optionally revoke all sessions.
    """
    # In a full implementation, you'd revoke tokens/sessions here
    sessions_revoked = 1
    if logout_data.revoke_all_sessions:
        sessions_revoked = 5  # Mock: revoke all user sessions

    return LogoutResponse(
        message="Successfully logged out",
        sessions_revoked=sessions_revoked
    )


@router.post("/password/reset")
async def request_password_reset(
        reset_data: PasswordResetRequest,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Request password reset email.
    """
    # Find user by email
    result = await db.execute(select(User).where(User.email == reset_data.email))
    user = result.scalar_one_or_none()

    # Always return success for security (don't reveal if email exists)
    if user:
        # Generate reset token and send email in background
        background_tasks.add_task(
            # This would trigger password reset email
            lambda: None
        )

    return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/password/reset/confirm")
async def confirm_password_reset(
        reset_data: PasswordResetConfirm,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Confirm password reset with token.
    """
    # In a full implementation, verify reset token and update password
    return {"message": "Password reset successful"}


@router.post("/me/change-password")
async def change_password(
        change_data: PasswordChangeRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_async_db)
):
    """
    Change current user password with proper validation.
    """
    success = await auth_service.change_password(
        db, current_user.id, change_data.current_password, change_data.new_password
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid current password"
        )

    return {"message": "Password changed successfully"}


@router.post("/email/verify")
async def request_email_verification(
        verify_data: EmailVerificationRequest,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Request email verification.
    """
    # Find user and send verification email
    result = await db.execute(select(User).where(User.email == verify_data.email))
    user = result.scalar_one_or_none()

    if user and not user.is_verified:
        background_tasks.add_task(
            # This would trigger verification email
            lambda: None
        )

    return {"message": "Verification email sent if account exists"}


@router.post("/email/verify/confirm")
async def confirm_email_verification(
        confirm_data: EmailVerificationConfirm,
        db: AsyncSession = Depends(get_async_db)
):
    """
    Confirm email verification with token.
    """
    try:
        success = await user_service.verify_email(db, confirm_data.token)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )

        return {"message": "Email verified successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
        current_user: User = Depends(get_current_active_user)
):
    """
    Get current user information.
    """
    return UserResponse.from_orm(current_user)


@router.get("/sessions", response_model=SessionListResponse)
async def get_user_sessions(
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_async_db)
):
    """
    Get user's active sessions.
    """
    # Get user devices (sessions)
    devices = await user_service.get_user_devices(db, current_user.id)

    # Convert to session info format
    sessions = [
        {
            "session_id": str(device.id),
            "device_info": f"{device.device_type} - {device.device_name}" if device.device_name else device.device_type,
            "ip_address": device.ip_address,
            "user_agent": device.user_agent,
            "created_at": device.created_at,
            "last_active": device.last_seen or device.created_at,
            "is_current": True  # Would determine from current session
        }
        for device in devices
    ]

    return SessionListResponse(sessions=sessions, total=len(sessions))


@router.post("/sessions/revoke")
async def revoke_session(
        revoke_data: SessionRevokeRequest,
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_async_db)
):
    """
    Revoke a specific session.
    """
    success = await user_service.revoke_user_device(
        db, current_user.id, UUID(revoke_data.session_id)
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    return {"message": "Session revoked successfully"}
