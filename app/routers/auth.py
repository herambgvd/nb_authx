"""
Authentication API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_async_session
from app.schemas import (
    LoginRequest, LoginResponse, RefreshTokenRequest, RefreshTokenResponse,
    ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest,
    UserCreate, UserResponse, MessageResponse
)
from app.services.auth_service import AuthService
from app.dependencies import get_current_user, get_client_ip, get_user_agent
from app.models import User
from app.config import settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Register a new user (for super admin or public registration)"""
    auth_service = AuthService(db)

    try:
        user = await auth_service.register_user(user_data)
        logger.info(f"User registered: {user.email}")
        return user
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Authenticate user and return access token"""
    auth_service = AuthService(db)

    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        user, access_token, refresh_token = await auth_service.authenticate_user(
            login_data, ip_address, user_agent
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            user=UserResponse.model_validate(user)
        )
    except Exception as e:
        logger.error(f"Login failed for {login_data.email}: {e}")
        raise


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_async_session)
):
    """Refresh access token using refresh token"""
    auth_service = AuthService(db)

    try:
        access_token, new_refresh_token = await auth_service.refresh_access_token(
            refresh_data.refresh_token
        )

        return RefreshTokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60
        )
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise


@router.post("/logout", response_model=MessageResponse)
async def logout(
    refresh_data: RefreshTokenRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """Logout user and revoke refresh token"""
    auth_service = AuthService(db)

    try:
        await auth_service.logout_user(current_user.id, refresh_data.refresh_token)
        return MessageResponse(message="Successfully logged out")
    except Exception as e:
        logger.error(f"Logout failed for user {current_user.id}: {e}")
        raise


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """Logout user from all devices by revoking all refresh tokens"""
    auth_service = AuthService(db)

    try:
        await auth_service.logout_user(current_user.id)
        return MessageResponse(message="Successfully logged out from all devices")
    except Exception as e:
        logger.error(f"Logout all failed for user {current_user.id}: {e}")
        raise


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    forgot_data: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Request password reset token"""
    auth_service = AuthService(db)

    try:
        reset_token = await auth_service.request_password_reset(
            forgot_data.email,
            forgot_data.organization_slug
        )

        # In production, send email with reset_token
        # For now, just log it (remove in production)
        logger.info(f"Password reset token for {forgot_data.email}: {reset_token}")

        return MessageResponse(
            message="If the email exists, a password reset link has been sent"
        )
    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        raise


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    reset_data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_async_session)
):
    """Reset password using reset token"""
    auth_service = AuthService(db)

    try:
        await auth_service.reset_password(reset_data.token, reset_data.new_password)
        return MessageResponse(message="Password reset successfully")
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
        raise


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """Change current user's password"""
    from app.security import verify_password, hash_password, PasswordValidator
    from app.models import RefreshToken
    from sqlalchemy import update

    # Verify current password
    if not verify_password(password_data.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Validate new password
    is_valid, errors = PasswordValidator.validate(password_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {', '.join(errors)}"
        )

    try:
        # Update password
        current_user.password_hash = hash_password(password_data.new_password)
        current_user.failed_login_attempts = 0
        current_user.locked_until = None

        # Revoke all refresh tokens for security
        revoke_stmt = update(RefreshToken).where(
            RefreshToken.user_id == current_user.id
        ).values(is_revoked=True)
        await db.execute(revoke_stmt)

        await db.commit()

        logger.info(f"Password changed for user: {current_user.email}")
        return MessageResponse(message="Password changed successfully")
    except Exception as e:
        logger.error(f"Password change failed for user {current_user.id}: {e}")
        await db.rollback()
        raise


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    return UserResponse.model_validate(current_user)
