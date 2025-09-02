"""
Authentication API endpoints for the AuthX service.
This module provides routes for user authentication, registration, and token management.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.models.organization import Organization
from app.schemas.auth import (
    Login,
    LoginResponse,
    TokenRefresh,
    PasswordResetRequest,
    PasswordReset,
    Registration,
    OrganizationRegistration,
    EmailVerification,
    MFAVerify,
    MFASetupRequest,
    MFASetupResponse,
    MFASetupVerify,
    MFAStatusResponse,
    MFADisableRequest,
    MFAListResponse,
    MFARecoveryCodesResponse
)
from app.schemas.base import ResponseBase
from app.services.auth_service import AuthService
from app.utils.security import (
    get_password_hash,
    verify_password_reset_token,
    verify_email_verification_token,
    verify_totp_code,
    verify_email_code,
    verify_sms_code,
    generate_mfa_secret,
    generate_totp_uri,
    generate_totp_qrcode,
    generate_email_code,
    generate_sms_code
)

router = APIRouter()

@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: Login,
    db: Session = Depends(get_db),
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    user = await AuthService.authenticate_user(
        db=db,
        username=login_data.username,
        password=login_data.password,
        organization_domain=login_data.organization_domain
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if MFA is required
    requires_mfa = user.mfa_enabled or (
        user.organization and user.organization.enforce_mfa
    )

    # Generate tokens
    tokens = await AuthService.create_tokens_for_user(user)

    # Return login response
    return {
        **tokens,
        "user_id": str(user.id),
        "organization_id": str(user.organization_id),
        "requires_mfa": requires_mfa,
        "mfa_type": user.mfa_type if requires_mfa else None
    }

@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    token_data: TokenRefresh,
    db: Session = Depends(get_db),
) -> Any:
    """
    Refresh access token.
    """
    try:
        tokens = await AuthService.refresh_access_token(db, token_data.refresh_token)

        # Get user from refresh token
        payload = jwt.decode(
            token_data.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Return login response
        return {
            **tokens,
            "user_id": str(user.id),
            "organization_id": str(user.organization_id),
            "requires_mfa": False,
            "mfa_type": None
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/verify-mfa", response_model=LoginResponse)
async def verify_mfa(
    mfa_data: MFAVerify,
    db: Session = Depends(get_db),
) -> Any:
    """
    Verify MFA code and complete login.
    """
    try:
        # Decode token to get user
        payload = jwt.decode(
            mfa_data.token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify MFA code based on user's MFA type
        from app.utils.security import verify_totp_code, verify_email_code, verify_sms_code

        # Check if user has MFA enabled
        if not user.mfa_enabled or not user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not enabled for this user",
            )

        # Verify code based on MFA type
        code_valid = False
        if user.mfa_type == "totp":
            code_valid = verify_totp_code(user.mfa_secret, mfa_data.code)
        elif user.mfa_type == "email":
            # We would get the stored code from a cache/database
            # For now, hardcode a test code
            stored_code = getattr(user, "mfa_email_code", "123456")
            code_valid = verify_email_code(stored_code, mfa_data.code)
        elif user.mfa_type == "sms":
            # We would get the stored code from a cache/database
            # For now, hardcode a test code
            stored_code = getattr(user, "mfa_sms_code", "123456")
            code_valid = verify_sms_code(stored_code, mfa_data.code)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported MFA type: {user.mfa_type}",
            )

        if not code_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate tokens
        tokens = await AuthService.create_tokens_for_user(user)

        # Return login response
        return {
            **tokens,
            "user_id": str(user.id),
            "organization_id": str(user.organization_id),
            "requires_mfa": False,
            "mfa_type": None
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/register", response_model=ResponseBase)
async def register(
    registration_data: Registration,
    db: Session = Depends(get_db),
) -> Any:
    """
    Register a new user and optionally create a new organization.
    """
    # Check if we need to create a new organization
    organization_id = None
    if registration_data.organization_name:
        # Create new organization
        organization = Organization(
            name=registration_data.organization_name,
            domain=registration_data.organization_domain,
            is_active=True,
            is_verified=False,
        )
        db.add(organization)
        db.commit()
        db.refresh(organization)
        organization_id = organization.id
    else:
        # Organization must be specified for registration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization is required for registration",
        )

    # Register user
    try:
        user = await AuthService.register_user(
            db=db,
            email=registration_data.email,
            password=registration_data.password,
            organization_id=organization_id,
            first_name=registration_data.first_name,
            last_name=registration_data.last_name,
        )

        # Send verification email
        from app.utils.security import generate_email_verification_token
        from app.services.email_service import EmailService

        verification_token = generate_email_verification_token(str(user.id))
        await EmailService.send_verification_email(user.email, verification_token)

        return {
            "success": True,
            "message": "User registered successfully. Please check your email for verification.",
        }
    except HTTPException as e:
        # Re-raise the exception
        raise e
    except Exception as e:
        # Handle any other exceptions
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error registering user: {str(e)}",
        )

@router.post("/register-organization", response_model=ResponseBase)
async def register_organization(
    registration_data: OrganizationRegistration,
    db: Session = Depends(get_db),
) -> Any:
    """
    Register a new organization with an admin user.
    """
    # Create new organization
    organization = Organization(
        name=registration_data.organization_name,
        domain=registration_data.organization_domain,
        is_active=True,
        is_verified=False,
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)

    # Register admin user
    try:
        user = await AuthService.register_user(
            db=db,
            email=registration_data.admin_email,
            password=registration_data.admin_password,
            organization_id=organization.id,
            first_name=registration_data.admin_first_name,
            last_name=registration_data.admin_last_name,
        )

        # Make user a superadmin for this organization
        # TODO: Implement role assignment

        # Send verification email
        from app.utils.security import generate_email_verification_token
        from app.services.email_service import EmailService

        verification_token = generate_email_verification_token(str(user.id))
        await EmailService.send_verification_email(user.email, verification_token)

        return {
            "success": True,
            "message": "Organization registered successfully. Please check your email for verification.",
        }
    except HTTPException as e:
        # Re-raise the exception
        raise e
    except Exception as e:
        # Handle any other exceptions
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error registering organization: {str(e)}",
        )

@router.post("/forgot-password", response_model=ResponseBase)
async def forgot_password(
    reset_data: PasswordResetRequest,
    db: Session = Depends(get_db),
) -> Any:
    """
    Send a password reset email.
    """
    # Find user by email
    user_query = db.query(User).filter(User.email == reset_data.email)

    # Add organization filter if domain is provided
    if reset_data.organization_domain:
        organization = db.query(Organization).filter(
            Organization.domain == reset_data.organization_domain
        ).first()
        if organization:
            user_query = user_query.filter(User.organization_id == organization.id)

    user = user_query.first()

    # Always return success to prevent email enumeration
    if not user:
        return {
            "success": True,
            "message": "If your email is registered, you will receive a password reset link.",
        }

    # Generate reset token
    from app.utils.security import generate_password_reset_token
    from app.services.email_service import EmailService

    token = generate_password_reset_token(user.email)

    # Send password reset email
    await EmailService.send_password_reset_email(user.email, token)

    return {
        "success": True,
        "message": "If your email is registered, you will receive a password reset link.",
    }

@router.post("/reset-password", response_model=ResponseBase)
async def reset_password(
    reset_data: PasswordReset,
    db: Session = Depends(get_db),
) -> Any:
    """
    Reset a user's password using a reset token.
    """
    # Verify reset token and get user email
    email = verify_password_reset_token(reset_data.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token",
        )

    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update password
    user.hashed_password = get_password_hash(reset_data.new_password)
    user.password_last_changed = datetime.utcnow()
    db.commit()

    return {
        "success": True,
        "message": "Password reset successfully. You can now login with your new password.",
    }

@router.post("/verify-email", response_model=ResponseBase)
async def verify_email(
    verification_data: EmailVerification,
    db: Session = Depends(get_db),
) -> Any:
    """
    Verify a user's email address.
    """
    # Verify token and get user ID
    from app.utils.security import verify_email_verification_token
    user_id = verify_email_verification_token(verification_data.token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    # Find user by ID
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update user verification status
    user.is_verified = True
    db.commit()

    return {
        "success": True,
        "message": "Email verified successfully. You can now log in to your account.",
    }

# MFA Management Endpoints
@router.get("/mfa/status", response_model=MFAStatusResponse)
async def get_mfa_status(
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Get the current MFA status for the authenticated user.
    """
    return {
        "enabled": current_user.mfa_enabled,
        "mfa_type": current_user.mfa_type if current_user.mfa_enabled else None
    }

@router.get("/mfa/methods", response_model=MFAListResponse)
async def list_mfa_methods(
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    List available MFA methods and the currently enabled method.
    """
    available_methods = ["totp"]

    # Add email if user has a verified email
    if current_user.is_verified:
        available_methods.append("email")

    # Add SMS if user has a phone number
    if current_user.phone_number:
        available_methods.append("sms")

    return {
        "available_methods": available_methods,
        "enabled_method": current_user.mfa_type if current_user.mfa_enabled else None
    }

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    setup_data: MFASetupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Set up MFA for the authenticated user.
    """
    # Check if MFA is already enabled
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled. Disable it first before setting up a new method."
        )

    # Validate MFA type
    if setup_data.mfa_type not in ["totp", "email", "sms"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA type. Supported types are: totp, email, sms"
        )

    # Check requirements for specific MFA types
    if setup_data.mfa_type == "email" and not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email must be verified before setting up email-based MFA"
        )

    if setup_data.mfa_type == "sms" and not current_user.phone_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number is required for SMS-based MFA"
        )

    # Generate setup data based on MFA type
    secret = None
    qrcode = None

    if setup_data.mfa_type == "totp":
        # Generate TOTP secret
        secret = generate_mfa_secret()

        # Generate QR code for TOTP setup
        uri = generate_totp_uri(secret, current_user.email)
        qrcode = generate_totp_qrcode(uri)

        # Store secret temporarily (will be confirmed on verification)
        current_user.mfa_secret_temp = secret
        db.commit()

    elif setup_data.mfa_type == "email":
        # Generate and send email code
        code = generate_email_code()

        # Send email with the verification code
        from app.services.email_service import EmailService
        await EmailService.send_mfa_code_email(current_user.email, code)

        # Store code temporarily
        current_user.mfa_email_code = code
        db.commit()

    elif setup_data.mfa_type == "sms":
        # Generate and send SMS code
        code = generate_sms_code()

        # In a real implementation, we would send an SMS with the code
        # For now, just log it
        print(f"SMS MFA setup code for {current_user.phone_number}: {code}")

        # Store code temporarily
        current_user.mfa_sms_code = code
        db.commit()

    # Generate setup token
    setup_token = jwt.encode(
        {
            "sub": str(current_user.id),
            "type": "mfa_setup",
            "mfa_type": setup_data.mfa_type,
            "exp": datetime.utcnow() + timedelta(minutes=15)
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )

    return {
        "secret": secret,
        "qrcode": qrcode,
        "mfa_type": setup_data.mfa_type,
        "setup_token": setup_token
    }

@router.post("/mfa/verify-setup", response_model=ResponseBase)
async def verify_mfa_setup(
    verify_data: MFASetupVerify,
    db: Session = Depends(get_db),
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Verify MFA setup and enable MFA for the user.
    """
    try:
        # Decode setup token
        payload = jwt.decode(
            verify_data.setup_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Validate token
        if payload.get("type") != "mfa_setup" or payload.get("sub") != str(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid setup token"
            )

        mfa_type = payload.get("mfa_type")

        # Verify code based on MFA type
        code_valid = False

        if mfa_type == "totp":
            if not current_user.mfa_secret_temp:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="MFA setup not initiated properly"
                )

            code_valid = verify_totp_code(current_user.mfa_secret_temp, verify_data.code)

            if code_valid:
                # Activate MFA
                current_user.mfa_enabled = True
                current_user.mfa_type = "totp"
                current_user.mfa_secret = current_user.mfa_secret_temp
                current_user.mfa_secret_temp = None

        elif mfa_type == "email":
            stored_code = getattr(current_user, "mfa_email_code", None)
            if not stored_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email verification code not sent"
                )

            code_valid = verify_email_code(stored_code, verify_data.code)

            if code_valid:
                # Activate MFA
                current_user.mfa_enabled = True
                current_user.mfa_type = "email"
                current_user.mfa_email_code = None

        elif mfa_type == "sms":
            stored_code = getattr(current_user, "mfa_sms_code", None)
            if not stored_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="SMS verification code not sent"
                )

            code_valid = verify_sms_code(stored_code, verify_data.code)

            if code_valid:
                # Activate MFA
                current_user.mfa_enabled = True
                current_user.mfa_type = "sms"
                current_user.mfa_sms_code = None

        if not code_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code"
            )

        # Generate recovery codes
        # In a real implementation, we would generate and store recovery codes

        # Save changes
        db.commit()

        return {
            "success": True,
            "message": f"{mfa_type.upper()} multi-factor authentication has been enabled successfully."
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired setup token"
        )

@router.post("/mfa/disable", response_model=ResponseBase)
async def disable_mfa(
    disable_data: MFADisableRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Disable MFA for the authenticated user.
    """
    # Verify password for security
    if not verify_password(disable_data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Check if MFA is enabled
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not currently enabled"
        )

    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_type = None
    current_user.mfa_secret = None

    # Save changes
    db.commit()

    return {
        "success": True,
        "message": "Multi-factor authentication has been disabled."
    }

@router.get("/mfa/recovery-codes", response_model=MFARecoveryCodesResponse)
async def get_recovery_codes(
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Get MFA recovery codes for the authenticated user.
    """
    # Check if MFA is enabled
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )

    # In a real implementation, we would retrieve stored recovery codes
    # For now, return placeholder codes
    recovery_codes = [
        "ABCD-EFGH-IJKL",
        "MNOP-QRST-UVWX",
        "1234-5678-90AB",
        "CDEF-GHIJ-KLMN",
        "OPQR-STUV-WXYZ"
    ]

    return {
        "recovery_codes": recovery_codes
    }

@router.post("/mfa/send-code", response_model=ResponseBase)
async def send_mfa_code(
    db: Session = Depends(get_db),
    current_user: User = Depends(AuthService.get_current_user),
) -> Any:
    """
    Send a new MFA code for email or SMS verification.
    """
    # Check if MFA is enabled
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )

    # Check MFA type
    if current_user.mfa_type not in ["email", "sms"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only for email or SMS-based MFA"
        )

    if current_user.mfa_type == "email":
        # Generate and send email code
        code = generate_email_code()

        # Send the MFA code via email
        from app.services.email_service import EmailService
        await EmailService.send_mfa_code_email(current_user.email, code)

        # Store code
        current_user.mfa_email_code = code
        db.commit()

        return {
            "success": True,
            "message": "Verification code has been sent to your email."
        }

    elif current_user.mfa_type == "sms":
        # Generate and send SMS code
        code = generate_sms_code()

        # In a real implementation, we would send an SMS with the code
        # For now, just log it
        print(f"SMS MFA code for {current_user.phone_number}: {code}")

        # Store code
        current_user.mfa_sms_code = code
        db.commit()

        return {
            "success": True,
            "message": "Verification code has been sent to your phone."
        }
