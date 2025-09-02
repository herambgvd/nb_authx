"""
Security utilities for the AuthX service.
This module provides functions for password hashing, verification, and token generation.
"""
import os
import base64
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union, Tuple
from io import BytesIO

import pyotp
import qrcode
from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify that a plain password matches a hashed password.

    Args:
        plain_password: The plain text password to verify
        hashed_password: The hashed password to compare against

    Returns:
        bool: True if the password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: The password to hash

    Returns:
        str: The hashed password
    """
    return pwd_context.hash(password)

def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        subject: The subject of the token, usually the user ID
        expires_delta: Optional expiration time delta, defaults to settings.ACCESS_TOKEN_EXPIRE_MINUTES

    Returns:
        str: The JWT token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any]) -> str:
    """
    Create a JWT refresh token with longer expiration.

    Args:
        subject: The subject of the token, usually the user ID

    Returns:
        str: The JWT refresh token
    """
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def generate_mfa_secret() -> str:
    """
    Generate a secret key for multi-factor authentication.

    Returns:
        str: A random secret key
    """
    return pyotp.random_base32()

def generate_password_reset_token(email: str) -> str:
    """
    Generate a password reset token.

    Args:
        email: The email address of the user

    Returns:
        str: The password reset token
    """
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode = {"exp": expire, "sub": email, "type": "reset"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Verify a password reset token and return the email if valid.

    Args:
        token: The password reset token

    Returns:
        Optional[str]: The email address if the token is valid, None otherwise
    """
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if decoded_token["type"] != "reset":
            return None
        return decoded_token["sub"]
    except jwt.JWTError:
        return None

def generate_email_verification_token(user_id: str) -> str:
    """
    Generate an email verification token.

    Args:
        user_id: The ID of the user

    Returns:
        str: The email verification token
    """
    expire = datetime.utcnow() + timedelta(days=3)
    to_encode = {"exp": expire, "sub": str(user_id), "type": "verification"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_email_verification_token(token: str) -> Optional[str]:
    """
    Verify an email verification token and return the user ID if valid.

    Args:
        token: The email verification token

    Returns:
        Optional[str]: The user ID if the token is valid, None otherwise
    """
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if decoded_token["type"] != "verification":
            return None
        return decoded_token["sub"]
    except jwt.JWTError:
        return None

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.

    Args:
        secret: The TOTP secret
        code: The code to verify

    Returns:
        bool: True if the code is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    # Allow for some time drift (30 seconds window)
    return totp.verify(code, valid_window=1)

def generate_totp_uri(secret: str, username: str, issuer: str = "AuthX") -> str:
    """
    Generate a TOTP URI for QR code generation.

    Args:
        secret: The TOTP secret
        username: The username or email of the user
        issuer: The name of the service (default: AuthX)

    Returns:
        str: The TOTP URI
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def generate_totp_qrcode(uri: str) -> str:
    """
    Generate a QR code image for TOTP setup.

    Args:
        uri: The TOTP URI

    Returns:
        str: Base64-encoded QR code image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"

def generate_email_code() -> str:
    """
    Generate a 6-digit code for email-based MFA.

    Returns:
        str: 6-digit code
    """
    return ''.join(random.choices(string.digits, k=6))

def generate_sms_code() -> str:
    """
    Generate a 6-digit code for SMS-based MFA.

    Returns:
        str: 6-digit code
    """
    return ''.join(random.choices(string.digits, k=6))

def verify_email_code(stored_code: str, provided_code: str) -> bool:
    """
    Verify an email-based MFA code.

    Args:
        stored_code: The code stored in the database
        provided_code: The code provided by the user

    Returns:
        bool: True if the codes match, False otherwise
    """
    return stored_code == provided_code

def verify_sms_code(stored_code: str, provided_code: str) -> bool:
    """
    Verify an SMS-based MFA code.

    Args:
        stored_code: The code stored in the database
        provided_code: The code provided by the user

    Returns:
        bool: True if the codes match, False otherwise
    """
    return stored_code == provided_code
