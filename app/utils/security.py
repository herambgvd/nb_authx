"""
Security utilities for AuthX.
Provides password hashing, token generation, and authentication utilities.
"""
from datetime import datetime, timedelta
from typing import Any, Union, Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
import secrets
import string
import pyotp
import qrcode
import io
import base64
import hashlib
import hmac

from app.core.config import settings

# Password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create an access token for authentication.

    Args:
        data: Dictionary of data to encode in the token
        expires_delta: Optional custom expiration time

    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    """
    Create a refresh token for authentication.

    Args:
        data: Dictionary of data to encode in the token

    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: The plain text password
        hashed_password: The hashed password

    Returns:
        bool: True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a password for storage.

    Args:
        password: The plain text password

    Returns:
        str: The hashed password
    """
    return pwd_context.hash(password)

def generate_password_reset_token(email: str) -> str:
    """
    Generate a password reset token.

    Args:
        email: User's email address

    Returns:
        str: Password reset token
    """
    delta = timedelta(hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS)
    now = datetime.utcnow()
    expires = now + delta
    exp = expires.timestamp()
    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email, "type": "password_reset"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return encoded_jwt

def verify_password_reset_token(token: str) -> Optional[str]:
    """
    Verify a password reset token and return the email.

    Args:
        token: The password reset token

    Returns:
        Optional[str]: Email if token is valid, None otherwise
    """
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if decoded_token.get("type") != "password_reset":
            return None
        return decoded_token["sub"]
    except JWTError:
        return None

def generate_email_verification_token(email: str) -> str:
    """
    Generate an email verification token.

    Args:
        email: User's email address

    Returns:
        str: Email verification token
    """
    delta = timedelta(hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS)
    now = datetime.utcnow()
    expires = now + delta
    exp = expires.timestamp()
    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email, "type": "email_verification"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return encoded_jwt

def verify_email_verification_token(token: str) -> Optional[str]:
    """
    Verify an email verification token and return the email.

    Args:
        token: The email verification token

    Returns:
        Optional[str]: Email if token is valid, None otherwise
    """
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if decoded_token.get("type") != "email_verification":
            return None
        return decoded_token["sub"]
    except JWTError:
        return None

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Length of the token

    Returns:
        str: Secure random token
    """
    return secrets.token_urlsafe(length)

def generate_api_key() -> str:
    """
    Generate an API key.

    Returns:
        str: API key
    """
    return secrets.token_urlsafe(64)

def generate_secret_key() -> str:
    """
    Generate a secret key for JWT signing.

    Returns:
        str: Secret key
    """
    return secrets.token_urlsafe(64)

def generate_totp_secret() -> str:
    """
    Generate a TOTP secret for 2FA.

    Returns:
        str: TOTP secret
    """
    return pyotp.random_base32()

def generate_totp_qr_code(email: str, secret: str, issuer: str = "AuthX") -> str:
    """
    Generate a QR code for TOTP setup.

    Args:
        email: User's email
        secret: TOTP secret
        issuer: Service name

    Returns:
        str: Base64 encoded QR code image
    """
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()

    return f"data:image/png;base64,{img_str}"

def verify_totp_token(secret: str, token: str) -> bool:
    """
    Verify a TOTP token.

    Args:
        secret: TOTP secret
        token: TOTP token

    Returns:
        bool: True if token is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for storage.

    Args:
        api_key: The API key

    Returns:
        str: Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_hmac_signature(data: str, signature: str, secret: str) -> bool:
    """
    Verify an HMAC signature.

    Args:
        data: The data that was signed
        signature: The signature to verify
        secret: The secret used for signing

    Returns:
        bool: True if signature is valid, False otherwise
    """
    expected_signature = hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

def generate_hmac_signature(data: str, secret: str) -> str:
    """
    Generate an HMAC signature.

    Args:
        data: The data to sign
        secret: The secret to use for signing

    Returns:
        str: The HMAC signature
    """
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def is_strong_password(password: str) -> bool:
    """
    Check if a password meets strength requirements.

    Args:
        password: The password to check

    Returns:
        bool: True if password is strong, False otherwise
    """
    if len(password) < 8:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    return has_upper and has_lower and has_digit and has_special
