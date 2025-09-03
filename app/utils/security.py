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
        str: Encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token to verify

    Returns:
        dict: Decoded token payload

    Raises:
        JWTError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise JWTError("Token is invalid or expired")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        bool: True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a password.

    Args:
        password: Plain text password

    Returns:
        str: Hashed password
    """
    return pwd_context.hash(password)

def generate_password(length: int = 12, include_symbols: bool = True) -> str:
    """
    Generate a secure random password.

    Args:
        length: Length of the password
        include_symbols: Whether to include symbols

    Returns:
        str: Generated password
    """
    characters = string.ascii_letters + string.digits
    if include_symbols:
        characters += "!@#$%^&*"

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Args:
        length: Length of the token

    Returns:
        str: URL-safe token
    """
    return secrets.token_urlsafe(length)

def generate_mfa_secret() -> str:
    """
    Generate a secret for TOTP MFA.

    Returns:
        str: Base32 encoded secret
    """
    return pyotp.random_base32()

def generate_mfa_qr_code(secret: str, user_email: str, issuer: str = None) -> str:
    """
    Generate QR code for MFA setup.

    Args:
        secret: TOTP secret
        user_email: User's email
        issuer: Issuer name

    Returns:
        str: Base64 encoded QR code image
    """
    issuer = issuer or settings.MFA_ISSUER
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name=issuer
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_code_data = base64.b64encode(buf.getvalue()).decode()

    return f"data:image/png;base64,{qr_code_data}"

def verify_mfa_token(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP MFA token.

    Args:
        secret: TOTP secret
        token: Token to verify
        valid_window: Number of time windows to accept

    Returns:
        bool: True if token is valid
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=valid_window)

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage.

    Args:
        api_key: Plain API key

    Returns:
        str: Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(plain_key: str, hashed_key: str) -> bool:
    """
    Verify an API key against its hash.

    Args:
        plain_key: Plain API key
        hashed_key: Hashed API key

    Returns:
        bool: True if key matches
    """
    return hmac.compare_digest(hash_api_key(plain_key), hashed_key)

def create_csrf_token() -> str:
    """
    Create a CSRF token.

    Returns:
        str: CSRF token
    """
    return secrets.token_urlsafe(32)

def verify_csrf_token(token: str, stored_token: str) -> bool:
    """
    Verify CSRF token.

    Args:
        token: Token to verify
        stored_token: Stored token

    Returns:
        bool: True if tokens match
    """
    return hmac.compare_digest(token, stored_token)

def generate_verification_code(length: int = 6) -> str:
    """
    Generate a numeric verification code.

    Args:
        length: Length of the code

    Returns:
        str: Verification code
    """
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def create_signature(data: str, secret: str) -> str:
    """
    Create HMAC signature for data.

    Args:
        data: Data to sign
        secret: Secret key

    Returns:
        str: Hex signature
    """
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()

def verify_signature(data: str, signature: str, secret: str) -> bool:
    """
    Verify HMAC signature.

    Args:
        data: Original data
        signature: Signature to verify
        secret: Secret key

    Returns:
        bool: True if signature is valid
    """
    expected_signature = create_signature(data, secret)
    return hmac.compare_digest(signature, expected_signature)
