"""
Security utilities for authentication and authorization
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import argon2
import secrets
import hashlib
from app.config import settings
from app.schemas import TokenPayload


# Password hashing context using Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MB
    argon2__time_cost=3,        # 3 iterations
    argon2__parallelism=1,      # 1 thread
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )
    return encoded_jwt


def create_refresh_token(user_id: str) -> tuple[str, datetime]:
    """Create refresh token and return token with expiry"""
    token = generate_token(48)
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    return token, expires_at


def create_reset_token(email: str) -> tuple[str, datetime]:
    """Create password reset token"""
    # Create a token based on email and timestamp for additional security
    timestamp = str(int(datetime.utcnow().timestamp()))
    data = f"{email}:{timestamp}:{secrets.token_urlsafe(32)}"
    token = hashlib.sha256(data.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(minutes=settings.reset_password_token_expire_minutes)
    return token, expires_at


def verify_token(token: str) -> Optional[TokenPayload]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Check if token is expired
        exp = payload.get("exp")
        if exp is None or datetime.utcfromtimestamp(exp) < datetime.utcnow():
            return None

        # Check token type
        if payload.get("type") != "access":
            return None

        # Extract user data
        user_id = payload.get("sub")
        email = payload.get("email")

        if user_id is None or email is None:
            return None

        return TokenPayload(
            sub=user_id,
            email=email,
            org_id=payload.get("org_id"),
            is_super_admin=payload.get("is_super_admin", False),
            exp=exp,
            iat=payload.get("iat", 0)
        )

    except JWTError:
        return None


def generate_verification_code() -> str:
    """Generate 6-digit verification code"""
    return f"{secrets.randbelow(1000000):06d}"


class PasswordValidator:
    """Password strength validator"""

    @staticmethod
    def validate(password: str) -> tuple[bool, List[str]]:
        """Validate password strength"""
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if len(password) > 128:
            errors.append("Password must be less than 128 characters long")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        # Check for common patterns
        common_patterns = ["123456", "password", "qwerty", "abc123"]
        if any(pattern in password.lower() for pattern in common_patterns):
            errors.append("Password contains common patterns and is not secure")

        return len(errors) == 0, errors


def create_token_data(user_id: str, email: str, org_id: Optional[str] = None, is_super_admin: bool = False) -> Dict[str, Any]:
    """Create token data dictionary"""
    return {
        "sub": user_id,
        "email": email,
        "org_id": org_id,
        "is_super_admin": is_super_admin,
    }
