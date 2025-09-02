"""
Authentication service for the AuthX microservice.
This module provides functions for user authentication, token management, and password reset.
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.models.organization import Organization
from app.utils.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
)

# OAuth2 token URL and scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")

class AuthService:
    """Service for authentication-related operations."""

    @staticmethod
    async def authenticate_user(
        db: Session, username: str, password: str, organization_domain: Optional[str] = None
    ) -> Optional[User]:
        """
        Authenticate a user with username/email and password.

        Args:
            db: Database session
            username: Username or email
            password: Plain text password
            organization_domain: Optional organization domain for multi-tenancy

        Returns:
            Optional[User]: User instance if authentication is successful, None otherwise
        """
        # Find user by email or username
        user_query = db.query(User).filter(
            (User.email == username) | (User.username == username)
        )

        # Add organization filter if domain is provided
        if organization_domain:
            organization = db.query(Organization).filter(
                Organization.domain == organization_domain
            ).first()
            if not organization:
                return None
            user_query = user_query.filter(User.organization_id == organization.id)

        user = user_query.first()

        # Verify user exists and password is correct
        if not user or not verify_password(password, user.hashed_password):
            return None

        # Check if user is active
        if not user.is_active:
            return None

        # Update login timestamp and reset failed login attempts
        user.last_login = datetime.utcnow()
        user.failed_login_attempts = 0
        db.commit()

        return user

    @staticmethod
    async def get_current_user(
        db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
    ) -> User:
        """
        Get the current user from the access token.

        Args:
            db: Database session
            token: JWT access token

        Returns:
            User: User instance

        Raises:
            HTTPException: If token is invalid or user is not found
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decode JWT token
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id: str = payload.get("sub")
            if user_id is None:
                raise credentials_exception
        except (JWTError, ValidationError):
            raise credentials_exception

        # Get user from database
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user",
            )

        return user

    @staticmethod
    async def get_current_active_superuser(
        current_user: User = Depends(get_current_user),
    ) -> User:
        """
        Get the current user and verify they are a superadmin.

        Args:
            current_user: Current authenticated user

        Returns:
            User: User instance if they are a superadmin

        Raises:
            HTTPException: If user is not a superadmin
        """
        if not current_user.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return current_user

    @staticmethod
    async def create_tokens_for_user(user: User) -> Dict[str, str]:
        """
        Create access and refresh tokens for a user.

        Args:
            user: User instance

        Returns:
            Dict[str, str]: Access and refresh tokens
        """
        return {
            "access_token": create_access_token(user.id),
            "refresh_token": create_refresh_token(user.id),
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    @staticmethod
    async def refresh_access_token(db: Session, refresh_token: str) -> Dict[str, str]:
        """
        Refresh an access token using a refresh token.

        Args:
            db: Database session
            refresh_token: JWT refresh token

        Returns:
            Dict[str, str]: New access and refresh tokens

        Raises:
            HTTPException: If refresh token is invalid
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decode refresh token
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            user_id: str = payload.get("sub")
            token_type: str = payload.get("type")

            # Verify it's a refresh token
            if user_id is None or token_type != "refresh":
                raise credentials_exception
        except (JWTError, ValidationError):
            raise credentials_exception

        # Get user from database
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user",
            )

        # Create new tokens
        return await AuthService.create_tokens_for_user(user)

    @staticmethod
    async def change_password(
        db: Session, user: User, current_password: str, new_password: str
    ) -> bool:
        """
        Change a user's password.

        Args:
            db: Database session
            user: User instance
            current_password: Current password
            new_password: New password

        Returns:
            bool: True if password was changed successfully

        Raises:
            HTTPException: If current password is incorrect
        """
        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
            )

        # Update password
        user.hashed_password = get_password_hash(new_password)
        user.password_last_changed = datetime.utcnow()
        db.commit()

        return True

    @staticmethod
    async def register_user(
        db: Session,
        email: str,
        password: str,
        organization_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> User:
        """
        Register a new user.

        Args:
            db: Database session
            email: User email
            password: Plain text password
            organization_id: Organization ID
            first_name: Optional first name
            last_name: Optional last name

        Returns:
            User: Created user instance

        Raises:
            HTTPException: If user already exists
        """
        # Check if user already exists
        existing_user = db.query(User).filter(
            User.email == email, User.organization_id == organization_id
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists",
            )

        # Create new user
        user = User(
            email=email,
            hashed_password=get_password_hash(password),
            organization_id=organization_id,
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            is_verified=False,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user
