"""
Comprehensive test suite for Authentication module.
Tests login, logout, token management, password reset, and security features.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from app.models.user import User
from app.models.organization import Organization
from app.services.auth_service import auth_service
from app.services.user_service import user_service

class TestAuthEndpoints:
    """Test authentication API endpoints."""

    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, test_user: User):
        """Test successful user login."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client: AsyncClient, test_user: User):
        """Test login with invalid credentials."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": test_user.username,
                "password": "wrongpassword"
            }
        )

        assert response.status_code == 401
        data = response.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent user."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": "nonexistent",
                "password": "TestPassword123!"
            }
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client: AsyncClient, test_user: User, db_session: AsyncSession):
        """Test login with inactive user."""
        # Deactivate user
        test_user.is_active = False
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_token_refresh_success(self, client: AsyncClient, test_user: User, db_session: AsyncSession):
        """Test successful token refresh."""
        # First login to get refresh token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": test_user.username,
                "password": "TestPassword123!"
            }
        )

        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token to get new access token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "expires_in" in data

    @pytest.mark.asyncio
    async def test_token_refresh_invalid_token(self, client: AsyncClient):
        """Test token refresh with invalid token."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid_token"}
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_success(self, client: AsyncClient, auth_headers: dict):
        """Test successful logout."""
        response = await client.post(
            "/api/v1/auth/logout",
            headers=auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_logout_without_auth(self, client: AsyncClient):
        """Test logout without authentication."""
        response = await client.post("/api/v1/auth/logout")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_password_reset_request(self, client: AsyncClient, test_user: User):
        """Test password reset request."""
        with patch('app.services.email_service.send_password_reset_email') as mock_email:
            response = await client.post(
                "/api/v1/auth/password-reset",
                json={"email": test_user.email}
            )

            assert response.status_code == 200
            mock_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_password_reset_nonexistent_email(self, client: AsyncClient):
        """Test password reset with non-existent email."""
        response = await client.post(
            "/api/v1/auth/password-reset",
            json={"email": "nonexistent@example.com"}
        )

        # Should return 200 for security reasons (don't reveal if email exists)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_password_reset_confirm(self, client: AsyncClient, test_user: User, db_session: AsyncSession):
        """Test password reset confirmation."""
        # Generate reset token
        reset_token = await auth_service.create_password_reset_token(db_session, test_user.email)

        response = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={
                "token": reset_token,
                "new_password": "NewPassword123!"
            }
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_password_change(self, client: AsyncClient, auth_headers: dict):
        """Test password change for authenticated user."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "TestPassword123!",
                "new_password": "NewPassword123!"
            },
            headers=auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_password_change_wrong_current(self, client: AsyncClient, auth_headers: dict):
        """Test password change with wrong current password."""
        response = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword",
                "new_password": "NewPassword123!"
            },
            headers=auth_headers
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_register_success(self, client: AsyncClient, test_organization: Organization):
        """Test successful user registration."""
        with patch('app.services.email_service.send_verification_email') as mock_email:
            response = await client.post(
                "/api/v1/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "NewPassword123!",
                    "first_name": "New",
                    "last_name": "User",
                    "organization_id": str(test_organization.id)
                }
            )

            assert response.status_code == 201
            data = response.json()
            assert data["username"] == "newuser"
            mock_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, client: AsyncClient, test_user: User, test_organization: Organization):
        """Test registration with duplicate username."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "username": test_user.username,
                "email": "different@example.com",
                "password": "Password123!",
                "first_name": "Test",
                "last_name": "User",
                "organization_id": str(test_organization.id)
            }
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client: AsyncClient, test_user: User, test_organization: Organization):
        """Test registration with duplicate email."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "username": "differentuser",
                "email": test_user.email,
                "password": "Password123!",
                "first_name": "Test",
                "last_name": "User",
                "organization_id": str(test_organization.id)
            }
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_email_verification(self, client: AsyncClient, test_user: User, db_session: AsyncSession):
        """Test email verification."""
        # Generate verification token
        verification_token = await auth_service.create_email_verification_token(db_session, test_user.email)

        response = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": verification_token}
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_email_verification_invalid_token(self, client: AsyncClient):
        """Test email verification with invalid token."""
        response = await client.post(
            "/api/v1/auth/verify-email",
            json={"token": "invalid_token"}
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_me_endpoint(self, client: AsyncClient, auth_headers: dict, test_user: User):
        """Test getting current user information."""
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_user.username
        assert data["email"] == test_user.email

    @pytest.mark.asyncio
    async def test_me_endpoint_unauthorized(self, client: AsyncClient):
        """Test me endpoint without authentication."""
        response = await client.get("/api/v1/auth/me")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_sessions_list(self, client: AsyncClient, auth_headers: dict):
        """Test listing user sessions."""
        response = await client.get(
            "/api/v1/auth/sessions",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data

    @pytest.mark.asyncio
    async def test_session_revoke(self, client: AsyncClient, auth_headers: dict):
        """Test revoking a user session."""
        # First get sessions
        sessions_response = await client.get(
            "/api/v1/auth/sessions",
            headers=auth_headers
        )
        sessions = sessions_response.json()["sessions"]

        if sessions:
            session_id = sessions[0]["id"]
            response = await client.delete(
                f"/api/v1/auth/sessions/{session_id}",
                headers=auth_headers
            )

            assert response.status_code == 200

class TestAuthService:
    """Test authentication service methods."""

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, db_session: AsyncSession, test_user: User, sample_request_info: dict):
        """Test successful user authentication."""
        user_data, auth_context = await auth_service.authenticate_user(
            db_session, test_user.username, "TestPassword123!", sample_request_info
        )

        assert user_data is not None
        assert user_data.id == test_user.id
        assert auth_context is not None

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, db_session: AsyncSession, test_user: User, sample_request_info: dict):
        """Test authentication with wrong password."""
        with pytest.raises(Exception):
            await auth_service.authenticate_user(
                db_session, test_user.username, "wrongpassword", sample_request_info
            )

    @pytest.mark.asyncio
    async def test_create_access_token(self):
        """Test access token creation."""
        data = {"sub": "test_user_id"}
        token = await auth_service.create_access_token(data)

        assert token is not None
        assert isinstance(token, str)

    @pytest.mark.asyncio
    async def test_create_refresh_token(self):
        """Test refresh token creation."""
        data = {"sub": "test_user_id"}
        token = await auth_service.create_refresh_token(data)

        assert token is not None
        assert isinstance(token, str)

    @pytest.mark.asyncio
    async def test_verify_token(self):
        """Test token verification."""
        data = {"sub": "test_user_id"}
        token = await auth_service.create_access_token(data)

        payload = await auth_service.verify_token(token)

        assert payload is not None
        assert payload["sub"] == "test_user_id"

    @pytest.mark.asyncio
    async def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        with pytest.raises(Exception):
            await auth_service.verify_token("invalid_token")

    @pytest.mark.asyncio
    async def test_password_reset_token_creation(self, db_session: AsyncSession, test_user: User):
        """Test password reset token creation."""
        token = await auth_service.create_password_reset_token(db_session, test_user.email)

        assert token is not None
        assert isinstance(token, str)

    @pytest.mark.asyncio
    async def test_password_reset_token_verification(self, db_session: AsyncSession, test_user: User):
        """Test password reset token verification."""
        token = await auth_service.create_password_reset_token(db_session, test_user.email)

        user = await auth_service.verify_password_reset_token(db_session, token)

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_email_verification_token_creation(self, db_session: AsyncSession, test_user: User):
        """Test email verification token creation."""
        token = await auth_service.create_email_verification_token(db_session, test_user.email)

        assert token is not None
        assert isinstance(token, str)

    @pytest.mark.asyncio
    async def test_email_verification_token_verification(self, db_session: AsyncSession, test_user: User):
        """Test email verification token verification."""
        token = await auth_service.create_email_verification_token(db_session, test_user.email)

        user = await auth_service.verify_email_verification_token(db_session, token)

        assert user is not None
        assert user.id == test_user.id

class TestAuthSecurity:
    """Test authentication security features."""

    @pytest.mark.asyncio
    async def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "TestPassword123!"
        hashed = await auth_service.hash_password(password)

        assert hashed != password
        assert await auth_service.verify_password(password, hashed)

    @pytest.mark.asyncio
    async def test_password_verification_failure(self):
        """Test password verification failure."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = await auth_service.hash_password(password)

        assert not await auth_service.verify_password(wrong_password, hashed)

    @pytest.mark.asyncio
    async def test_rate_limiting(self, client: AsyncClient, test_user: User):
        """Test rate limiting on login attempts."""
        # Attempt multiple failed logins
        for _ in range(6):  # Assuming rate limit is 5 attempts
            await client.post(
                "/api/v1/auth/login",
                json={
                    "username": test_user.username,
                    "password": "wrongpassword"
                }
            )

        # Next attempt should be rate limited
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "username": test_user.username,
                "password": "wrongpassword"
            }
        )

        assert response.status_code == 429  # Too Many Requests

    @pytest.mark.asyncio
    async def test_token_expiration(self):
        """Test token expiration."""
        data = {"sub": "test_user_id"}
        # Create token with very short expiration
        token = await auth_service.create_access_token(
            data, expires_delta=timedelta(seconds=-1)
        )

        with pytest.raises(Exception):
            await auth_service.verify_token(token)

class TestAuthValidation:
    """Test authentication input validation."""

    @pytest.mark.asyncio
    async def test_login_validation_missing_username(self, client: AsyncClient):
        """Test login validation with missing username."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"password": "TestPassword123!"}
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_login_validation_missing_password(self, client: AsyncClient):
        """Test login validation with missing password."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"username": "testuser"}
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_register_validation_weak_password(self, client: AsyncClient, test_organization: Organization):
        """Test registration validation with weak password."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "weak",
                "first_name": "New",
                "last_name": "User",
                "organization_id": str(test_organization.id)
            }
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_register_validation_invalid_email(self, client: AsyncClient, test_organization: Organization):
        """Test registration validation with invalid email."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "username": "newuser",
                "email": "invalid-email",
                "password": "TestPassword123!",
                "first_name": "New",
                "last_name": "User",
                "organization_id": str(test_organization.id)
            }
        )

        assert response.status_code == 422
