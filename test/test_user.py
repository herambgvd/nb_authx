"""
Comprehensive test suite for User management module.
Tests user CRUD operations, permissions, and user lifecycle management.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from unittest.mock import patch

from app.models.user import User
from app.models.organization import Organization
from app.services.user_service import user_service
from test.conftest import generate_unique_email, generate_unique_username

class TestUserEndpoints:
    """Test user API endpoints."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test successful user creation."""
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "organization_id": str(test_organization.id)
        }

        response = await client.post(
            "/api/v1/users/",
            json=user_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, client: AsyncClient, admin_auth_headers: dict, test_user: User, test_organization: Organization):
        """Test user creation with duplicate username."""
        user_data = {
            "username": test_user.username,
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "organization_id": str(test_organization.id)
        }

        response = await client.post(
            "/api/v1/users/",
            json=user_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_get_user_by_id(self, client: AsyncClient, auth_headers: dict, test_user: User):
        """Test getting user by ID."""
        response = await client.get(
            f"/api/v1/users/{test_user.id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_user.id)
        assert data["username"] == test_user.username

    @pytest.mark.asyncio
    async def test_get_user_unauthorized(self, client: AsyncClient, test_user: User):
        """Test getting user without authentication."""
        response = await client.get(f"/api/v1/users/{test_user.id}")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_users(self, client: AsyncClient, admin_auth_headers: dict):
        """Test listing users."""
        response = await client.get(
            "/api/v1/users/",
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_update_user(self, client: AsyncClient, auth_headers: dict, test_user: User):
        """Test updating user information."""
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }

        response = await client.patch(
            f"/api/v1/users/{test_user.id}",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"

    @pytest.mark.asyncio
    async def test_delete_user(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization, db_session: AsyncSession):
        """Test deleting a user."""
        # Create a user to delete
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Delete",
            "last_name": "Me"
        }
        user = await user_service.create_user(db_session, user_data, test_organization.id)

        response = await client.delete(
            f"/api/v1/users/{user.id}",
            headers=admin_auth_headers
        )

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_activate_deactivate_user(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization, db_session: AsyncSession):
        """Test activating and deactivating users."""
        # Create a user
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User"
        }
        user = await user_service.create_user(db_session, user_data, test_organization.id)

        # Deactivate user
        response = await client.post(
            f"/api/v1/users/{user.id}/deactivate",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

        # Activate user
        response = await client.post(
            f"/api/v1/users/{user.id}/activate",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

class TestUserService:
    """Test user service methods."""

    @pytest.mark.asyncio
    async def test_create_user_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test user creation through service."""
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Service",
            "last_name": "Test"
        }

        user = await user_service.create_user(db_session, user_data, test_organization.id)

        assert user is not None
        assert user.username == user_data["username"]
        assert user.email == user_data["email"]
        assert user.organization_id == test_organization.id

    @pytest.mark.asyncio
    async def test_get_user_by_username(self, db_session: AsyncSession, test_user: User):
        """Test getting user by username."""
        user = await user_service.get_user_by_username(db_session, test_user.username)

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, db_session: AsyncSession, test_user: User):
        """Test getting user by email."""
        user = await user_service.get_user_by_email(db_session, test_user.email)

        assert user is not None
        assert user.id == test_user.id

    @pytest.mark.asyncio
    async def test_update_user_service(self, db_session: AsyncSession, test_user: User):
        """Test updating user through service."""
        update_data = {
            "first_name": "Updated",
            "last_name": "Service"
        }

        updated_user = await user_service.update_user(db_session, test_user.id, update_data)

        assert updated_user.first_name == "Updated"
        assert updated_user.last_name == "Service"

    @pytest.mark.asyncio
    async def test_delete_user_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test deleting user through service."""
        # Create user to delete
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Delete",
            "last_name": "Service"
        }
        user = await user_service.create_user(db_session, user_data, test_organization.id)

        # Delete user
        result = await user_service.delete_user(db_session, user.id)

        assert result is True

        # Verify user is deleted
        deleted_user = await user_service.get_user_by_id(db_session, user.id)
        assert deleted_user is None

    @pytest.mark.asyncio
    async def test_list_users_by_organization(self, db_session: AsyncSession, test_organization: Organization):
        """Test listing users by organization."""
        users = await user_service.list_users_by_organization(
            db_session, test_organization.id, skip=0, limit=10
        )

        assert isinstance(users, list)
        for user in users:
            assert user.organization_id == test_organization.id

class TestUserValidation:
    """Test user validation rules."""

    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test user creation with invalid email."""
        user_data = {
            "username": generate_unique_username(),
            "email": "invalid-email",
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "organization_id": str(test_organization.id)
        }

        response = await client.post(
            "/api/v1/users/",
            json=user_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_user_weak_password(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test user creation with weak password."""
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "weak",
            "first_name": "Test",
            "last_name": "User",
            "organization_id": str(test_organization.id)
        }

        response = await client.post(
            "/api/v1/users/",
            json=user_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

class TestUserPermissions:
    """Test user permission scenarios."""

    @pytest.mark.asyncio
    async def test_regular_user_cannot_create_user(self, client: AsyncClient, auth_headers: dict, test_organization: Organization):
        """Test that regular users cannot create other users."""
        user_data = {
            "username": generate_unique_username(),
            "email": generate_unique_email(),
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "organization_id": str(test_organization.id)
        }

        response = await client.post(
            "/api/v1/users/",
            json=user_data,
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_user_can_view_own_profile(self, client: AsyncClient, auth_headers: dict, test_user: User):
        """Test that users can view their own profile."""
        response = await client.get(
            f"/api/v1/users/{test_user.id}",
            headers=auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_user_can_update_own_profile(self, client: AsyncClient, auth_headers: dict, test_user: User):
        """Test that users can update their own profile."""
        update_data = {
            "first_name": "Updated"
        }

        response = await client.patch(
            f"/api/v1/users/{test_user.id}",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code == 200
