"""
Comprehensive test suite for Role and Permissions management module.
Tests role CRUD operations, permission assignments, and access control.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.models.user import User
from app.models.organization import Organization
from app.models.role import Role
from app.services.role_service import role_service

class TestRoleEndpoints:
    """Test role API endpoints."""

    @pytest.mark.asyncio
    async def test_create_role_success(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test successful role creation."""
        role_data = {
            "name": f"Test Role {uuid.uuid4().hex[:8]}",
            "description": "Test role description",
            "permissions_config": {
                "users": ["read", "write"],
                "locations": ["read"]
            }
        }

        response = await client.post(
            "/api/v1/roles/",
            json=role_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == role_data["name"]
        assert "id" in data
        assert "slug" in data

    @pytest.mark.asyncio
    async def test_create_role_non_admin(self, client: AsyncClient, auth_headers: dict):
        """Test that non-admin users cannot create roles."""
        role_data = {
            "name": "Unauthorized Role",
            "description": "Should not be created"
        }

        response = await client.post(
            "/api/v1/roles/",
            json=role_data,
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_roles(self, client: AsyncClient, admin_auth_headers: dict):
        """Test listing roles."""
        response = await client.get(
            "/api/v1/roles/",
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_role_by_id(self, client: AsyncClient, admin_auth_headers: dict, test_role: Role):
        """Test getting role by ID."""
        response = await client.get(
            f"/api/v1/roles/{test_role.id}",
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_role.id)
        assert data["name"] == test_role.name

    @pytest.mark.asyncio
    async def test_update_role(self, client: AsyncClient, admin_auth_headers: dict, test_role: Role):
        """Test updating role."""
        update_data = {
            "description": "Updated description",
            "permissions_config": {
                "users": ["read"],
                "locations": ["read", "write"]
            }
        }

        response = await client.patch(
            f"/api/v1/roles/{test_role.id}",
            json=update_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"

    @pytest.mark.asyncio
    async def test_delete_role(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization, db_session: AsyncSession):
        """Test deleting role."""
        # Create role to delete
        role_data = {
            "name": f"Delete Role {uuid.uuid4().hex[:8]}",
            "description": "Role to delete"
        }
        role = await role_service.create_role(db_session, role_data, test_organization.id)

        response = await client.delete(
            f"/api/v1/roles/{role.id}",
            headers=admin_auth_headers
        )

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_assign_role_to_user(self, client: AsyncClient, admin_auth_headers: dict, test_user: User, test_role: Role):
        """Test assigning role to user."""
        response = await client.post(
            f"/api/v1/roles/{test_role.id}/assign",
            json={"user_id": str(test_user.id)},
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_remove_role_from_user(self, client: AsyncClient, admin_auth_headers: dict, test_user: User, test_role: Role):
        """Test removing role from user."""
        # First assign the role
        await client.post(
            f"/api/v1/roles/{test_role.id}/assign",
            json={"user_id": str(test_user.id)},
            headers=admin_auth_headers
        )

        # Then remove it
        response = await client.post(
            f"/api/v1/roles/{test_role.id}/remove",
            json={"user_id": str(test_user.id)},
            headers=admin_auth_headers
        )

        assert response.status_code == 200

class TestRoleService:
    """Test role service methods."""

    @pytest.mark.asyncio
    async def test_create_role_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test role creation through service."""
        role_data = {
            "name": f"Service Role {uuid.uuid4().hex[:8]}",
            "description": "Service test role",
            "permissions_config": {
                "test": ["read", "write"]
            }
        }

        role = await role_service.create_role(db_session, role_data, test_organization.id)

        assert role is not None
        assert role.name == role_data["name"]
        assert role.organization_id == test_organization.id

    @pytest.mark.asyncio
    async def test_get_role_by_slug(self, db_session: AsyncSession, test_role: Role):
        """Test getting role by slug."""
        role = await role_service.get_role_by_slug(
            db_session, test_role.slug, test_role.organization_id
        )

        assert role is not None
        assert role.id == test_role.id

    @pytest.mark.asyncio
    async def test_assign_remove_role_service(self, db_session: AsyncSession, test_user: User, test_role: Role):
        """Test assigning and removing roles through service."""
        # Assign role
        result = await role_service.assign_role_to_user(db_session, test_user.id, test_role.id)
        assert result is True

        # Check assignment
        user_roles = await role_service.get_user_roles(db_session, test_user.id)
        role_ids = [role.id for role in user_roles]
        assert test_role.id in role_ids

        # Remove role
        result = await role_service.remove_role_from_user(db_session, test_user.id, test_role.id)
        assert result is True

        # Check removal
        user_roles = await role_service.get_user_roles(db_session, test_user.id)
        role_ids = [role.id for role in user_roles]
        assert test_role.id not in role_ids

    @pytest.mark.asyncio
    async def test_get_user_permissions(self, db_session: AsyncSession, test_user: User, test_role: Role):
        """Test getting user permissions through roles."""
        # Assign role to user
        await role_service.assign_role_to_user(db_session, test_user.id, test_role.id)

        # Get permissions
        permissions = await role_service.get_user_permissions(db_session, test_user.id)

        assert isinstance(permissions, list)
        # Should include permissions from test_role

class TestPermissionValidation:
    """Test permission validation and checking."""

    @pytest.mark.asyncio
    async def test_user_has_permission(self, db_session: AsyncSession, test_user: User, test_role: Role):
        """Test checking if user has specific permission."""
        # Assign role with specific permissions
        await role_service.assign_role_to_user(db_session, test_user.id, test_role.id)

        # Check permission
        has_permission = await role_service.user_has_permission(
            db_session, test_user.id, "users:read"
        )

        assert has_permission is True

    @pytest.mark.asyncio
    async def test_user_lacks_permission(self, db_session: AsyncSession, test_user: User):
        """Test checking permission user doesn't have."""
        has_permission = await role_service.user_has_permission(
            db_session, test_user.id, "admin:delete"
        )

        assert has_permission is False

    @pytest.mark.asyncio
    async def test_superuser_has_all_permissions(self, db_session: AsyncSession, test_superuser: User):
        """Test that superusers have all permissions."""
        has_permission = await role_service.user_has_permission(
            db_session, test_superuser.id, "any:permission"
        )

        assert has_permission is True

class TestRoleValidation:
    """Test role validation rules."""

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, client: AsyncClient, admin_auth_headers: dict, test_role: Role):
        """Test creating role with duplicate name in same organization."""
        role_data = {
            "name": test_role.name,
            "description": "Duplicate name test"
        }

        response = await client.post(
            "/api/v1/roles/",
            json=role_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_create_role_invalid_permissions(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating role with invalid permissions format."""
        role_data = {
            "name": f"Invalid Perms {uuid.uuid4().hex[:8]}",
            "permissions_config": "invalid_format"
        }

        response = await client.post(
            "/api/v1/roles/",
            json=role_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_role_missing_name(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating role without name."""
        role_data = {
            "description": "Missing name test"
        }

        response = await client.post(
            "/api/v1/roles/",
            json=role_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

class TestBuiltinRoles:
    """Test built-in system roles."""

    @pytest.mark.asyncio
    async def test_admin_role_exists(self, db_session: AsyncSession, test_organization: Organization):
        """Test that admin role exists for organization."""
        admin_role = await role_service.get_role_by_slug(
            db_session, "administrator", test_organization.id
        )

        assert admin_role is not None
        assert admin_role.is_system_role is True

    @pytest.mark.asyncio
    async def test_cannot_delete_system_role(self, client: AsyncClient, admin_auth_headers: dict, db_session: AsyncSession, test_organization: Organization):
        """Test that system roles cannot be deleted."""
        admin_role = await role_service.get_role_by_slug(
            db_session, "administrator", test_organization.id
        )

        if admin_role:
            response = await client.delete(
                f"/api/v1/roles/{admin_role.id}",
                headers=admin_auth_headers
            )

            assert response.status_code == 400  # Should prevent deletion

    @pytest.mark.asyncio
    async def test_system_role_permissions(self, db_session: AsyncSession, test_organization: Organization):
        """Test that system roles have correct permissions."""
        admin_role = await role_service.get_role_by_slug(
            db_session, "administrator", test_organization.id
        )

        if admin_role:
            permissions = role_service.get_role_permissions(admin_role)
            assert "users:read" in permissions
            assert "users:write" in permissions
            assert "roles:read" in permissions
            assert "roles:write" in permissions
