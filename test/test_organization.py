"""
Comprehensive test suite for Organization management module.
Tests organization CRUD operations, settings, and multi-tenancy features.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.models.user import User
from app.models.organization import Organization
from app.services.organization_service import organization_service
from test.conftest import generate_unique_email, generate_unique_username

class TestOrganizationEndpoints:
    """Test organization API endpoints."""

    @pytest.mark.asyncio
    async def test_create_organization_success(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test successful organization creation."""
        org_data = {
            "name": f"Test Org {uuid.uuid4().hex[:8]}",
            "description": "Test organization",
            "subscription_tier": "professional",
            "contact_email": generate_unique_email(),
            "industry": "technology"
        }

        response = await client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == org_data["name"]
        assert data["subscription_tier"] == org_data["subscription_tier"]
        assert "id" in data
        assert "slug" in data

    @pytest.mark.asyncio
    async def test_create_organization_non_superuser(self, client: AsyncClient, auth_headers: dict):
        """Test that non-superusers cannot create organizations."""
        org_data = {
            "name": "Test Org",
            "description": "Test organization"
        }

        response = await client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_organization_by_id(self, client: AsyncClient, auth_headers: dict, test_organization: Organization):
        """Test getting organization by ID."""
        response = await client.get(
            f"/api/v1/organizations/{test_organization.id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_organization.id)
        assert data["name"] == test_organization.name

    @pytest.mark.asyncio
    async def test_list_organizations_superuser(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test listing organizations as superuser."""
        response = await client.get(
            "/api/v1/organizations/",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_list_organizations_regular_user(self, client: AsyncClient, auth_headers: dict):
        """Test that regular users cannot list all organizations."""
        response = await client.get(
            "/api/v1/organizations/",
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_organization(self, client: AsyncClient, superuser_auth_headers: dict, test_organization: Organization):
        """Test updating organization."""
        update_data = {
            "description": "Updated description",
            "website": "https://updated.example.com"
        }

        response = await client.patch(
            f"/api/v1/organizations/{test_organization.id}",
            json=update_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"
        assert data["website"] == "https://updated.example.com"

    @pytest.mark.asyncio
    async def test_delete_organization(self, client: AsyncClient, superuser_auth_headers: dict, db_session: AsyncSession):
        """Test deleting organization."""
        # Create organization to delete
        org_data = {
            "name": f"Delete Me {uuid.uuid4().hex[:8]}",
            "description": "Organization to delete"
        }
        organization = await organization_service.create_organization(db_session, org_data)

        response = await client.delete(
            f"/api/v1/organizations/{organization.id}",
            headers=superuser_auth_headers
        )

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_organization_settings(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test organization settings management."""
        settings_data = {
            "timezone": "America/New_York",
            "date_format": "MM/DD/YYYY",
            "require_2fa": True
        }

        response = await client.put(
            f"/api/v1/organizations/{test_organization.id}/settings",
            json=settings_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 200

class TestOrganizationService:
    """Test organization service methods."""

    @pytest.mark.asyncio
    async def test_create_organization_service(self, db_session: AsyncSession):
        """Test organization creation through service."""
        org_data = {
            "name": f"Service Test {uuid.uuid4().hex[:8]}",
            "description": "Service test organization",
            "subscription_tier": "basic"
        }

        organization = await organization_service.create_organization(db_session, org_data)

        assert organization is not None
        assert organization.name == org_data["name"]
        assert organization.subscription_tier == org_data["subscription_tier"]
        assert organization.slug is not None

    @pytest.mark.asyncio
    async def test_get_organization_by_slug(self, db_session: AsyncSession, test_organization: Organization):
        """Test getting organization by slug."""
        organization = await organization_service.get_organization_by_slug(
            db_session, test_organization.slug
        )

        assert organization is not None
        assert organization.id == test_organization.id

    @pytest.mark.asyncio
    async def test_update_organization_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test updating organization through service."""
        update_data = {
            "description": "Updated through service",
            "max_users": 500
        }

        updated_org = await organization_service.update_organization(
            db_session, test_organization.id, update_data
        )

        assert updated_org.description == "Updated through service"
        assert updated_org.max_users == 500

    @pytest.mark.asyncio
    async def test_list_organizations_service(self, db_session: AsyncSession):
        """Test listing organizations through service."""
        organizations = await organization_service.list_organizations(
            db_session, skip=0, limit=10
        )

        assert isinstance(organizations, list)

    @pytest.mark.asyncio
    async def test_get_organization_stats(self, db_session: AsyncSession, test_organization: Organization):
        """Test getting organization statistics."""
        stats = await organization_service.get_organization_stats(
            db_session, test_organization.id
        )

        assert "total_users" in stats
        assert "active_users" in stats
        assert "total_locations" in stats

class TestOrganizationValidation:
    """Test organization validation rules."""

    @pytest.mark.asyncio
    async def test_create_organization_duplicate_name(self, client: AsyncClient, superuser_auth_headers: dict, test_organization: Organization):
        """Test creating organization with duplicate name."""
        org_data = {
            "name": test_organization.name,
            "description": "Duplicate name test"
        }

        response = await client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_create_organization_invalid_subscription_tier(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test creating organization with invalid subscription tier."""
        org_data = {
            "name": f"Invalid Tier {uuid.uuid4().hex[:8]}",
            "subscription_tier": "invalid_tier"
        }

        response = await client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_organization_missing_name(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test creating organization without name."""
        org_data = {
            "description": "Missing name test"
        }

        response = await client.post(
            "/api/v1/organizations/",
            json=org_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 422

class TestOrganizationFeatures:
    """Test organization-specific features."""

    @pytest.mark.asyncio
    async def test_organization_user_limit(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization, db_session: AsyncSession):
        """Test organization user limit enforcement."""
        # Set low user limit
        await organization_service.update_organization(
            db_session, test_organization.id, {"max_users": 2}
        )

        # Try to create users beyond limit
        for i in range(3):
            user_data = {
                "username": f"limituser{i}_{uuid.uuid4().hex[:4]}",
                "email": f"limituser{i}@example.com",
                "password": "TestPassword123!",
                "first_name": "Limit",
                "last_name": f"User{i}",
                "organization_id": str(test_organization.id)
            }

            response = await client.post(
                "/api/v1/users/",
                json=user_data,
                headers=admin_auth_headers
            )

            if i < 2:  # First 2 should succeed
                assert response.status_code == 201
            else:  # 3rd should fail due to limit
                assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_organization_subscription_features(self, db_session: AsyncSession, test_organization: Organization):
        """Test subscription tier feature access."""
        # Test basic tier limitations
        test_organization.subscription_tier = "basic"
        await db_session.commit()

        features = await organization_service.get_subscription_features(
            db_session, test_organization.id
        )

        assert "basic_features" in features
        assert features["max_locations"] <= 10

        # Test professional tier features
        test_organization.subscription_tier = "professional"
        await db_session.commit()

        features = await organization_service.get_subscription_features(
            db_session, test_organization.id
        )

        assert "advanced_features" in features
        assert features["max_locations"] > 10

class TestOrganizationSecurity:
    """Test organization security features."""

    @pytest.mark.asyncio
    async def test_organization_isolation(self, client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
        """Test that organizations are properly isolated."""
        # Create another organization
        other_org_data = {
            "name": f"Other Org {uuid.uuid4().hex[:8]}",
            "description": "Other organization"
        }
        other_org = await organization_service.create_organization(db_session, other_org_data)

        # Try to access other organization's data
        response = await client.get(
            f"/api/v1/organizations/{other_org.id}",
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_organization_admin_permissions(self, client: AsyncClient, auth_headers: dict, admin_auth_headers: dict, test_organization: Organization):
        """Test organization admin permission differences."""
        # Regular user cannot update organization
        update_data = {"description": "Unauthorized update"}

        response = await client.patch(
            f"/api/v1/organizations/{test_organization.id}",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code == 403

        # Admin can update organization
        response = await client.patch(
            f"/api/v1/organizations/{test_organization.id}",
            json=update_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 200
