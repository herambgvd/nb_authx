"""
Comprehensive test suite for Location management module.
Tests location CRUD operations, hierarchies, and geographic features.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.models.user import User
from app.models.organization import Organization
from app.models.location import Location
from app.models.location_group import LocationGroup
from app.services.location_service import location_service

class TestLocationEndpoints:
    """Test location API endpoints."""

    @pytest.mark.asyncio
    async def test_create_location_success(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization):
        """Test successful location creation."""
        location_data = {
            "name": f"Test Location {uuid.uuid4().hex[:8]}",
            "description": "Test location description",
            "location_type": "office",
            "address": "123 Test Street",
            "city": "Test City",
            "state": "Test State",
            "country": "Test Country",
            "postal_code": "12345",
            "latitude": 40.7128,
            "longitude": -74.0060
        }

        response = await client.post(
            "/api/v1/locations/",
            json=location_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == location_data["name"]
        assert data["location_type"] == location_data["location_type"]
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_location_non_admin(self, client: AsyncClient, auth_headers: dict):
        """Test that non-admin users cannot create locations."""
        location_data = {
            "name": "Unauthorized Location",
            "location_type": "office"
        }

        response = await client.post(
            "/api/v1/locations/",
            json=location_data,
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_locations(self, client: AsyncClient, auth_headers: dict):
        """Test listing locations."""
        response = await client.get(
            "/api/v1/locations/",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_location_by_id(self, client: AsyncClient, auth_headers: dict, test_location: Location):
        """Test getting location by ID."""
        response = await client.get(
            f"/api/v1/locations/{test_location.id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_location.id)
        assert data["name"] == test_location.name

    @pytest.mark.asyncio
    async def test_update_location(self, client: AsyncClient, admin_auth_headers: dict, test_location: Location):
        """Test updating location."""
        update_data = {
            "description": "Updated description",
            "address": "456 Updated Street"
        }

        response = await client.patch(
            f"/api/v1/locations/{test_location.id}",
            json=update_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"
        assert data["address"] == "456 Updated Street"

    @pytest.mark.asyncio
    async def test_delete_location(self, client: AsyncClient, admin_auth_headers: dict, test_organization: Organization, db_session: AsyncSession):
        """Test deleting location."""
        # Create location to delete
        location_data = {
            "name": f"Delete Location {uuid.uuid4().hex[:8]}",
            "location_type": "office"
        }
        location = await location_service.create_location(db_session, location_data, test_organization.id)

        response = await client.delete(
            f"/api/v1/locations/{location.id}",
            headers=admin_auth_headers
        )

        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_search_locations(self, client: AsyncClient, auth_headers: dict):
        """Test searching locations."""
        response = await client.get(
            "/api/v1/locations/search?q=test",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

class TestLocationService:
    """Test location service methods."""

    @pytest.mark.asyncio
    async def test_create_location_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test location creation through service."""
        location_data = {
            "name": f"Service Location {uuid.uuid4().hex[:8]}",
            "description": "Service test location",
            "location_type": "warehouse",
            "address": "789 Service Ave"
        }

        location = await location_service.create_location(db_session, location_data, test_organization.id)

        assert location is not None
        assert location.name == location_data["name"]
        assert location.organization_id == test_organization.id

    @pytest.mark.asyncio
    async def test_get_locations_by_type(self, db_session: AsyncSession, test_organization: Organization):
        """Test getting locations by type."""
        locations = await location_service.get_locations_by_type(
            db_session, test_organization.id, "office"
        )

        assert isinstance(locations, list)
        for location in locations:
            assert location.location_type == "office"

    @pytest.mark.asyncio
    async def test_search_locations_service(self, db_session: AsyncSession, test_organization: Organization):
        """Test searching locations through service."""
        results = await location_service.search_locations(
            db_session, test_organization.id, "test"
        )

        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_get_nearby_locations(self, db_session: AsyncSession, test_organization: Organization):
        """Test getting nearby locations."""
        # Create a location with coordinates
        location_data = {
            "name": f"GPS Location {uuid.uuid4().hex[:8]}",
            "location_type": "office",
            "latitude": 40.7128,
            "longitude": -74.0060
        }
        location = await location_service.create_location(db_session, location_data, test_organization.id)

        # Search for nearby locations
        nearby = await location_service.get_nearby_locations(
            db_session, test_organization.id, 40.7130, -74.0058, radius_km=1.0
        )

        assert isinstance(nearby, list)

class TestLocationGroups:
    """Test location group functionality."""

    @pytest.mark.asyncio
    async def test_create_location_group(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating location group."""
        group_data = {
            "name": f"Test Group {uuid.uuid4().hex[:8]}",
            "description": "Test location group"
        }

        response = await client.post(
            "/api/v1/locations/groups/",
            json=group_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == group_data["name"]

    @pytest.mark.asyncio
    async def test_add_location_to_group(self, client: AsyncClient, admin_auth_headers: dict, test_location: Location, test_location_group: LocationGroup):
        """Test adding location to group."""
        response = await client.post(
            f"/api/v1/locations/groups/{test_location_group.id}/locations",
            json={"location_id": str(test_location.id)},
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_list_group_locations(self, client: AsyncClient, auth_headers: dict, test_location_group: LocationGroup):
        """Test listing locations in group."""
        response = await client.get(
            f"/api/v1/locations/groups/{test_location_group.id}/locations",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

class TestLocationValidation:
    """Test location validation rules."""

    @pytest.mark.asyncio
    async def test_create_location_invalid_type(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating location with invalid type."""
        location_data = {
            "name": f"Invalid Type {uuid.uuid4().hex[:8]}",
            "location_type": "invalid_type"
        }

        response = await client.post(
            "/api/v1/locations/",
            json=location_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_location_invalid_coordinates(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating location with invalid coordinates."""
        location_data = {
            "name": f"Invalid GPS {uuid.uuid4().hex[:8]}",
            "location_type": "office",
            "latitude": 200.0,  # Invalid latitude
            "longitude": -74.0060
        }

        response = await client.post(
            "/api/v1/locations/",
            json=location_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_create_location_missing_name(self, client: AsyncClient, admin_auth_headers: dict):
        """Test creating location without name."""
        location_data = {
            "location_type": "office"
        }

        response = await client.post(
            "/api/v1/locations/",
            json=location_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 422

class TestLocationHierarchy:
    """Test location hierarchy and relationships."""

    @pytest.mark.asyncio
    async def test_create_child_location(self, client: AsyncClient, admin_auth_headers: dict, test_location: Location):
        """Test creating child location."""
        child_data = {
            "name": f"Child Location {uuid.uuid4().hex[:8]}",
            "location_type": "room",
            "parent_id": str(test_location.id)
        }

        response = await client.post(
            "/api/v1/locations/",
            json=child_data,
            headers=admin_auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["parent_id"] == str(test_location.id)

    @pytest.mark.asyncio
    async def test_get_location_children(self, client: AsyncClient, auth_headers: dict, test_location: Location):
        """Test getting child locations."""
        response = await client.get(
            f"/api/v1/locations/{test_location.id}/children",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_location_ancestors(self, client: AsyncClient, auth_headers: dict, test_location: Location):
        """Test getting location ancestors."""
        response = await client.get(
            f"/api/v1/locations/{test_location.id}/ancestors",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

class TestLocationPermissions:
    """Test location-based permissions."""

    @pytest.mark.asyncio
    async def test_user_location_access(self, client: AsyncClient, auth_headers: dict, test_location: Location):
        """Test user access to locations."""
        response = await client.get(
            f"/api/v1/locations/{test_location.id}",
            headers=auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_location_organization_isolation(self, client: AsyncClient, auth_headers: dict, db_session: AsyncSession):
        """Test that locations are isolated by organization."""
        # Create location in different organization
        other_org_data = {
            "name": f"Other Org {uuid.uuid4().hex[:8]}",
            "description": "Other organization"
        }
        from app.services.organization_service import organization_service
        other_org = await organization_service.create_organization(db_session, other_org_data)

        other_location_data = {
            "name": "Other Location",
            "location_type": "office"
        }
        other_location = await location_service.create_location(
            db_session, other_location_data, other_org.id
        )

        # Try to access location from different organization
        response = await client.get(
            f"/api/v1/locations/{other_location.id}",
            headers=auth_headers
        )

        assert response.status_code == 403
