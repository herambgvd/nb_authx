"""
Comprehensive test suite for Admin management module.
Tests admin operations, system configuration, and administrative features.
"""
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from unittest.mock import patch

from app.models.user import User
from app.models.organization import Organization

class TestAdminEndpoints:
    """Test admin API endpoints."""

    @pytest.mark.asyncio
    async def test_admin_dashboard(self, client: AsyncClient, admin_auth_headers: dict):
        """Test admin dashboard access."""
        response = await client.get(
            "/api/v1/admin/dashboard",
            headers=admin_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "statistics" in data
        assert "recent_activity" in data

    @pytest.mark.asyncio
    async def test_admin_dashboard_non_admin(self, client: AsyncClient, auth_headers: dict):
        """Test that non-admin users cannot access admin dashboard."""
        response = await client.get(
            "/api/v1/admin/dashboard",
            headers=auth_headers
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_system_statistics(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test getting system statistics."""
        response = await client.get(
            "/api/v1/admin/stats",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_users" in data
        assert "total_organizations" in data
        assert "system_health" in data

    @pytest.mark.asyncio
    async def test_user_impersonation(self, client: AsyncClient, superuser_auth_headers: dict, test_user: User):
        """Test user impersonation functionality."""
        response = await client.post(
            f"/api/v1/admin/impersonate/{test_user.id}",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "impersonation_token" in data

    @pytest.mark.asyncio
    async def test_stop_impersonation(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test stopping user impersonation."""
        response = await client.post(
            "/api/v1/admin/stop-impersonation",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_system_configuration(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test system configuration management."""
        config_data = {
            "maintenance_mode": False,
            "registration_enabled": True,
            "email_verification_required": True
        }

        response = await client.put(
            "/api/v1/admin/config",
            json=config_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_system_logs(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test retrieving system logs."""
        response = await client.get(
            "/api/v1/admin/logs?limit=50",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

class TestAdminUserManagement:
    """Test admin user management features."""

    @pytest.mark.asyncio
    async def test_list_all_users(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test listing all users across organizations."""
        response = await client.get(
            "/api/v1/admin/users",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_force_password_reset(self, client: AsyncClient, admin_auth_headers: dict, test_user: User):
        """Test forcing password reset for user."""
        response = await client.post(
            f"/api/v1/admin/users/{test_user.id}/force-password-reset",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_suspend_user(self, client: AsyncClient, admin_auth_headers: dict, test_user: User):
        """Test suspending user account."""
        response = await client.post(
            f"/api/v1/admin/users/{test_user.id}/suspend",
            json={"reason": "Test suspension"},
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_unsuspend_user(self, client: AsyncClient, admin_auth_headers: dict, test_user: User):
        """Test unsuspending user account."""
        # First suspend
        await client.post(
            f"/api/v1/admin/users/{test_user.id}/suspend",
            json={"reason": "Test suspension"},
            headers=admin_auth_headers
        )

        # Then unsuspend
        response = await client.post(
            f"/api/v1/admin/users/{test_user.id}/unsuspend",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

class TestAdminOrganizationManagement:
    """Test admin organization management features."""

    @pytest.mark.asyncio
    async def test_organization_analytics(self, client: AsyncClient, superuser_auth_headers: dict, test_organization: Organization):
        """Test getting organization analytics."""
        response = await client.get(
            f"/api/v1/admin/organizations/{test_organization.id}/analytics",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "user_activity" in data
        assert "usage_statistics" in data

    @pytest.mark.asyncio
    async def test_organization_billing(self, client: AsyncClient, superuser_auth_headers: dict, test_organization: Organization):
        """Test organization billing information."""
        response = await client.get(
            f"/api/v1/admin/organizations/{test_organization.id}/billing",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_upgrade_organization(self, client: AsyncClient, superuser_auth_headers: dict, test_organization: Organization):
        """Test upgrading organization subscription."""
        upgrade_data = {
            "subscription_tier": "enterprise",
            "max_users": 1000
        }

        response = await client.post(
            f"/api/v1/admin/organizations/{test_organization.id}/upgrade",
            json=upgrade_data,
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

class TestAdminSecurity:
    """Test admin security features."""

    @pytest.mark.asyncio
    async def test_security_alerts(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test retrieving security alerts."""
        response = await client.get(
            "/api/v1/admin/security/alerts",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_failed_login_attempts(self, client: AsyncClient, admin_auth_headers: dict):
        """Test retrieving failed login attempts."""
        response = await client.get(
            "/api/v1/admin/security/failed-logins",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_active_sessions(self, client: AsyncClient, admin_auth_headers: dict):
        """Test retrieving active user sessions."""
        response = await client.get(
            "/api/v1/admin/security/sessions",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_revoke_user_sessions(self, client: AsyncClient, admin_auth_headers: dict, test_user: User):
        """Test revoking all sessions for a user."""
        response = await client.post(
            f"/api/v1/admin/users/{test_user.id}/revoke-sessions",
            headers=admin_auth_headers
        )

        assert response.status_code == 200

class TestAdminMaintenance:
    """Test admin maintenance features."""

    @pytest.mark.asyncio
    async def test_database_backup(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test initiating database backup."""
        with patch('app.services.backup_service.create_backup') as mock_backup:
            response = await client.post(
                "/api/v1/admin/maintenance/backup",
                headers=superuser_auth_headers
            )

            assert response.status_code == 202
            mock_backup.assert_called_once()

    @pytest.mark.asyncio
    async def test_system_health_check(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test comprehensive system health check."""
        response = await client.get(
            "/api/v1/admin/maintenance/health",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "database" in data
        assert "redis" in data
        assert "external_services" in data

    @pytest.mark.asyncio
    async def test_clear_cache(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test clearing system cache."""
        response = await client.post(
            "/api/v1/admin/maintenance/clear-cache",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_maintenance_mode(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test enabling/disabling maintenance mode."""
        # Enable maintenance mode
        response = await client.post(
            "/api/v1/admin/maintenance/enable",
            json={"message": "System maintenance in progress"},
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

        # Disable maintenance mode
        response = await client.post(
            "/api/v1/admin/maintenance/disable",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

class TestAdminReporting:
    """Test admin reporting features."""

    @pytest.mark.asyncio
    async def test_usage_report(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test generating usage reports."""
        response = await client.get(
            "/api/v1/admin/reports/usage?period=30d",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "user_activity" in data
        assert "api_usage" in data

    @pytest.mark.asyncio
    async def test_security_report(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test generating security reports."""
        response = await client.get(
            "/api/v1/admin/reports/security?period=7d",
            headers=superuser_auth_headers
        )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_export_data(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test data export functionality."""
        export_request = {
            "data_type": "users",
            "format": "csv",
            "filters": {}
        }

        response = await client.post(
            "/api/v1/admin/export",
            json=export_request,
            headers=superuser_auth_headers
        )

        assert response.status_code == 202  # Async export job started

class TestAdminPermissions:
    """Test admin permission scenarios."""

    @pytest.mark.asyncio
    async def test_superuser_full_access(self, client: AsyncClient, superuser_auth_headers: dict):
        """Test that superusers have full admin access."""
        endpoints = [
            "/api/v1/admin/dashboard",
            "/api/v1/admin/stats",
            "/api/v1/admin/users"
        ]

        for endpoint in endpoints:
            response = await client.get(endpoint, headers=superuser_auth_headers)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_limited_access(self, client: AsyncClient, admin_auth_headers: dict):
        """Test that organization admins have limited access."""
        # Can access organization-specific admin features
        response = await client.get(
            "/api/v1/admin/dashboard",
            headers=admin_auth_headers
        )
        assert response.status_code == 200

        # Cannot access system-wide features
        response = await client.get(
            "/api/v1/admin/stats",
            headers=admin_auth_headers
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_regular_user_no_admin_access(self, client: AsyncClient, auth_headers: dict):
        """Test that regular users cannot access admin features."""
        admin_endpoints = [
            "/api/v1/admin/dashboard",
            "/api/v1/admin/stats",
            "/api/v1/admin/users"
        ]

        for endpoint in admin_endpoints:
            response = await client.get(endpoint, headers=auth_headers)
            assert response.status_code == 403
