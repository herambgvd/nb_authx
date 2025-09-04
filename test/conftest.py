"""
Test configuration and fixtures for AuthX application.
Provides common test setup, database fixtures, and utility functions.
"""
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import uuid
from datetime import datetime, timedelta

from main import app
from app.db.session import get_async_db
from app.models.base import Base
from app.models.user import User
from app.models.organization import Organization
from app.models.role import Role
from app.models.location import Location
from app.models.location_group import LocationGroup
from app.models.admin import Admin
from app.models.audit import AuditLog
from app.models.user_device import UserDevice
from app.core.config import settings
from app.services.auth_service import auth_service
from app.services.user_service import user_service
from app.services.organization_service import organization_service
from app.services.role_service import role_service
from app.services.location_service import location_service

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Create test engine
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    poolclass=StaticPool,
    connect_args={"check_same_thread": False}
)

# Create test session factory
TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session
    async with TestSessionLocal() as session:
        yield session

    # Drop all tables after test
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with database session override."""
    def get_test_db():
        return db_session

    app.dependency_overrides[get_async_db] = get_test_db

    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()

@pytest.fixture
async def test_organization(db_session: AsyncSession) -> Organization:
    """Create a test organization."""
    org_data = {
        "name": "Test Organization",
        "description": "Organization for testing",
        "subscription_tier": "professional"
    }
    organization = await organization_service.create_organization(db_session, org_data)
    return organization

@pytest.fixture
async def test_user(db_session: AsyncSession, test_organization: Organization) -> User:
    """Create a test user."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }
    user = await user_service.create_user(db_session, user_data, test_organization.id)
    return user

@pytest.fixture
async def test_superuser(db_session: AsyncSession, test_organization: Organization) -> User:
    """Create a test superuser."""
    user_data = {
        "username": "superuser",
        "email": "super@example.com",
        "password": "SuperPassword123!",
        "first_name": "Super",
        "last_name": "User"
    }
    user = await user_service.create_user(db_session, user_data, test_organization.id)
    user.is_superuser = True
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture
async def test_admin_user(db_session: AsyncSession, test_organization: Organization) -> User:
    """Create a test admin user."""
    user_data = {
        "username": "adminuser",
        "email": "admin@example.com",
        "password": "AdminPassword123!",
        "first_name": "Admin",
        "last_name": "User"
    }
    user = await user_service.create_user(db_session, user_data, test_organization.id)

    # Assign admin role
    admin_role = await role_service.get_role_by_slug(db_session, "administrator", test_organization.id)
    if admin_role:
        await role_service.assign_role_to_user(db_session, user.id, admin_role.id)

    return user

@pytest.fixture
async def test_role(db_session: AsyncSession, test_organization: Organization) -> Role:
    """Create a test role."""
    role_data = {
        "name": "Test Role",
        "description": "Role for testing",
        "permissions_config": {
            "users": ["read"],
            "locations": ["read"]
        }
    }
    role = await role_service.create_role(db_session, role_data, test_organization.id)
    return role

@pytest.fixture
async def test_location(db_session: AsyncSession, test_organization: Organization) -> Location:
    """Create a test location."""
    location_data = {
        "name": "Test Location",
        "description": "Location for testing",
        "location_type": "office",
        "address": "123 Test St",
        "city": "Test City",
        "state": "Test State",
        "country": "Test Country",
        "postal_code": "12345"
    }
    location = await location_service.create_location(db_session, location_data, test_organization.id)
    return location

@pytest.fixture
async def test_location_group(db_session: AsyncSession, test_organization: Organization) -> LocationGroup:
    """Create a test location group."""
    group = LocationGroup(
        name="Test Group",
        description="Group for testing",
        organization_id=test_organization.id
    )
    db_session.add(group)
    await db_session.commit()
    await db_session.refresh(group)
    return group

@pytest.fixture
async def auth_headers(test_user: User, db_session: AsyncSession) -> dict:
    """Create authentication headers for test user."""
    # Generate token for test user
    token_data = await auth_service.create_access_token(
        data={"sub": str(test_user.id)},
        expires_delta=timedelta(minutes=30)
    )
    return {"Authorization": f"Bearer {token_data}"}

@pytest.fixture
async def admin_auth_headers(test_admin_user: User, db_session: AsyncSession) -> dict:
    """Create authentication headers for admin test user."""
    # Generate token for admin test user
    token_data = await auth_service.create_access_token(
        data={"sub": str(test_admin_user.id)},
        expires_delta=timedelta(minutes=30)
    )
    return {"Authorization": f"Bearer {token_data}"}

@pytest.fixture
async def superuser_auth_headers(test_superuser: User, db_session: AsyncSession) -> dict:
    """Create authentication headers for superuser."""
    # Generate token for superuser
    token_data = await auth_service.create_access_token(
        data={"sub": str(test_superuser.id)},
        expires_delta=timedelta(minutes=30)
    )
    return {"Authorization": f"Bearer {token_data}"}

@pytest.fixture
def sample_request_info() -> dict:
    """Sample request information for testing."""
    return {
        "ip_address": "127.0.0.1",
        "user_agent": "test-agent",
        "headers": {"user-agent": "test-agent"}
    }

# Utility functions for tests
def generate_unique_email():
    """Generate a unique email for testing."""
    return f"test_{uuid.uuid4().hex[:8]}@example.com"

def generate_unique_username():
    """Generate a unique username for testing."""
    return f"user_{uuid.uuid4().hex[:8]}"

async def create_test_data(db_session: AsyncSession, organization: Organization):
    """Create test data for comprehensive testing."""
    test_data = {}

    # Create multiple users
    for i in range(3):
        user_data = {
            "username": f"testuser{i}",
            "email": f"user{i}@example.com",
            "password": "TestPassword123!",
            "first_name": f"User{i}",
            "last_name": "Test"
        }
        user = await user_service.create_user(db_session, user_data, organization.id)
        test_data[f"user{i}"] = user

    return test_data
