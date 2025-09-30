"""
Database initialization and seeding utilities
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import Permission, User, Organization, Role, RolePermission
from app.security import hash_password
import logging

logger = logging.getLogger(__name__)


async def create_default_permissions():
    """Create default permissions for the system"""

    permissions_data = [
        # User permissions
        {"name": "Create User", "resource": "user", "action": "create", "description": "Create new users"},
        {"name": "Read User", "resource": "user", "action": "read", "description": "View user information"},
        {"name": "Update User", "resource": "user", "action": "update", "description": "Update user information"},
        {"name": "Delete User", "resource": "user", "action": "delete", "description": "Delete users"},

        # Role permissions
        {"name": "Create Role", "resource": "role", "action": "create", "description": "Create new roles"},
        {"name": "Read Role", "resource": "role", "action": "read", "description": "View role information"},
        {"name": "Update Role", "resource": "role", "action": "update", "description": "Update role information"},
        {"name": "Delete Role", "resource": "role", "action": "delete", "description": "Delete roles"},
        {"name": "Assign Role", "resource": "role", "action": "assign", "description": "Assign roles to users"},

        # Permission permissions
        {"name": "Create Permission", "resource": "permission", "action": "create", "description": "Create new permissions"},
        {"name": "Read Permission", "resource": "permission", "action": "read", "description": "View permission information"},
        {"name": "Update Permission", "resource": "permission", "action": "update", "description": "Update permission information"},
        {"name": "Delete Permission", "resource": "permission", "action": "delete", "description": "Delete permissions"},
        {"name": "Assign Permission", "resource": "permission", "action": "assign", "description": "Assign permissions to roles"},

        # Organization permissions
        {"name": "Create Organization", "resource": "organization", "action": "create", "description": "Create new organizations"},
        {"name": "Read Organization", "resource": "organization", "action": "read", "description": "View organization information"},
        {"name": "Update Organization", "resource": "organization", "action": "update", "description": "Update organization information"},
        {"name": "Delete Organization", "resource": "organization", "action": "delete", "description": "Delete organizations"},

        # Audit permissions
        {"name": "Read Audit", "resource": "audit", "action": "read", "description": "View audit logs"},
        {"name": "Export Audit", "resource": "audit", "action": "export", "description": "Export audit logs"},
        {"name": "Delete Audit", "resource": "audit", "action": "delete", "description": "Delete audit logs"},
    ]

    async with AsyncSessionLocal() as db:
        created_permissions = []

        for perm_data in permissions_data:
            # Check if permission already exists
            stmt = select(Permission).where(
                Permission.resource == perm_data["resource"],
                Permission.action == perm_data["action"]
            )
            result = await db.execute(stmt)
            existing_permission = result.scalar_one_or_none()

            if not existing_permission:
                permission = Permission(**perm_data)
                db.add(permission)
                created_permissions.append(f"{perm_data['resource']}:{perm_data['action']}")

        await db.commit()
        logger.info(f"Created {len(created_permissions)} permissions: {created_permissions}")


async def create_super_admin(email: str, password: str, first_name: str = "Super", last_name: str = "Admin"):
    """Create a super admin user"""

    async with AsyncSessionLocal() as db:
        # Check if super admin already exists
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        existing_user = result.scalar_one_or_none()

        if existing_user:
            logger.info(f"Super admin with email {email} already exists")
            return existing_user

        # Create super admin user
        super_admin = User(
            email=email,
            username="superadmin",
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            is_verified=True,
            is_super_admin=True,
            organization_id=None  # Super admin doesn't belong to any organization
        )

        db.add(super_admin)
        await db.commit()
        await db.refresh(super_admin)

        logger.info(f"Created super admin user: {email}")
        return super_admin


async def create_sample_organization():
    """Create a sample organization for testing"""

    async with AsyncSessionLocal() as db:
        # Check if sample organization already exists
        stmt = select(Organization).where(Organization.slug == "sample-org")
        result = await db.execute(stmt)
        existing_org = result.scalar_one_or_none()

        if existing_org:
            logger.info("Sample organization already exists")
            return existing_org

        # Create sample organization
        organization = Organization(
            name="Sample Organization",
            slug="sample-org",
            description="A sample organization for testing purposes",
            max_users=50,
            is_active=True
        )

        db.add(organization)
        await db.flush()  # Get the ID

        # Create default roles for the organization
        await _create_default_roles_for_org(db, organization.id)

        await db.commit()
        await db.refresh(organization)

        logger.info(f"Created sample organization: {organization.name}")
        return organization


async def _create_default_roles_for_org(db: AsyncSession, org_id: str):
    """Create default roles for an organization"""

    # Get all permissions
    permissions_stmt = select(Permission)
    permissions_result = await db.execute(permissions_stmt)
    all_permissions = list(permissions_result.scalars().all())

    # Admin role - all permissions
    admin_role = Role(
        name="Admin",
        description="Organization administrator with full access",
        organization_id=org_id,
        is_active=True
    )
    db.add(admin_role)
    await db.flush()

    for permission in all_permissions:
        role_permission = RolePermission(role_id=admin_role.id, permission_id=permission.id)
        db.add(role_permission)

    # Manager role - user and role management
    manager_role = Role(
        name="Manager",
        description="Organization manager with user and role management access",
        organization_id=org_id,
        is_active=True
    )
    db.add(manager_role)
    await db.flush()

    manager_permissions = [p for p in all_permissions if p.resource in ['user', 'role', 'audit'] and p.action in ['create', 'read', 'update', 'assign']]
    for permission in manager_permissions:
        role_permission = RolePermission(role_id=manager_role.id, permission_id=permission.id)
        db.add(role_permission)

    # Member role - basic permissions
    member_role = Role(
        name="Member",
        description="Basic organization member",
        organization_id=org_id,
        is_active=True
    )
    db.add(member_role)
    await db.flush()

    member_permissions = [p for p in all_permissions if p.action == 'read' and p.resource in ['user', 'role']]
    for permission in member_permissions:
        role_permission = RolePermission(role_id=member_role.id, permission_id=permission.id)
        db.add(role_permission)

    # Viewer role - minimal permissions
    viewer_role = Role(
        name="Viewer",
        description="Read-only access",
        organization_id=org_id,
        is_active=True
    )
    db.add(viewer_role)
    await db.flush()

    viewer_permissions = [p for p in all_permissions if p.action == 'read' and p.resource == 'user']
    for permission in viewer_permissions:
        role_permission = RolePermission(role_id=viewer_role.id, permission_id=permission.id)
        db.add(role_permission)


async def initialize_database():
    """Initialize database with default data"""
    logger.info("Initializing database...")

    try:
        # Create default permissions
        await create_default_permissions()

        # Create super admin (use environment variables in production)
        await create_super_admin(
            email="admin@authx.com",
            password="SuperAdmin123!",
            first_name="Super",
            last_name="Admin"
        )

        # Create sample organization
        await create_sample_organization()

        logger.info("Database initialization completed successfully")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


if __name__ == "__main__":
    import asyncio
    asyncio.run(initialize_database())
