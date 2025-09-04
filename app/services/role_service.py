"""
Role management service for the AuthX microservice.
This module provides comprehensive role and permission management functionality with full async support.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.orm import selectinload

from app.models.role import Role, Permission
from app.models.user import User
from app.models.organization import Organization

logger = logging.getLogger(__name__)

class RoleService:
    """Comprehensive role management service with full async support."""

    def __init__(self):
        self.default_permissions = {
            'users': ['read', 'write', 'delete'],
            'organizations': ['read', 'write'],
            'locations': ['read', 'write', 'delete'],
            'roles': ['read', 'write', 'delete'],
            'audit': ['read'],
            'settings': ['read', 'write']
        }

    async def create_role(
        self,
        db: AsyncSession,
        role_data: Dict[str, Any],
        organization_id: UUID,
        created_by: Optional[UUID] = None
    ) -> Role:
        """Create a new role with comprehensive validation."""
        logger.info(f"Creating role: {role_data.get('name')} for organization: {organization_id}")

        # Check if role with name already exists in organization
        existing_role = await self.get_role_by_name(db, role_data.get('name'), organization_id)
        if existing_role:
            logger.warning(f"Role creation failed - name already exists: {role_data.get('name')}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role with this name already exists in the organization"
            )

        # Generate slug from name
        slug = role_data.get('slug') or self._generate_slug(role_data['name'])

        # Create role
        role = Role(
            name=role_data['name'],
            slug=slug,
            description=role_data.get('description'),
            organization_id=organization_id,
            is_default=role_data.get('is_default', False),
            is_system=role_data.get('is_system', False),
            permissions_config=role_data.get('permissions_config', {}),
            priority=role_data.get('priority', 0)
        )

        db.add(role)
        await db.commit()
        await db.refresh(role)

        logger.info(f"Role created successfully: {role.id}")
        return role

    async def get_role_by_id(self, db: AsyncSession, role_id: UUID) -> Optional[Role]:
        """Get role by ID with all relationships loaded."""
        logger.debug(f"Fetching role by ID: {role_id}")

        result = await db.execute(
            select(Role)
            .options(
                selectinload(Role.organization),
                selectinload(Role.permissions)
            )
            .where(Role.id == role_id)
        )
        role = result.scalar_one_or_none()

        if role:
            logger.debug(f"Role found: {role.name}")
        else:
            logger.debug(f"Role not found with ID: {role_id}")

        return role

    async def get_role_by_name(self, db: AsyncSession, name: str, organization_id: UUID) -> Optional[Role]:
        """Get role by name within organization."""
        logger.debug(f"Fetching role by name: {name} in organization: {organization_id}")

        result = await db.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .where(
                and_(
                    Role.name == name,
                    Role.organization_id == organization_id
                )
            )
        )
        return result.scalar_one_or_none()

    async def update_role(
        self,
        db: AsyncSession,
        role_id: UUID,
        role_update: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> Optional[Role]:
        """Update role with validation and audit logging."""
        logger.info(f"Updating role: {role_id}")

        # Get existing role
        role = await self.get_role_by_id(db, role_id)
        if not role:
            logger.warning(f"Role not found for update: {role_id}")
            return None

        # Check if trying to update system role
        if role.is_system and not role_update.get('allow_system_update', False):
            logger.warning(f"Attempt to update system role: {role_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot update system roles"
            )

        # Update allowed fields
        allowed_fields = {
            'name', 'description', 'permissions_config', 'priority', 'is_active'
        }

        for field, value in role_update.items():
            if field in allowed_fields and hasattr(role, field):
                setattr(role, field, value)
                logger.debug(f"Updated {field} for role {role_id}")

        # Update slug if name changed
        if 'name' in role_update:
            role.slug = self._generate_slug(role_update['name'])

        role.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(role)

        logger.info(f"Role updated successfully: {role_id}")
        return role

    async def delete_role(self, db: AsyncSession, role_id: UUID) -> bool:
        """Delete role with validation."""
        logger.info(f"Deleting role: {role_id}")

        role = await self.get_role_by_id(db, role_id)
        if not role:
            logger.warning(f"Role not found for deletion: {role_id}")
            return False

        # Check if it's a system role
        if role.is_system:
            logger.warning(f"Attempt to delete system role: {role_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete system roles"
            )

        # Check if role is assigned to users
        result = await db.execute(
            select(func.count(User.id)).where(User.id == role.user_id)
        )
        assigned_users = result.scalar()

        if assigned_users > 0:
            logger.warning(f"Cannot delete role assigned to users: {assigned_users}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete role assigned to {assigned_users} users"
            )

        # Delete role
        await db.delete(role)
        await db.commit()

        logger.info(f"Role deleted successfully: {role_id}")
        return True

    async def list_roles(
        self,
        db: AsyncSession,
        organization_id: UUID,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Tuple[List[Role], int]:
        """List roles with pagination and filtering."""
        logger.debug(f"Listing roles for organization: {organization_id}")

        query = select(Role).options(
            selectinload(Role.permissions)
        ).where(Role.organization_id == organization_id)

        # Apply filters
        if search:
            search_term = f"%{search}%"
            query = query.where(
                or_(
                    Role.name.ilike(search_term),
                    Role.description.ilike(search_term)
                )
            )

        if is_active is not None:
            query = query.where(Role.is_active == is_active)

        # Get total count
        count_query = select(func.count(Role.id)).where(Role.organization_id == organization_id)
        if search:
            count_query = count_query.where(
                or_(
                    Role.name.ilike(search_term),
                    Role.description.ilike(search_term)
                )
            )
        if is_active is not None:
            count_query = count_query.where(Role.is_active == is_active)

        count_result = await db.execute(count_query)
        total = count_result.scalar()

        # Get paginated results
        query = query.offset(skip).limit(limit).order_by(Role.priority.desc(), Role.created_at.desc())
        result = await db.execute(query)
        roles = result.scalars().all()

        logger.debug(f"Found {len(roles)} roles out of {total} total")
        return list(roles), total

    async def assign_role_to_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        role_id: UUID,
        assigned_by: Optional[UUID] = None
    ) -> bool:
        """Assign role to user."""
        logger.info(f"Assigning role {role_id} to user {user_id}")

        # Get user and role
        user = await db.get(User, user_id)
        role = await self.get_role_by_id(db, role_id)

        if not user or not role:
            logger.warning(f"User or role not found for assignment")
            return False

        # Check if user belongs to same organization as role
        if user.organization_id != role.organization_id:
            logger.warning(f"User and role belong to different organizations")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User and role must belong to the same organization"
            )

        # Update user's role
        # Note: This assumes one role per user. For multiple roles, you'd need a junction table
        role.user_id = user_id
        await db.commit()

        logger.info(f"Role assigned successfully")
        return True

    async def remove_role_from_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        role_id: UUID
    ) -> bool:
        """Remove role from user."""
        logger.info(f"Removing role {role_id} from user {user_id}")

        role = await self.get_role_by_id(db, role_id)
        if not role or role.user_id != user_id:
            logger.warning(f"Role not assigned to user")
            return False

        role.user_id = None
        await db.commit()

        logger.info(f"Role removed successfully")
        return True

    async def get_user_roles(self, db: AsyncSession, user_id: UUID) -> List[Role]:
        """Get all roles assigned to a user."""
        logger.debug(f"Getting roles for user: {user_id}")

        result = await db.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.user_id == user_id)
        )
        roles = result.scalars().all()

        logger.debug(f"Found {len(roles)} roles for user")
        return list(roles)

    async def check_permission(
        self,
        db: AsyncSession,
        user_id: UUID,
        resource: str,
        action: str
    ) -> bool:
        """Check if user has permission for specific resource and action."""
        logger.debug(f"Checking permission for user {user_id}: {resource}.{action}")

        # Get user roles
        user_roles = await self.get_user_roles(db, user_id)

        # Check permissions in each role
        for role in user_roles:
            if not role.is_active:
                continue

            permissions = role.permissions_config or {}
            resource_permissions = permissions.get(resource, [])

            if action in resource_permissions or 'all' in resource_permissions:
                logger.debug(f"Permission granted via role: {role.name}")
                return True

        logger.debug(f"Permission denied")
        return False

    async def create_default_roles(self, db: AsyncSession, organization_id: UUID):
        """Create default roles for an organization."""
        logger.info(f"Creating default roles for organization: {organization_id}")

        default_roles = [
            {
                'name': 'Super Admin',
                'slug': 'super-admin',
                'description': 'Full system access',
                'is_system': True,
                'priority': 1000,
                'permissions_config': {
                    'users': ['all'],
                    'organizations': ['all'],
                    'locations': ['all'],
                    'roles': ['all'],
                    'audit': ['all'],
                    'settings': ['all']
                }
            },
            {
                'name': 'Admin',
                'slug': 'admin',
                'description': 'Administrative access',
                'is_system': True,
                'priority': 800,
                'permissions_config': {
                    'users': ['read', 'write'],
                    'locations': ['read', 'write'],
                    'roles': ['read'],
                    'audit': ['read'],
                    'settings': ['read', 'write']
                }
            },
            {
                'name': 'Manager',
                'slug': 'manager',
                'description': 'Management access',
                'is_system': True,
                'priority': 600,
                'permissions_config': {
                    'users': ['read'],
                    'locations': ['read', 'write'],
                    'audit': ['read']
                }
            },
            {
                'name': 'Employee',
                'slug': 'employee',
                'description': 'Basic employee access',
                'is_system': True,
                'is_default': True,
                'priority': 400,
                'permissions_config': {
                    'users': ['read'],
                    'locations': ['read']
                }
            },
            {
                'name': 'Auditor',
                'slug': 'auditor',
                'description': 'Audit and compliance access',
                'is_system': True,
                'priority': 500,
                'permissions_config': {
                    'audit': ['read'],
                    'users': ['read'],
                    'locations': ['read']
                }
            }
        ]

        for role_data in default_roles:
            try:
                await self.create_role(db, role_data, organization_id)
            except HTTPException:
                # Role might already exist, skip
                logger.debug(f"Skipping existing role: {role_data['name']}")
                continue

        logger.info(f"Default roles created for organization: {organization_id}")

    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from role name."""
        return name.lower().replace(' ', '-').replace('_', '-')

# Create singleton instance
role_service = RoleService()
