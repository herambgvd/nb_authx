"""
Role and Permission management service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, func
from sqlalchemy.orm import selectinload
from typing import Optional, List, Tuple
from app.models import Role, Permission, RolePermission, UserRole, AuditLog
from app.schemas import RoleCreate, RoleUpdate, PermissionCreate, PermissionUpdate, RolePermissionAssign
from fastapi import HTTPException, status
import logging
import json

logger = logging.getLogger(__name__)


class RoleService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_role(
        self,
        role_data: RoleCreate,
        organization_id: str,
        created_by_user_id: Optional[str] = None
    ) -> Role:
        """Create a new role in an organization"""

        # Check if role name already exists in organization
        stmt = select(Role).where(
            and_(
                Role.name == role_data.name,
                Role.organization_id == organization_id
            )
        )
        existing_role = await self.db.execute(stmt)
        if existing_role.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role with this name already exists in the organization"
            )

        # Create role
        role = Role(
            name=role_data.name,
            description=role_data.description,
            organization_id=organization_id,
            is_active=True
        )

        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)

        # Log role creation
        await self._log_audit(
            user_id=created_by_user_id,
            organization_id=organization_id,
            action="role_created",
            resource="role",
            resource_id=role.id,
            status="success",
            details=json.dumps({
                "name": role.name,
                "created_by": created_by_user_id
            })
        )

        logger.info(f"Role created: {role.name} in organization {organization_id}")
        return role

    async def get_role_by_id(self, role_id: str, organization_id: Optional[str] = None) -> Optional[Role]:
        """Get role by ID, optionally scoped to organization"""
        stmt = select(Role).where(Role.id == role_id)

        if organization_id:
            stmt = stmt.where(Role.organization_id == organization_id)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_organization_roles(
        self,
        organization_id: str,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None
    ) -> Tuple[List[Role], int]:
        """List roles in an organization"""

        # Build query
        stmt = select(Role).where(Role.organization_id == organization_id)

        # Apply filters
        if is_active is not None:
            stmt = stmt.where(Role.is_active == is_active)

        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                Role.name.ilike(search_pattern) |
                Role.description.ilike(search_pattern)
            )

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(Role.created_at.desc())

        result = await self.db.execute(stmt)
        roles = result.scalars().all()

        return list(roles), total

    async def update_role(
        self,
        role_id: str,
        role_data: RoleUpdate,
        organization_id: str,
        updated_by_user_id: Optional[str] = None
    ) -> Role:
        """Update role"""

        # Get existing role
        role = await self.get_role_by_id(role_id, organization_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Check if new name conflicts
        if role_data.name and role_data.name != role.name:
            stmt = select(Role).where(
                and_(
                    Role.name == role_data.name,
                    Role.organization_id == organization_id,
                    Role.id != role_id
                )
            )
            existing_role = await self.db.execute(stmt)
            if existing_role.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role with this name already exists in the organization"
                )

        # Track changes
        changes = {}

        if role_data.name is not None and role_data.name != role.name:
            changes["name"] = {"from": role.name, "to": role_data.name}
            role.name = role_data.name

        if role_data.description is not None and role_data.description != role.description:
            changes["description"] = {"from": role.description, "to": role_data.description}
            role.description = role_data.description

        if role_data.is_active is not None and role_data.is_active != role.is_active:
            changes["is_active"] = {"from": role.is_active, "to": role_data.is_active}
            role.is_active = role_data.is_active

        if changes:
            await self.db.commit()
            await self.db.refresh(role)

            # Log role update
            await self._log_audit(
                user_id=updated_by_user_id,
                organization_id=organization_id,
                action="role_updated",
                resource="role",
                resource_id=role.id,
                status="success",
                details=json.dumps({
                    "changes": changes,
                    "updated_by": updated_by_user_id
                })
            )

            logger.info(f"Role updated: {role.name}")

        return role

    async def delete_role(
        self,
        role_id: str,
        organization_id: str,
        deleted_by_user_id: Optional[str] = None
    ) -> bool:
        """Delete role (check for users first)"""

        role = await self.get_role_by_id(role_id, organization_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Check if role is assigned to any users
        user_count_stmt = select(func.count()).where(UserRole.role_id == role_id)
        user_count_result = await self.db.execute(user_count_stmt)
        assigned_users = user_count_result.scalar()

        if assigned_users > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete role assigned to {assigned_users} users"
            )

        # Delete role permissions first
        delete_permissions_stmt = delete(RolePermission).where(RolePermission.role_id == role_id)
        await self.db.execute(delete_permissions_stmt)

        # Delete role
        delete_role_stmt = delete(Role).where(Role.id == role_id)
        await self.db.execute(delete_role_stmt)
        await self.db.commit()

        # Log role deletion
        await self._log_audit(
            user_id=deleted_by_user_id,
            organization_id=organization_id,
            action="role_deleted",
            resource="role",
            resource_id=role_id,
            status="success",
            details=json.dumps({
                "name": role.name,
                "deleted_by": deleted_by_user_id
            })
        )

        logger.info(f"Role deleted: {role.name}")
        return True

    async def assign_permissions_to_role(
        self,
        role_id: str,
        permission_assignment: RolePermissionAssign,
        organization_id: str,
        assigned_by_user_id: Optional[str] = None
    ) -> List[Permission]:
        """Assign permissions to role"""

        # Get role
        role = await self.get_role_by_id(role_id, organization_id)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found"
            )

        # Get permissions
        permissions_stmt = select(Permission).where(
            Permission.id.in_(permission_assignment.permission_ids)
        )
        permissions_result = await self.db.execute(permissions_stmt)
        permissions = permissions_result.scalars().all()

        if len(permissions) != len(permission_assignment.permission_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more permissions not found"
            )

        # Remove existing permissions
        delete_stmt = delete(RolePermission).where(RolePermission.role_id == role_id)
        await self.db.execute(delete_stmt)

        # Create new permission assignments
        for permission in permissions:
            role_permission = RolePermission(role_id=role_id, permission_id=permission.id)
            self.db.add(role_permission)

        await self.db.commit()

        # Log permission assignment
        await self._log_audit(
            user_id=assigned_by_user_id,
            organization_id=organization_id,
            action="role_permissions_assigned",
            resource="role",
            resource_id=role_id,
            status="success",
            details=json.dumps({
                "role_name": role.name,
                "permission_ids": permission_assignment.permission_ids,
                "permission_names": [p.name for p in permissions],
                "assigned_by": assigned_by_user_id
            })
        )

        logger.info(f"Permissions assigned to role {role.name}: {[p.name for p in permissions]}")
        return list(permissions)

    async def get_role_permissions(self, role_id: str) -> List[Permission]:
        """Get all permissions for a role"""

        stmt = (
            select(Permission)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id == role_id)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def list_roles_with_access_control(
        self,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        organization_id: Optional[str] = None,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Tuple[List[Role], int]:
        """List roles with access control"""

        # Super admin can see all roles
        if is_super_admin:
            stmt = select(Role).options(selectinload(Role.organization))

            # Apply filters
            if organization_id:
                stmt = stmt.where(Role.organization_id == organization_id)
            if is_active is not None:
                stmt = stmt.where(Role.is_active == is_active)
            if search:
                search_pattern = f"%{search}%"
                stmt = stmt.where(
                    Role.name.ilike(search_pattern) |
                    Role.description.ilike(search_pattern)
                )

            # Get total count
            count_stmt = select(func.count()).select_from(stmt.subquery())
            count_result = await self.db.execute(count_stmt)
            total = count_result.scalar()

            # Apply pagination
            offset = (page - 1) * size
            stmt = stmt.offset(offset).limit(size).order_by(Role.created_at.desc())

            result = await self.db.execute(stmt)
            roles = result.scalars().all()

            return list(roles), total

        # Organization users can only see roles in their organization
        elif user_org_id:
            return await self.list_organization_roles(
                organization_id=user_org_id,
                page=page,
                size=size,
                is_active=is_active,
                search=search
            )

        # No access
        else:
            return [], 0

    async def get_role_with_access_control(
        self,
        role_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Optional[Role]:
        """Get role with access control"""

        role = await self.get_role_by_id(role_id)
        if not role:
            return None

        # Super admin can access any role
        if is_super_admin:
            return role

        # Organization users can only access roles in their organization
        if user_org_id and role.organization_id == user_org_id:
            return role

        # No access
        return None

    async def can_user_manage_role(
        self,
        role_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> bool:
        """Check if a user can manage a role"""

        # Super admin can manage any role
        if is_super_admin:
            return True

        # Get role
        role = await self.get_role_by_id(role_id)
        if not role:
            return False

        # Organization users can only manage roles in their organization
        if user_org_id and role.organization_id == user_org_id:
            return True

        return False

    async def _log_audit(
        self,
        action: str,
        resource: str,
        status: str,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[str] = None
    ):
        """Create audit log entry"""

        audit_log = AuditLog(
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details,
            status=status
        )

        self.db.add(audit_log)


class PermissionService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_permission(
        self,
        permission_data: PermissionCreate,
        created_by_user_id: Optional[str] = None
    ) -> Permission:
        """Create a new permission (super admin only)"""

        # Check if permission already exists
        stmt = select(Permission).where(
            and_(
                Permission.resource == permission_data.resource,
                Permission.action == permission_data.action
            )
        )
        existing_permission = await self.db.execute(stmt)
        if existing_permission.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission with this resource and action already exists"
            )

        # Create permission
        permission = Permission(
            name=permission_data.name,
            description=permission_data.description,
            resource=permission_data.resource,
            action=permission_data.action
        )

        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)

        logger.info(f"Permission created: {permission.name}")
        return permission

    async def list_permissions(
        self,
        page: int = 1,
        size: int = 50,
        resource: Optional[str] = None,
        action: Optional[str] = None
    ) -> Tuple[List[Permission], int]:
        """List all permissions"""

        # Build query
        stmt = select(Permission)

        # Apply filters
        if resource:
            stmt = stmt.where(Permission.resource == resource)

        if action:
            stmt = stmt.where(Permission.action == action)

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(Permission.resource, Permission.action)

        result = await self.db.execute(stmt)
        permissions = result.scalars().all()

        return list(permissions), total

    async def list_permissions_grouped_by_resource(
        self,
        search: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None
    ) -> Tuple[dict, int]:
        """List all permissions grouped by resource for easier frontend consumption"""

        # Build query
        stmt = select(Permission)

        # Apply filters
        if resource:
            stmt = stmt.where(Permission.resource == resource)

        if action:
            stmt = stmt.where(Permission.action == action)

        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                Permission.name.ilike(search_pattern) |
                Permission.description.ilike(search_pattern) |
                Permission.resource.ilike(search_pattern) |
                Permission.action.ilike(search_pattern)
            )

        # Order by resource and action for consistent grouping
        stmt = stmt.order_by(Permission.resource, Permission.action)

        result = await self.db.execute(stmt)
        permissions = result.scalars().all()

        # Group permissions by resource
        permissions_by_resource = {}
        for permission in permissions:
            if permission.resource not in permissions_by_resource:
                permissions_by_resource[permission.resource] = []
            permissions_by_resource[permission.resource].append(permission)

        return permissions_by_resource, len(permissions)

    async def get_permission_by_id(self, permission_id: str) -> Optional[Permission]:
        """Get permission by ID"""
        stmt = select(Permission).where(Permission.id == permission_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def update_permission(
        self,
        permission_id: str,
        permission_data: PermissionUpdate,
        updated_by_user_id: Optional[str] = None
    ) -> Permission:
        """Update permission (super admin only)"""

        permission = await self.get_permission_by_id(permission_id)
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found"
            )

        # Update fields
        if permission_data.name is not None:
            permission.name = permission_data.name

        if permission_data.description is not None:
            permission.description = permission_data.description

        await self.db.commit()
        await self.db.refresh(permission)

        logger.info(f"Permission updated: {permission.name}")
        return permission
