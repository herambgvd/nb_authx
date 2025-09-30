"""
Organization service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, func
from sqlalchemy.orm import selectinload
from typing import Optional, List, Tuple
from app.models import Organization, User, Role, Permission, RolePermission
from app.schemas import OrganizationCreate, OrganizationUpdate, PaginatedResponse
from fastapi import HTTPException, status
import logging
import json
import re

logger = logging.getLogger(__name__)


class OrganizationService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_organization(
        self,
        org_data: OrganizationCreate,
        created_by_user_id: Optional[str] = None
    ) -> Organization:
        """Create a new organization"""

        # Validate slug format (alphanumeric and hyphens only)
        if not re.match(r'^[a-z0-9-]+$', org_data.slug):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Slug must contain only lowercase letters, numbers, and hyphens"
            )

        # Check if organization with slug already exists
        stmt = select(Organization).where(Organization.slug == org_data.slug)
        existing_org = await self.db.execute(stmt)
        if existing_org.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization with this slug already exists"
            )

        # Create organization
        organization = Organization(
            name=org_data.name,
            slug=org_data.slug,
            description=org_data.description,
            max_users=org_data.max_users,
            is_active=True
        )

        self.db.add(organization)
        await self.db.flush()  # Flush to get the ID

        # Create default roles for the organization
        await self._create_default_roles(organization.id)

        await self.db.commit()
        await self.db.refresh(organization)

        # Log organization creation
        await self._log_audit(
            user_id=created_by_user_id,
            organization_id=organization.id,
            action="organization_created",
            resource="organization",
            resource_id=organization.id,
            status="success",
            details=json.dumps({
                "name": organization.name,
                "slug": organization.slug,
                "created_by": created_by_user_id
            })
        )

        logger.info(f"Organization created: {organization.name} ({organization.slug})")
        return organization

    async def get_organization_by_id(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID"""
        stmt = select(Organization).where(Organization.id == org_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_organization_by_slug(self, slug: str) -> Optional[Organization]:
        """Get organization by slug"""
        stmt = select(Organization).where(Organization.slug == slug)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_organizations(
        self,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        include_locations: bool = True
    ) -> Tuple[List[Organization], int]:
        """List organizations with pagination and filtering (Super Admin only - for organization onboarding)"""

        # Build query with locations
        stmt = select(Organization)
        if include_locations:
            stmt = stmt.options(selectinload(Organization.locations))

        # Apply filters
        if is_active is not None:
            stmt = stmt.where(Organization.is_active == is_active)

        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                Organization.name.ilike(search_pattern) |
                Organization.slug.ilike(search_pattern)
            )

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(Organization.created_at.desc())

        result = await self.db.execute(stmt)
        organizations = result.scalars().all()

        return list(organizations), total

    async def get_organization_for_user(
        self,
        org_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False,
        is_org_admin: bool = False
    ) -> Optional[Organization]:
        """Get organization with access control"""
        
        # Super admins can access any organization (for organization onboarding management)
        if is_super_admin:
            stmt = select(Organization).options(selectinload(Organization.locations)).where(Organization.id == org_id)
            result = await self.db.execute(stmt)
            return result.scalar_one_or_none()
        
        # Organization admins and users can only access their own organization
        if (is_org_admin or user_org_id) and org_id == user_org_id:
            stmt = select(Organization).options(selectinload(Organization.locations)).where(Organization.id == org_id)
            result = await self.db.execute(stmt)
            return result.scalar_one_or_none()
        
        # No access
        return None

    async def list_user_organizations(
        self,
        user_org_id: str,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[Organization], int]:
        """List organizations for organization users (only their own org)"""
        
        stmt = select(Organization).options(selectinload(Organization.locations)).where(
            and_(Organization.id == user_org_id, Organization.is_active == True)
        )
        
        result = await self.db.execute(stmt)
        organization = result.scalar_one_or_none()
        
        if organization:
            return [organization], 1
        else:
            return [], 0

    async def update_organization(
        self,
        org_id: str,
        org_data: OrganizationUpdate,
        updated_by_user_id: Optional[str] = None
    ) -> Organization:
        """Update organization"""

        # Get existing organization
        organization = await self.get_organization_by_id(org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Track changes for audit log
        changes = {}

        # Update fields
        if org_data.name is not None and org_data.name != organization.name:
            changes["name"] = {"from": organization.name, "to": org_data.name}
            organization.name = org_data.name

        if org_data.description is not None and org_data.description != organization.description:
            changes["description"] = {"from": organization.description, "to": org_data.description}
            organization.description = org_data.description

        if org_data.max_users is not None and org_data.max_users != organization.max_users:
            changes["max_users"] = {"from": organization.max_users, "to": org_data.max_users}
            organization.max_users = org_data.max_users

        if org_data.is_active is not None and org_data.is_active != organization.is_active:
            changes["is_active"] = {"from": organization.is_active, "to": org_data.is_active}
            organization.is_active = org_data.is_active

        if changes:
            await self.db.commit()
            await self.db.refresh(organization)

            # Log organization update
            await self._log_audit(
                user_id=updated_by_user_id,
                organization_id=organization.id,
                action="organization_updated",
                resource="organization",
                resource_id=organization.id,
                status="success",
                details=json.dumps({
                    "changes": changes,
                    "updated_by": updated_by_user_id
                })
            )

            logger.info(f"Organization updated: {organization.name}")

        return organization

    async def delete_organization(
        self,
        org_id: str,
        deleted_by_user_id: Optional[str] = None
    ) -> bool:
        """Delete organization (soft delete by marking as inactive)"""

        organization = await self.get_organization_by_id(org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if organization has active users
        user_count_stmt = select(func.count()).where(
            and_(User.organization_id == org_id, User.is_active == True)
        )
        user_count_result = await self.db.execute(user_count_stmt)
        active_users = user_count_result.scalar()

        if active_users > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete organization with {active_users} active users"
            )

        # Soft delete - mark as inactive
        organization.is_active = False
        await self.db.commit()

        # Log organization deletion
        await self._log_audit(
            user_id=deleted_by_user_id,
            organization_id=organization.id,
            action="organization_deleted",
            resource="organization",
            resource_id=organization.id,
            status="success",
            details=json.dumps({
                "name": organization.name,
                "slug": organization.slug,
                "deleted_by": deleted_by_user_id
            })
        )

        logger.info(f"Organization deleted: {organization.name}")
        return True

    async def get_organization_stats(self, org_id: str) -> dict:
        """Get organization statistics"""

        organization = await self.get_organization_by_id(org_id)
        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Count active users
        active_users_stmt = select(func.count()).where(
            and_(User.organization_id == org_id, User.is_active == True)
        )
        active_users_result = await self.db.execute(active_users_stmt)
        active_users = active_users_result.scalar()

        # Count total users
        total_users_stmt = select(func.count()).where(User.organization_id == org_id)
        total_users_result = await self.db.execute(total_users_stmt)
        total_users = total_users_result.scalar()

        # Count roles
        roles_stmt = select(func.count()).where(
            and_(Role.organization_id == org_id, Role.is_active == True)
        )
        roles_result = await self.db.execute(roles_stmt)
        total_roles = roles_result.scalar()

        return {
            "organization_id": org_id,
            "name": organization.name,
            "slug": organization.slug,
            "is_active": organization.is_active,
            "max_users": organization.max_users,
            "active_users": active_users,
            "total_users": total_users,
            "total_roles": total_roles,
            "user_capacity_percentage": round((active_users / organization.max_users) * 100, 2) if organization.max_users > 0 else 0
        }

    async def _create_default_roles(self, org_id: str):
        """Create default roles for new organization"""

        # Get all available permissions
        permissions_stmt = select(Permission)
        permissions_result = await self.db.execute(permissions_stmt)
        all_permissions = permissions_result.scalars().all()

        # Create Admin role with all permissions
        admin_role = Role(
            name="Admin",
            description="Organization administrator with full access",
            organization_id=org_id,
            is_active=True
        )
        self.db.add(admin_role)
        await self.db.flush()

        # Assign all permissions to admin role
        for permission in all_permissions:
            role_permission = RolePermission(
                role_id=admin_role.id,
                permission_id=permission.id
            )
            self.db.add(role_permission)

        # Create Member role with basic permissions
        member_role = Role(
            name="Member",
            description="Basic organization member",
            organization_id=org_id,
            is_active=True
        )
        self.db.add(member_role)
        await self.db.flush()

        # Assign basic permissions to member role (read operations)
        basic_permissions = [p for p in all_permissions if p.action in ['read']]
        for permission in basic_permissions:
            role_permission = RolePermission(
                role_id=member_role.id,
                permission_id=permission.id
            )
            self.db.add(role_permission)

        # Create Viewer role with minimal permissions
        viewer_role = Role(
            name="Viewer",
            description="Read-only access",
            organization_id=org_id,
            is_active=True
        )
        self.db.add(viewer_role)
        await self.db.flush()

        # Assign minimal permissions to viewer role
        viewer_permissions = [p for p in all_permissions if p.action == 'read' and p.resource in ['user', 'role']]
        for permission in viewer_permissions:
            role_permission = RolePermission(
                role_id=viewer_role.id,
                permission_id=permission.id
            )
            self.db.add(role_permission)

    async def _log_audit(
        self,
        action: str,
        resource: str,
        status: str,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[str] = None
    ):
        """Create audit log entry"""
        from app.models import AuditLog

        audit_log = AuditLog(
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            status=status
        )

        self.db.add(audit_log)
