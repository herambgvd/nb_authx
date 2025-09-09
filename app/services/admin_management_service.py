"""
Admin Management Service for AuthX system.
Handles super admin and organization admin operations.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from app.models.user import User
from app.models.admin import Admin
from app.models.organization import Organization
from app.models.admin import License
from app.schemas.admin_management import (
    AdminCreate,
    AdminUpdate,
    CreateOrganizationAdminRequest,
    CreateSuperAdminRequest,
    OnboardOrganizationRequest
)
from app.services.user_service import user_service
from app.core.security import get_password_hash
import uuid


class AdminManagementService:
    """Service for managing admin operations."""

    async def create_super_admin(
        self,
        db: AsyncSession,
        request: CreateSuperAdminRequest,
        created_by: Optional[UUID] = None
    ) -> tuple[User, Admin]:
        """Create a new super admin."""
        # Check if user already exists by email
        existing_user_by_email = await user_service.get_user_by_email(db, request.email)

        # Check if user already exists by username
        existing_user_by_username = await user_service.get_user_by_username(db, request.username)

        # Handle case where user exists by email
        if existing_user_by_email:
            # If it's the same user (email and username match)
            if existing_user_by_email.username == request.username:
                # Check if user already has admin record
                existing_admin = await self.get_admin_by_user_id(db, existing_user_by_email.id)
                if existing_admin and existing_admin.admin_level == "super_admin":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Super admin with this email already exists"
                    )
                elif existing_admin:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="User with this email already exists as organization admin"
                    )
                else:
                    # User exists but no admin record - create admin record for existing user
                    new_admin = Admin(
                        user_id=existing_user_by_email.id,
                        admin_level="super_admin",
                        permissions=request.permissions or self._get_default_super_admin_permissions(),
                        is_active=True,
                        created_by=created_by
                    )
                    db.add(new_admin)

                    # Update user to be superuser
                    existing_user_by_email.is_superuser = True

                    await db.commit()
                    await db.refresh(existing_user_by_email)
                    await db.refresh(new_admin)

                    return existing_user_by_email, new_admin
            else:
                # Email exists but with different username
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )

        # Handle case where username exists but email doesn't
        if existing_user_by_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this username already exists"
            )

        # Create new user - both email and username are available
        user_data = {
            "email": request.email,
            "username": request.username,
            "hashed_password": get_password_hash(request.password),
            "first_name": request.first_name,
            "last_name": request.last_name,
            "phone_number": request.phone_number,
            "is_superuser": True,
            "is_active": True,
            "is_verified": True
        }

        new_user = User(**user_data)
        db.add(new_user)
        await db.flush()

        # Create admin record
        admin_data = AdminCreate(
            user_id=new_user.id,
            admin_level="super_admin",
            permissions=request.permissions or self._get_default_super_admin_permissions(),
            is_active=True
        )

        new_admin = Admin(
            **admin_data.model_dump(),
            created_by=created_by
        )
        db.add(new_admin)

        await db.commit()
        await db.refresh(new_user)
        await db.refresh(new_admin)

        return new_user, new_admin

    async def onboard_organization_with_admin(
        self,
        db: AsyncSession,
        request: OnboardOrganizationRequest,
        created_by: UUID
    ) -> tuple[Organization, User, Admin, License]:
        """Onboard a new organization with its admin."""
        # Check if organization slug already exists
        existing_org = await self._get_organization_by_slug(db, request.organization_slug)
        if existing_org:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization with this slug already exists"
            )

        # Check if admin user already exists
        existing_user = await user_service.get_user_by_email(db, request.admin_email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # Create organization
        org_data = {
            "name": request.organization_name,
            "slug": request.organization_slug,
            "description": request.organization_description,
            "domain": request.organization_domain,
            "email": request.organization_email,
            "phone": request.organization_phone,
            "is_active": True,
            "max_users": request.max_users,
            "max_locations": request.max_locations
        }

        new_org = Organization(**org_data)
        db.add(new_org)
        await db.flush()

        # Create organization admin user
        admin_user_data = {
            "email": request.admin_email,
            "username": request.admin_username,
            "hashed_password": get_password_hash(request.admin_password),
            "first_name": request.admin_first_name,
            "last_name": request.admin_last_name,
            "phone_number": request.admin_phone_number,
            "organization_id": new_org.id,
            "is_organization_admin": True,
            "is_active": True,
            "is_verified": True
        }

        new_admin_user = User(**admin_user_data)
        db.add(new_admin_user)
        await db.flush()

        # Create admin record
        new_admin = Admin(
            user_id=new_admin_user.id,
            admin_level="organization_admin",
            organization_id=new_org.id,
            permissions=self._get_default_org_admin_permissions(),
            is_active=True,
            created_by=created_by
        )
        db.add(new_admin)
        await db.flush()

        # Create license
        license_key = self._generate_license_key()
        new_license = License(
            license_key=license_key,
            organization_id=new_org.id,
            license_type=request.license_type,
            max_users=request.max_users,
            max_locations=request.max_locations,
            valid_from=datetime.utcnow(),
            valid_until=request.valid_until,
            is_active=True,
            created_by=created_by
        )
        db.add(new_license)

        await db.commit()

        # Refresh objects
        await db.refresh(new_org)
        await db.refresh(new_admin_user)
        await db.refresh(new_admin)
        await db.refresh(new_license)

        return new_org, new_admin_user, new_admin, new_license

    async def create_organization_admin(
        self,
        db: AsyncSession,
        request: CreateOrganizationAdminRequest,
        created_by: UUID
    ) -> tuple[User, Admin]:
        """Create a new organization admin for an existing organization."""
        # Verify organization exists
        org_query = select(Organization).where(Organization.id == request.organization_id)
        result = await db.execute(org_query)
        organization = result.scalar_one_or_none()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

        # Check if user already exists
        existing_user = await user_service.get_user_by_email(db, request.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # Create user
        user_data = {
            "email": request.email,
            "username": request.username,
            "hashed_password": get_password_hash(request.password),
            "first_name": request.first_name,
            "last_name": request.last_name,
            "phone_number": request.phone_number,
            "organization_id": request.organization_id,
            "is_organization_admin": True,
            "is_active": True,
            "is_verified": True
        }

        new_user = User(**user_data)
        db.add(new_user)
        await db.flush()

        # Create admin record
        new_admin = Admin(
            user_id=new_user.id,
            admin_level="organization_admin",
            organization_id=request.organization_id,
            permissions=request.permissions or self._get_default_org_admin_permissions(),
            is_active=True,
            created_by=created_by
        )
        db.add(new_admin)

        await db.commit()
        await db.refresh(new_user)
        await db.refresh(new_admin)

        return new_user, new_admin

    async def get_admin_by_user_id(
        self,
        db: AsyncSession,
        user_id: UUID
    ) -> Optional[Admin]:
        """Get admin record by user ID."""
        query = select(Admin).options(
            selectinload(Admin.user),
            selectinload(Admin.organization)
        ).where(Admin.user_id == user_id)

        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_organization_admins(
        self,
        db: AsyncSession,
        organization_id: UUID
    ) -> List[Admin]:
        """Get all admins for an organization."""
        query = select(Admin).options(
            selectinload(Admin.user)
        ).where(
            and_(
                Admin.organization_id == organization_id,
                Admin.admin_level == "organization_admin",
                Admin.is_active == True
            )
        )

        result = await db.execute(query)
        return result.scalars().all()

    async def get_all_super_admins(
        self,
        db: AsyncSession
    ) -> List[Admin]:
        """Get all super admins."""
        query = select(Admin).options(
            selectinload(Admin.user)
        ).where(
            and_(
                Admin.admin_level == "super_admin",
                Admin.is_active == True
            )
        )

        result = await db.execute(query)
        return result.scalars().all()

    async def update_admin(
        self,
        db: AsyncSession,
        admin_id: UUID,
        update_data: AdminUpdate
    ) -> Admin:
        """Update admin record."""
        query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(query)
        admin = result.scalar_one_or_none()

        if not admin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Admin not found"
            )

        # Update fields
        for field, value in update_data.model_dump(exclude_unset=True).items():
            setattr(admin, field, value)

        await db.commit()
        await db.refresh(admin)
        return admin

    async def deactivate_admin(
        self,
        db: AsyncSession,
        admin_id: UUID
    ) -> Admin:
        """Deactivate admin record."""
        query = select(Admin).where(Admin.id == admin_id)
        result = await db.execute(query)
        admin = result.scalar_one_or_none()

        if not admin:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Admin not found"
            )

        admin.is_active = False
        await db.commit()
        await db.refresh(admin)
        return admin

    async def verify_admin_permissions(
        self,
        db: AsyncSession,
        user_id: UUID,
        required_permission: str,
        organization_id: Optional[UUID] = None
    ) -> bool:
        """Verify if user has required admin permissions."""
        admin = await self.get_admin_by_user_id(db, user_id)

        if not admin or not admin.is_active:
            return False

        # Super admins have all permissions
        if admin.is_super_admin:
            return True

        # Organization admins can only manage their own organization
        if admin.is_organization_admin:
            if organization_id and admin.organization_id != organization_id:
                return False

            # Check specific permissions
            if admin.permissions:
                return admin.permissions.get(required_permission, False)

        return False

    async def _get_organization_by_slug(
        self,
        db: AsyncSession,
        slug: str
    ) -> Optional[Organization]:
        """Get organization by slug."""
        query = select(Organization).where(Organization.slug == slug)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    def _generate_license_key(self) -> str:
        """Generate a unique license key."""
        return f"LIC-{uuid.uuid4().hex[:16].upper()}"

    def _get_default_super_admin_permissions(self) -> Dict[str, Any]:
        """Get default permissions for super admin."""
        return {
            "organizations": {
                "create": True,
                "read": True,
                "update": True,
                "delete": True,
                "manage_admins": True
            },
            "users": {
                "create": True,
                "read": True,
                "update": True,
                "delete": True,
                "manage_roles": True
            },
            "system": {
                "configuration": True,
                "monitoring": True,
                "audit": True
            }
        }

    def _get_default_org_admin_permissions(self) -> Dict[str, Any]:
        """Get default permissions for organization admin."""
        return {
            "users": {
                "create": True,
                "read": True,
                "update": True,
                "delete": True,
                "manage_roles": True
            },
            "locations": {
                "create": True,
                "read": True,
                "update": True,
                "delete": True,
                "manage_access": True
            },
            "roles": {
                "create": True,
                "read": True,
                "update": True,
                "delete": True
            },
            "organization": {
                "read": True,
                "update": True
            }
        }


# Create service instance
admin_management_service = AdminManagementService()
