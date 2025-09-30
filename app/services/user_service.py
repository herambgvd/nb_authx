"""
User management service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, func, or_
from sqlalchemy.orm import selectinload
from typing import Optional, List, Tuple
from app.models import User, Organization, Role, UserRole, AuditLog
from app.schemas import UserCreate, UserUpdate, UserRoleAssign
from app.security import hash_password, PasswordValidator
from fastapi import HTTPException, status
import logging
import json

logger = logging.getLogger(__name__)


class UserService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_user(
        self,
        user_data: UserCreate,
        organization_id: str,
        created_by_user_id: Optional[str] = None,
        assign_default_role: bool = True
    ) -> User:
        """Create a new user in an organization"""

        # Validate organization exists and is active
        org_stmt = select(Organization).where(
            and_(Organization.id == organization_id, Organization.is_active == True)
        )
        org_result = await self.db.execute(org_stmt)
        organization = org_result.scalar_one_or_none()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found or inactive"
            )

        # Check if email already exists
        email_stmt = select(User).where(User.email == user_data.email)
        email_result = await self.db.execute(email_stmt)
        if email_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # Check username uniqueness within organization
        username_stmt = select(User).where(
            and_(
                User.username == user_data.username,
                User.organization_id == organization_id
            )
        )
        username_result = await self.db.execute(username_stmt)
        if username_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists in this organization"
            )

        # Check organization user limit
        user_count_stmt = select(func.count()).where(
            and_(User.organization_id == organization_id, User.is_active == True)
        )
        user_count_result = await self.db.execute(user_count_stmt)
        active_users = user_count_result.scalar()

        if active_users >= organization.max_users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Organization has reached maximum user limit of {organization.max_users}"
            )

        # Validate password strength
        is_valid, errors = PasswordValidator.validate(user_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(errors)}"
            )

        # Create user
        user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=hash_password(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            organization_id=organization_id,
            is_active=True,
            is_verified=False  # Require email verification
        )

        self.db.add(user)
        await self.db.flush()

        # Assign default role if requested
        if assign_default_role:
            await self._assign_default_role(user.id, organization_id)

        await self.db.commit()
        await self.db.refresh(user)

        # Log user creation
        await self._log_audit(
            user_id=created_by_user_id,
            organization_id=organization_id,
            action="user_created",
            resource="user",
            resource_id=user.id,
            status="success",
            details=json.dumps({
                "email": user.email,
                "username": user.username,
                "created_by": created_by_user_id,
                "assign_default_role": assign_default_role
            })
        )

        logger.info(f"User created: {user.email} in organization {organization_id}")
        return user

    async def get_user_by_id(self, user_id: str, include_organization: bool = False) -> Optional[User]:
        """Get user by ID"""
        stmt = select(User)

        if include_organization:
            stmt = stmt.options(selectinload(User.organization))

        stmt = stmt.where(User.id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str, organization_id: Optional[str] = None) -> Optional[User]:
        """Get user by email, optionally within an organization"""
        stmt = select(User).where(User.email == email)

        if organization_id:
            stmt = stmt.where(User.organization_id == organization_id)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_organization_users(
        self,
        organization_id: str,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        role_id: Optional[str] = None
    ) -> Tuple[List[User], int]:
        """List users in an organization with filtering"""

        # Build base query
        stmt = select(User).where(User.organization_id == organization_id)

        # Apply filters
        if is_active is not None:
            stmt = stmt.where(User.is_active == is_active)

        if search:
            search_pattern = f"%{search}%"
            stmt = stmt.where(
                or_(
                    User.email.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern)
                )
            )

        if role_id:
            stmt = stmt.join(UserRole).where(UserRole.role_id == role_id)

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(User.created_at.desc())

        result = await self.db.execute(stmt)
        users = result.scalars().all()

        return list(users), total

    async def update_user(
        self,
        user_id: str,
        user_data: UserUpdate,
        updated_by_user_id: Optional[str] = None,
        organization_id: Optional[str] = None
    ) -> User:
        """Update user"""

        # Get existing user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # If organization_id provided, ensure user belongs to it
        if organization_id and user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to this organization"
            )

        # Track changes for audit log
        changes = {}

        # Update fields
        if user_data.username is not None and user_data.username != user.username:
            # Check username uniqueness within organization
            if user.organization_id:
                username_stmt = select(User).where(
                    and_(
                        User.username == user_data.username,
                        User.organization_id == user.organization_id,
                        User.id != user_id
                    )
                )
                username_result = await self.db.execute(username_stmt)
                if username_result.scalar_one_or_none():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username already exists in this organization"
                    )

            changes["username"] = {"from": user.username, "to": user_data.username}
            user.username = user_data.username

        if user_data.first_name is not None and user_data.first_name != user.first_name:
            changes["first_name"] = {"from": user.first_name, "to": user_data.first_name}
            user.first_name = user_data.first_name

        if user_data.last_name is not None and user_data.last_name != user.last_name:
            changes["last_name"] = {"from": user.last_name, "to": user_data.last_name}
            user.last_name = user_data.last_name

        if user_data.is_active is not None and user_data.is_active != user.is_active:
            changes["is_active"] = {"from": user.is_active, "to": user_data.is_active}
            user.is_active = user_data.is_active

        if user_data.is_verified is not None and user_data.is_verified != user.is_verified:
            changes["is_verified"] = {"from": user.is_verified, "to": user_data.is_verified}
            user.is_verified = user_data.is_verified

        if changes:
            await self.db.commit()
            await self.db.refresh(user)

            # Log user update
            await self._log_audit(
                user_id=updated_by_user_id,
                organization_id=user.organization_id,
                action="user_updated",
                resource="user",
                resource_id=user.id,
                status="success",
                details=json.dumps({
                    "changes": changes,
                    "updated_by": updated_by_user_id,
                    "target_user": user.email
                })
            )

            logger.info(f"User updated: {user.email}")

        return user

    async def delete_user(
        self,
        user_id: str,
        deleted_by_user_id: Optional[str] = None,
        organization_id: Optional[str] = None
    ) -> bool:
        """Delete user (soft delete by marking as inactive)"""

        user = await self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # If organization_id provided, ensure user belongs to it
        if organization_id and user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to this organization"
            )

        # Prevent super admin deletion
        if user.is_super_admin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete super admin user"
            )

        # Soft delete - mark as inactive
        user.is_active = False
        await self.db.commit()

        # Log user deletion
        await self._log_audit(
            user_id=deleted_by_user_id,
            organization_id=user.organization_id,
            action="user_deleted",
            resource="user",
            resource_id=user.id,
            status="success",
            details=json.dumps({
                "email": user.email,
                "username": user.username,
                "deleted_by": deleted_by_user_id
            })
        )

        logger.info(f"User deleted: {user.email}")
        return True

    async def assign_roles_to_user(
        self,
        user_id: str,
        role_assignment: UserRoleAssign,
        assigned_by_user_id: Optional[str] = None,
        organization_id: Optional[str] = None
    ) -> List[Role]:
        """Assign roles to user"""

        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # If organization_id provided, ensure user belongs to it
        if organization_id and user.organization_id != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not belong to this organization"
            )

        # Get roles and validate they belong to the same organization
        roles_stmt = select(Role).where(
            and_(
                Role.id.in_(role_assignment.role_ids),
                Role.organization_id == user.organization_id,
                Role.is_active == True
            )
        )
        roles_result = await self.db.execute(roles_stmt)
        roles = roles_result.scalars().all()

        if len(roles) != len(role_assignment.role_ids):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more roles not found or not accessible"
            )

        # Remove existing role assignments
        delete_stmt = delete(UserRole).where(UserRole.user_id == user_id)
        await self.db.execute(delete_stmt)

        # Create new role assignments
        for role in roles:
            user_role = UserRole(user_id=user_id, role_id=role.id)
            self.db.add(user_role)

        await self.db.commit()

        # Log role assignment
        await self._log_audit(
            user_id=assigned_by_user_id,
            organization_id=user.organization_id,
            action="user_roles_assigned",
            resource="user",
            resource_id=user.id,
            status="success",
            details=json.dumps({
                "user_email": user.email,
                "role_ids": role_assignment.role_ids,
                "role_names": [role.name for role in roles],
                "assigned_by": assigned_by_user_id
            })
        )

        logger.info(f"Roles assigned to user {user.email}: {[role.name for role in roles]}")
        return list(roles)

    async def get_user_roles(self, user_id: str) -> List[Role]:
        """Get all roles for a user"""

        stmt = (
            select(Role)
            .join(UserRole, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user_id)
            .where(Role.is_active == True)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def change_user_password(
        self,
        user_id: str,
        new_password: str,
        changed_by_user_id: Optional[str] = None
    ) -> bool:
        """Change user password (admin action)"""

        user = await self.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Validate password strength
        is_valid, errors = PasswordValidator.validate(new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(errors)}"
            )

        # Update password
        user.password_hash = hash_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None

        # Revoke all refresh tokens for security
        from app.models import RefreshToken
        revoke_stmt = update(RefreshToken).where(
            RefreshToken.user_id == user_id
        ).values(is_revoked=True)
        await self.db.execute(revoke_stmt)

        await self.db.commit()

        # Log password change
        await self._log_audit(
            user_id=changed_by_user_id,
            organization_id=user.organization_id,
            action="user_password_changed",
            resource="user",
            resource_id=user.id,
            status="success",
            details=json.dumps({
                "user_email": user.email,
                "changed_by": changed_by_user_id
            })
        )

        logger.info(f"Password changed for user: {user.email}")
        return True

    async def _assign_default_role(self, user_id: str, organization_id: str):
        """Assign default Member role to new user"""

        # Find Member role in organization
        member_role_stmt = select(Role).where(
            and_(
                Role.name == "Member",
                Role.organization_id == organization_id,
                Role.is_active == True
            )
        )
        member_role_result = await self.db.execute(member_role_stmt)
        member_role = member_role_result.scalar_one_or_none()

        if member_role:
            user_role = UserRole(user_id=user_id, role_id=member_role.id)
            self.db.add(user_role)

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

    async def list_users_with_access_control(
        self,
        page: int = 1,
        size: int = 20,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        organization_id: Optional[str] = None,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False,
        is_org_admin: bool = False
    ) -> Tuple[List[User], int]:
        """List users with access control"""

        # Super admin can see all users across organizations
        if is_super_admin:
            stmt = select(User).options(selectinload(User.organization))

            # Apply filters
            if organization_id:
                stmt = stmt.where(User.organization_id == organization_id)
            if is_active is not None:
                stmt = stmt.where(User.is_active == is_active)
            if search:
                search_pattern = f"%{search}%"
                stmt = stmt.where(
                    or_(
                        User.email.ilike(search_pattern),
                        User.username.ilike(search_pattern),
                        User.first_name.ilike(search_pattern),
                        User.last_name.ilike(search_pattern)
                    )
                )

            # Get total count
            count_stmt = select(func.count()).select_from(stmt.subquery())
            count_result = await self.db.execute(count_stmt)
            total = count_result.scalar()

            # Apply pagination
            offset = (page - 1) * size
            stmt = stmt.offset(offset).limit(size).order_by(User.created_at.desc())

            result = await self.db.execute(stmt)
            users = result.scalars().all()

            return list(users), total

        # Organization admins and users can only see users in their organization
        elif (is_org_admin or user_org_id) and user_org_id:
            return await self.list_organization_users(
                organization_id=user_org_id,
                page=page,
                size=size,
                is_active=is_active,
                search=search
            )

        # No access
        else:
            return [], 0

    async def get_user_with_access_control(
        self,
        user_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False,
        is_org_admin: bool = False
    ) -> Optional[User]:
        """Get user with access control"""

        user = await self.get_user_by_id(user_id, include_organization=True)
        if not user:
            return None

        # Super admin can access any user
        if is_super_admin:
            return user

        # Organization admins and users can only access users in their organization
        if (is_org_admin or user_org_id) and user.organization_id == user_org_id:
            return user

        # No access
        return None

    async def can_user_manage_user(
        self,
        target_user_id: str,
        manager_user_id: str,
        manager_org_id: Optional[str] = None,
        is_super_admin: bool = False,
        is_org_admin: bool = False
    ) -> bool:
        """Check if a user can manage another user"""

        # Super admin can manage any user
        if is_super_admin:
            return True

        # Get target user
        target_user = await self.get_user_by_id(target_user_id)
        if not target_user:
            return False

        # Organization admins can manage users in their organization
        if is_org_admin and manager_org_id and target_user.organization_id == manager_org_id:
            return True
        
        # Regular organization users cannot manage other users
        return False

