"""
Role model for AuthX role-based access control system.
Defines roles and permissions for users within organizations with async support.
"""
from sqlalchemy import String, Boolean, Text, ForeignKey, Integer, Table, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from typing import Optional, List, Dict, Any
import uuid

from app.models.base import TenantBaseModel, UUIDBaseModel

# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    UUIDBaseModel.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'), primary_key=True)
)

# Association table for many-to-many relationship between roles and permissions
role_permissions = Table(
    'role_permissions',
    UUIDBaseModel.metadata,
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', UUID(as_uuid=True), ForeignKey('permissions.id'), primary_key=True)
)


class Role(TenantBaseModel):
    """Role model for role-based access control with async support."""

    __tablename__ = "roles"

    # Basic role fields
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Role slug for URL-friendly identification
    slug: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    # Role configuration
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Permissions stored as structured JSON
    permissions_config: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True, default=lambda: {}
    )

    # Priority for role hierarchy (higher number = higher priority)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    organization = relationship("Organization", back_populates="roles")

    def __repr__(self) -> str:
        return f"<Role {self.name} in org {self.organization_id}>"

    @property
    def display_name(self) -> str:
        """Get display name for the role."""
        return self.name.replace('_', ' ').title()

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has specific permission."""
        if not self.permissions_config:
            return False

        resource_perms = self.permissions_config.get(resource, {})
        if isinstance(resource_perms, dict):
            return resource_perms.get(action, False)
        elif isinstance(resource_perms, list):
            return action in resource_perms
        elif resource_perms == "*":
            return True

        return False

    @property
    def user_count(self) -> int:
        """Get the number of users assigned to this role."""
        return len(self.users) if self.users else 0


class Permission(UUIDBaseModel):
    """Permission model for fine-grained access control."""

    __tablename__ = "permissions"

    # Basic permission fields
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Permission categorization
    resource: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # System permission flag
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

    def __repr__(self) -> str:
        return f"<Permission {self.name} ({self.resource}:{self.action})>"

    @property
    def display_name(self) -> str:
        """Get display name for the permission."""
        return self.name.replace('_', ' ').title()

    @property
    def full_name(self) -> str:
        """Get full permission name in resource:action format."""
        return f"{self.resource}:{self.action}"
