"""
Role and Permission models
"""
from sqlalchemy import Column, String, Boolean, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class Role(Base, UUIDMixin, TimestampMixin):
    """Role model - organization scoped"""
    __tablename__ = "roles"

    name = Column(String(100), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True, nullable=False)

    # Organization relationship
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="roles")

    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    role_permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_roles_organization_id', 'organization_id'),
        Index('ix_roles_is_active', 'is_active'),
        UniqueConstraint('name', 'organization_id', name='uq_role_name_organization'),
    )


class Permission(Base, UUIDMixin, TimestampMixin):
    """Permission model"""
    __tablename__ = "permissions"

    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    resource = Column(String(100), nullable=False)  # e.g., 'user', 'role', 'organization'
    action = Column(String(50), nullable=False)     # e.g., 'create', 'read', 'update', 'delete'

    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

    __table_args__ = (
        Index('ix_permissions_resource_action', 'resource', 'action'),
        UniqueConstraint('resource', 'action', name='uq_permission_resource_action'),
    )


class UserRole(Base, UUIDMixin, TimestampMixin):
    """User-Role association - organization scoped"""
    __tablename__ = "user_roles"

    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)

    # Relationships
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")

    __table_args__ = (
        Index('ix_user_roles_user_id', 'user_id'),
        Index('ix_user_roles_role_id', 'role_id'),
        UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
    )


class RolePermission(Base, UUIDMixin, TimestampMixin):
    """Role-Permission association"""
    __tablename__ = "role_permissions"

    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    permission_id = Column(String(36), ForeignKey("permissions.id"), nullable=False)

    # Relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")

    __table_args__ = (
        Index('ix_role_permissions_role_id', 'role_id'),
        Index('ix_role_permissions_permission_id', 'permission_id'),
        UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
    )
