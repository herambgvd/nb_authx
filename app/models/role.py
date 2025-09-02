"""
Role and Permission models for the AuthX service.
This module defines the entities for role-based access control (RBAC).
"""
from typing import Optional, List
from sqlalchemy import Column, String, Boolean, Text, Integer, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.session import Base
from app.models.base import BaseModel, TenantBaseModel

# Many-to-many relationship between roles and permissions
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", UUID(as_uuid=True), ForeignKey("permissions.id"), primary_key=True),
)

class Role(TenantBaseModel):
    """
    Role model representing a set of permissions that can be assigned to users.
    """
    __tablename__ = "roles"

    # Basic information
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)

    # Role attributes
    is_system_role = Column(Boolean, default=False, nullable=False)
    is_location_specific = Column(Boolean, default=False, nullable=False)
    location_id = Column(UUID(as_uuid=True), ForeignKey("locations.id"), nullable=True)

    # Role hierarchy
    parent_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    users = relationship("UserRole", back_populates="role")
    parent = relationship("Role", remote_side="Role.id", backref="children")
    location = relationship("Location")

    def __repr__(self) -> str:
        return f"<Role {self.name}>"

class Permission(BaseModel):
    """
    Permission model representing a granular access control permission.
    """
    __tablename__ = "permissions"

    # Permission attributes
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    resource = Column(String(100), nullable=False)  # The resource this permission applies to
    action = Column(String(100), nullable=False)    # The action allowed on the resource (create, read, update, delete)

    # Permission attributes
    is_system_permission = Column(Boolean, default=False, nullable=False)

    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

    def __repr__(self) -> str:
        return f"<Permission {self.name}>"
