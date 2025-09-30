"""
Audit log model for tracking user actions
"""
from sqlalchemy import Column, String, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class AuditLog(Base, UUIDMixin, TimestampMixin):
    """Audit log model for tracking user actions"""
    __tablename__ = "audit_logs"

    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=True)

    action = Column(String(100), nullable=False)  # e.g., 'login', 'create_user', 'update_role'
    resource = Column(String(100))  # e.g., 'user', 'role', 'organization'
    resource_id = Column(String(36))  # ID of the affected resource

    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(Text)

    # Additional context
    details = Column(Text)  # JSON string with additional details
    status = Column(String(20), nullable=False)  # 'success', 'failure', 'warning'

    # Relationships
    user = relationship("User", back_populates="audit_logs")
    organization = relationship("Organization", back_populates="audit_logs")

    __table_args__ = (
        Index('ix_audit_logs_user_id', 'user_id'),
        Index('ix_audit_logs_organization_id', 'organization_id'),
        Index('ix_audit_logs_action', 'action'),
        Index('ix_audit_logs_resource', 'resource'),
        Index('ix_audit_logs_created_at', 'created_at'),
        Index('ix_audit_logs_status', 'status'),
    )
