"""
Audit log schemas
"""
from pydantic import BaseModel, ConfigDict
from typing import Optional
from app.schemas.base import UUIDSchema, TimestampSchema, ActionStatus


class AuditLogResponse(UUIDSchema, TimestampSchema):
    user_id: Optional[str] = None
    organization_id: Optional[str] = None
    action: str
    resource: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None
    status: ActionStatus

    model_config = ConfigDict(from_attributes=True)
