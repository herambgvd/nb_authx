"""
Base schemas and common types
"""
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar, List

T = TypeVar('T')


class ActionStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"


class TimestampSchema(BaseModel):
    created_at: datetime
    updated_at: datetime


class UUIDSchema(BaseModel):
    id: str


class MessageResponse(BaseModel):
    message: str
    status: str = "success"


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    size: int
    pages: int


class TokenPayload(BaseModel):
    """JWT token payload"""
    sub: str  # user ID
    email: str
    org_id: str | None = None
    is_super_admin: bool = False
    exp: int
    iat: int
