"""
Base schemas for the AuthX service.
This module provides base Pydantic models for API requests and responses.
"""
from datetime import datetime
from typing import Optional, List, Generic, TypeVar, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict

# Type variable for generic models
T = TypeVar('T')

class BaseSchema(BaseModel):
    """Base schema with common configuration."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        arbitrary_types_allowed=True
    )

class TimestampSchema(BaseSchema):
    """Schema mixin with timestamp fields."""
    created_at: datetime
    updated_at: datetime

class UUIDSchema(BaseSchema):
    """Schema mixin with UUID primary key."""
    id: UUID

class TenantBaseSchema(BaseSchema):
    """Schema mixin for organization-specific (tenant) models."""
    organization_id: UUID

class ResponseBase(BaseSchema, Generic[T]):
    """Base schema for API responses."""
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None

class PaginatedResponse(ResponseBase, Generic[T]):
    """Schema for paginated API responses."""
    data: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int

class ErrorResponse(ResponseBase):
    """Schema for error responses."""
    success: bool = False
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class TokenResponse(BaseSchema):
    """Schema for authentication token responses."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
