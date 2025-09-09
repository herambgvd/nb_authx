"""
Base schemas for AuthX API.
Common response models and validation schemas.
"""
from datetime import datetime
from typing import Optional, Any, Dict
from uuid import UUID

from pydantic import BaseModel, Field

class BaseSchema(BaseModel):
    """Base schema with common configuration."""
    class Config:
        from_attributes = True
        validate_assignment = True
        use_enum_values = True

class UUIDSchema(BaseSchema):
    """Base schema with UUID field."""
    id: UUID

class TimestampSchema(BaseSchema):
    """Base schema with timestamp fields."""
    created_at: datetime
    updated_at: datetime

class TenantBaseSchema(BaseSchema):
    """Base schema for tenant-aware entities."""
    organization_id: Optional[UUID] = None

class BaseResponse(BaseModel):
    """Base response schema with common fields."""
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ErrorResponse(BaseModel):
    """Error response schema."""
    success: bool = False
    error: str
    details: Optional[Dict[str, Any]] = None
    status_code: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class MessageResponse(BaseModel):
    """Simple message response schema."""
    message: str
    success: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class PaginationMeta(BaseModel):
    """Pagination metadata schema."""
    total: int
    page: int
    per_page: int
    total_pages: int
    has_next: bool
    has_prev: bool

class BaseListResponse(BaseModel):
    """Base list response with pagination."""
    meta: PaginationMeta
    success: bool = True

class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    environment: str
    services: Optional[Dict[str, Any]] = None
