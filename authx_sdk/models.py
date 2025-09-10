"""
AuthX SDK Data Models - Pydantic models for API responses and requests.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field

class User(BaseModel):
    """User model for AuthX SDK."""
    id: str
    email: EmailStr
    username: Optional[str] = None
    full_name: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    organization_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    """User creation model."""
    email: EmailStr
    password: str = Field(min_length=8)
    username: Optional[str] = None
    full_name: Optional[str] = None
    organization_id: Optional[str] = None

class UserUpdate(BaseModel):
    """User update model."""
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None

class Organization(BaseModel):
    """Organization model."""
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    tier: str = "free"
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class Role(BaseModel):
    """Role model."""
    id: str
    name: str
    description: Optional[str] = None
    permissions: List[str] = []
    organization_id: Optional[str] = None
    is_system_role: bool = False
    created_at: datetime

    class Config:
        from_attributes = True

class Location(BaseModel):
    """Location model."""
    id: str
    name: str
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    organization_id: Optional[str] = None
    is_active: bool = True
    created_at: datetime

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None

class AuthResponse(BaseModel):
    """Authentication response model."""
    user: User
    token: TokenResponse
    permissions: List[str] = []
    organization: Optional[Organization] = None

class ApiResponse(BaseModel):
    """Generic API response model."""
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None
    errors: Optional[List[str]] = None

class PaginatedResponse(BaseModel):
    """Paginated response model."""
    items: List[Any]
    total: int
    page: int = 1
    size: int = 50
    pages: int

class HealthCheck(BaseModel):
    """Health check response model."""
    status: str
    service: str
    version: str
    timestamp: float
    environment: str
    checks: Optional[Dict[str, Any]] = None
