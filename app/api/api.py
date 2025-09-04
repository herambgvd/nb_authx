"""
Main API router for AuthX application.
Combines all API endpoints into a single router with proper organization.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.api.v1 import (
    auth,
    user,
    organization,
    role,
    location,
    admin,
    audit,
    operations
)

# Create main API router
api_router = APIRouter()

# Health check endpoint
@api_router.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "healthy",
            "service": "AuthX",
            "version": "1.0.0"
        }
    )

# Include all v1 API routers with proper prefixes and tags
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

api_router.include_router(
    user.router,
    prefix="/users",
    tags=["Users"]
)

api_router.include_router(
    organization.router,
    prefix="/organizations",
    tags=["Organizations"]
)

api_router.include_router(
    role.router,
    prefix="/roles",
    tags=["Roles & Permissions"]
)

api_router.include_router(
    location.router,
    prefix="/locations",
    tags=["Locations"]
)

api_router.include_router(
    admin.router,
    prefix="/admin",
    tags=["Administration"]
)

api_router.include_router(
    audit.router,
    prefix="/audit",
    tags=["Audit & Logging"]
)

api_router.include_router(
    operations.router,
    prefix="/ops",
    tags=["Operations"]
)
