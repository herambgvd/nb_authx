"""
Main API router for AuthX.
Combines all API route modules into a single router.
"""

from fastapi import APIRouter

from app.api.v1 import (
    auth,
    user,
    organization,
    role,
    location,
    admin,
    audit,
    operations,
)

# Create main API router
api_router = APIRouter()

# Include all API routes with proper prefixes and tags
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(user.router, prefix="/users", tags=["users"])
api_router.include_router(organization.router, prefix="/organizations", tags=["organizations"])
api_router.include_router(role.router, prefix="/roles", tags=["roles"])
api_router.include_router(location.router, prefix="/locations", tags=["locations"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(operations.router, prefix="/operations", tags=["operations"])


@api_router.get("/status")
async def api_status():
    """API status endpoint."""
    return {
        "status": "API is running",
        "version": "1.0.0",
        "available_endpoints": [
            "/auth",
            "/users",
            "/organizations",
            "/roles",
            "/locations",
            "/admin",
            "/audit",
            "/operations"
        ]
    }
