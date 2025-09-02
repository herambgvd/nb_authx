from fastapi import APIRouter

from app.api.v1 import auth, organization, location, user, role, audit, admin, operations

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(organization.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(location.router, prefix="/locations", tags=["Locations"])
api_router.include_router(user.router, prefix="/users", tags=["Users"])
api_router.include_router(role.router, prefix="/rbac", tags=["Role-Based Access Control"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit & Logging"])
api_router.include_router(admin.router, prefix="/admin", tags=["Super Admin"])
api_router.include_router(operations.router, prefix="/ops", tags=["Operations"])
