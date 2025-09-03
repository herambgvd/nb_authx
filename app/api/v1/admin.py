"""
Super Admin API endpoints for the AuthX service.
This module provides API endpoints for system configuration, license management,
platform analytics, and user impersonation.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
import secrets
import string
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body, BackgroundTasks, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.api.deps import get_async_db, get_current_superuser
from app.models.user import User
from app.models.organization import Organization
from app.models.admin import SystemConfig, License, UserImpersonation, MaintenanceWindow, PlatformMetric
from app.models.audit import AuditLog, SecurityEvent
from app.schemas.admin import (
    SystemConfigCreate,
    SystemConfigUpdate,
    SystemConfigResponse,
    SystemConfigListResponse,
    LicenseCreate,
    LicenseUpdate,
    LicenseResponse,
    LicenseListResponse,
    PlatformAnalyticsResponse,
    OrganizationAnalyticsResponse,
    ImpersonationRequest,
    ImpersonationResponse,
    ImpersonationEndRequest,
    SystemHealthResponse,
    HealthCheckComponent,
    AnalyticsTimeRange,
    AnalyticsMetric,
    AnalyticsSeries
)
from app.utils.security import create_access_token

router = APIRouter()

# System Configuration Endpoints
@router.post("/system/config", response_model=SystemConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_system_config(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    config_data: SystemConfigCreate
):
    """
    Create a new system configuration.
    Only superadmins can create system configurations.
    """
    # Check if config with same key already exists
    result = await db.execute(select(SystemConfig).where(SystemConfig.key == config_data.key))
    existing_config = result.scalar_one_or_none()

    if existing_config:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"System configuration with key '{config_data.key}' already exists"
        )

    # Create new system config
    new_config = SystemConfig(**config_data.dict())
    db.add(new_config)
    await db.commit()
    await db.refresh(new_config)

    return new_config

@router.get("/system/config", response_model=SystemConfigListResponse)
async def get_system_configs(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    key: Optional[str] = None,
    category: Optional[str] = None,
    is_active: Optional[bool] = None
):
    """
    Get system configurations with filtering and pagination.
    Only superadmins can view system configurations.
    """
    # Build query
    query = select(SystemConfig)

    # Apply filters
    if key:
        query = query.where(SystemConfig.key.ilike(f"%{key}%"))
    if category:
        query = query.where(SystemConfig.category == category)
    if is_active is not None:
        query = query.where(SystemConfig.is_active == is_active)

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply pagination
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    configs = result.scalars().all()

    return SystemConfigListResponse(
        configs=[SystemConfigResponse.from_orm(config) for config in configs],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.get("/system/config/{config_id}", response_model=SystemConfigResponse)
async def get_system_config(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    config_id: UUID
):
    """Get system configuration by ID."""
    result = await db.execute(select(SystemConfig).where(SystemConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    return config

@router.put("/system/config/{config_id}", response_model=SystemConfigResponse)
async def update_system_config(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    config_id: UUID,
    config_data: SystemConfigUpdate
):
    """Update system configuration."""
    result = await db.execute(select(SystemConfig).where(SystemConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    # Update configuration with provided data
    update_data = config_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(config, key, value)

    await db.commit()
    await db.refresh(config)

    return config

@router.delete("/system/config/{config_id}")
async def delete_system_config(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    config_id: UUID
):
    """Delete system configuration."""
    result = await db.execute(select(SystemConfig).where(SystemConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    await db.delete(config)
    await db.commit()

    return {"message": "System configuration deleted successfully"}

# License Management Endpoints
@router.post("/licenses", response_model=LicenseResponse, status_code=status.HTTP_201_CREATED)
async def create_license(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    license_data: LicenseCreate
):
    """
    Create a new license.
    Only superadmins can create licenses.
    """
    # Generate license key if not provided
    if not license_data.license_key:
        license_data.license_key = generate_license_key()

    # Create new license
    new_license = License(**license_data.dict())
    db.add(new_license)
    await db.commit()
    await db.refresh(new_license)

    return new_license

@router.get("/licenses", response_model=LicenseListResponse)
async def get_licenses(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    organization_id: Optional[UUID] = None,
    license_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_expired: Optional[bool] = None
):
    """
    Get licenses with filtering and pagination.
    Only superadmins can view all licenses.
    """
    # Build query
    query = select(License)

    # Apply filters
    if organization_id:
        query = query.where(License.organization_id == organization_id)
    if license_type:
        query = query.where(License.license_type == license_type)
    if is_active is not None:
        query = query.where(License.is_active == is_active)
    if is_expired is not None:
        if is_expired:
            query = query.where(License.expires_at < datetime.utcnow())
        else:
            query = query.where(License.expires_at >= datetime.utcnow())

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply pagination
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    licenses = result.scalars().all()

    return LicenseListResponse(
        licenses=[LicenseResponse.from_orm(license) for license in licenses],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

# Platform Analytics Endpoints
@router.get("/analytics/platform", response_model=PlatformAnalyticsResponse)
async def get_platform_analytics(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    time_range: AnalyticsTimeRange = Query(AnalyticsTimeRange.last_30_days)
):
    """
    Get platform-wide analytics.
    Only superadmins can view platform analytics.
    """
    # Calculate date range
    end_date = datetime.utcnow()
    if time_range == AnalyticsTimeRange.last_7_days:
        start_date = end_date - timedelta(days=7)
    elif time_range == AnalyticsTimeRange.last_30_days:
        start_date = end_date - timedelta(days=30)
    elif time_range == AnalyticsTimeRange.last_90_days:
        start_date = end_date - timedelta(days=90)
    else:
        start_date = end_date - timedelta(days=365)

    # Get basic metrics
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar()

    total_orgs_result = await db.execute(select(func.count(Organization.id)))
    total_organizations = total_orgs_result.scalar()

    active_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_active == True)
    )
    active_users = active_users_result.scalar()

    # Get time series data for user registrations
    user_registrations_result = await db.execute(
        select(
            func.date(User.created_at).label('date'),
            func.count(User.id).label('count')
        ).where(
            User.created_at >= start_date
        ).group_by(
            func.date(User.created_at)
        ).order_by(
            func.date(User.created_at)
        )
    )
    user_registrations = user_registrations_result.all()

    return PlatformAnalyticsResponse(
        total_users=total_users,
        total_organizations=total_organizations,
        active_users=active_users,
        user_registrations=[
            AnalyticsSeries(date=reg.date, value=reg.count)
            for reg in user_registrations
        ],
        time_range=time_range
    )

# User Impersonation Endpoints
@router.post("/impersonate", response_model=ImpersonationResponse)
async def start_impersonation(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    impersonation_data: ImpersonationRequest
):
    """
    Start impersonating a user.
    Only superadmins can impersonate users.
    """
    # Get target user
    result = await db.execute(select(User).where(User.id == impersonation_data.target_user_id))
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found"
        )

    # Create impersonation record
    impersonation = UserImpersonation(
        admin_user_id=current_user.id,
        target_user_id=target_user.id,
        reason=impersonation_data.reason,
        started_at=datetime.utcnow()
    )
    db.add(impersonation)
    await db.commit()
    await db.refresh(impersonation)

    # Create impersonation token
    impersonation_token = create_access_token(
        data={
            "sub": str(target_user.id),
            "impersonation_id": str(impersonation.id),
            "admin_user_id": str(current_user.id)
        }
    )

    return ImpersonationResponse(
        impersonation_id=impersonation.id,
        target_user_id=target_user.id,
        impersonation_token=impersonation_token,
        expires_at=impersonation.started_at + timedelta(hours=1)
    )

@router.post("/impersonate/end")
async def end_impersonation(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser),
    end_data: ImpersonationEndRequest
):
    """
    End an active impersonation session.
    Only superadmins can end impersonation.
    """
    # Get impersonation record
    result = await db.execute(
        select(UserImpersonation).where(UserImpersonation.id == end_data.impersonation_id)
    )
    impersonation = result.scalar_one_or_none()

    if not impersonation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Impersonation session not found"
        )

    if impersonation.ended_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impersonation session already ended"
        )

    # End impersonation
    impersonation.ended_at = datetime.utcnow()
    await db.commit()

    return {"message": "Impersonation session ended successfully"}

# System Health Endpoints
@router.get("/health", response_model=SystemHealthResponse)
async def get_system_health(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    Get system health status.
    Only superadmins can view system health.
    """
    components = []

    # Database health check
    try:
        await db.execute(select(1))
        db_health = HealthCheckComponent(
            name="database",
            status="healthy",
            message="Database connection successful"
        )
    except Exception as e:
        db_health = HealthCheckComponent(
            name="database",
            status="unhealthy",
            message=f"Database connection failed: {str(e)}"
        )

    components.append(db_health)

    # Determine overall status
    overall_status = "healthy" if all(c.status == "healthy" for c in components) else "unhealthy"

    return SystemHealthResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        components=components
    )

# Helper functions
def generate_license_key() -> str:
    """Generate a random license key."""
    characters = string.ascii_uppercase + string.digits
    return '-'.join([''.join(secrets.choice(characters) for _ in range(4)) for _ in range(4)])
