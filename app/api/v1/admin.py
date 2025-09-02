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
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.api.deps import get_db, get_current_superadmin
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    config_data: SystemConfigCreate
):
    """
    Create a new system configuration.
    Only superadmins can create system configurations.
    """
    # Check if config with the same key already exists
    existing_config = db.query(SystemConfig).filter(SystemConfig.key == config_data.key).first()

    if existing_config:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"System configuration with key '{config_data.key}' already exists"
        )

    # Create new system configuration
    new_config = SystemConfig(
        **config_data.dict(),
        created_by=current_user.id,
        updated_by=current_user.id
    )
    db.add(new_config)
    db.commit()
    db.refresh(new_config)

    return new_config

@router.get("/system/config", response_model=SystemConfigListResponse)
async def get_system_configs(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    key: Optional[str] = None
):
    """
    Get a paginated list of system configurations with optional filtering.
    Only superadmins can view system configurations.
    """
    # Build query
    query = db.query(SystemConfig)

    # Apply filters
    if key:
        query = query.filter(SystemConfig.key.ilike(f"%{key}%"))

    # Get total count
    total = query.count()

    # Apply pagination
    configs = query.offset(skip).limit(limit).all()

    return {
        "items": configs,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/system/config/{config_id}", response_model=SystemConfigResponse)
async def get_system_config(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    config_id: UUID
):
    """
    Get detailed information about a specific system configuration by ID.
    Only superadmins can view system configurations.
    """
    # Get system config
    config = db.query(SystemConfig).filter(SystemConfig.id == config_id).first()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    return config

@router.patch("/system/config/{config_id}", response_model=SystemConfigResponse)
async def update_system_config(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    config_id: UUID,
    config_data: SystemConfigUpdate
):
    """
    Update a system configuration's details.
    Only superadmins can update system configurations.
    """
    # Get system config
    config = db.query(SystemConfig).filter(SystemConfig.id == config_id).first()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    # Update config
    update_data = config_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(config, key, value)

    # Update audit fields
    config.updated_by = current_user.id

    db.commit()
    db.refresh(config)

    return config

@router.delete("/system/config/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_system_config(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    config_id: UUID
):
    """
    Delete a system configuration.
    Only superadmins can delete system configurations.
    """
    # Get system config
    config = db.query(SystemConfig).filter(SystemConfig.id == config_id).first()

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="System configuration not found"
        )

    # Delete config
    db.delete(config)
    db.commit()

    return None

# License Management Endpoints
@router.post("/licenses", response_model=LicenseResponse, status_code=status.HTTP_201_CREATED)
async def create_license(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    license_data: LicenseCreate
):
    """
    Create a new license.
    Only superadmins can create licenses.
    """
    # Check if license with the same key already exists
    existing_license = db.query(License).filter(License.key == license_data.key).first()

    if existing_license:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"License with key '{license_data.key}' already exists"
        )

    # Validate organization if provided
    if license_data.organization_id:
        organization = db.query(Organization).filter(Organization.id == license_data.organization_id).first()

        if not organization:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found"
            )

    # Create new license
    new_license = License(**license_data.dict())
    db.add(new_license)
    db.commit()
    db.refresh(new_license)

    # Add usage data for response
    usage = {"current_users": 0, "current_locations": 0}

    if new_license.organization_id:
        # Count users in the organization
        user_count = db.query(func.count(User.id)).filter(
            User.organization_id == new_license.organization_id
        ).scalar() or 0

        # Count locations in the organization
        from app.models.location import Location
        location_count = db.query(func.count(Location.id)).filter(
            Location.organization_id == new_license.organization_id
        ).scalar() or 0

        usage = {
            "current_users": user_count,
            "current_locations": location_count
        }

    # Determine license status
    now = datetime.utcnow()
    if not new_license.is_active:
        status = "inactive"
    elif now > new_license.expiration_date:
        status = "expired"
    else:
        status = "active"

    # Prepare response
    response_data = {
        **new_license.__dict__,
        "status": status,
        "usage": usage
    }

    return response_data

@router.get("/licenses", response_model=LicenseListResponse)
async def get_licenses(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    organization_id: Optional[UUID] = None,
    type: Optional[str] = None,
    is_active: Optional[bool] = None
):
    """
    Get a paginated list of licenses with optional filtering.
    Only superadmins can view licenses.
    """
    # Build query
    query = db.query(License)

    # Apply filters
    if organization_id:
        query = query.filter(License.organization_id == organization_id)

    if type:
        query = query.filter(License.type == type)

    if is_active is not None:
        query = query.filter(License.is_active == is_active)

    # Get total count
    total = query.count()

    # Apply pagination
    licenses = query.offset(skip).limit(limit).all()

    # Add usage and status to each license
    now = datetime.utcnow()
    license_responses = []

    for license in licenses:
        # Calculate usage
        usage = {"current_users": 0, "current_locations": 0}

        if license.organization_id:
            # Count users in the organization
            user_count = db.query(func.count(User.id)).filter(
                User.organization_id == license.organization_id
            ).scalar() or 0

            # Count locations in the organization
            from app.models.location import Location
            location_count = db.query(func.count(Location.id)).filter(
                Location.organization_id == license.organization_id
            ).scalar() or 0

            usage = {
                "current_users": user_count,
                "current_locations": location_count
            }

        # Determine license status
        if not license.is_active:
            status = "inactive"
        elif now > license.expiration_date:
            status = "expired"
        else:
            status = "active"

        # Add to response
        license_data = {
            **license.__dict__,
            "status": status,
            "usage": usage
        }
        license_responses.append(license_data)

    return {
        "items": license_responses,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/licenses/{license_id}", response_model=LicenseResponse)
async def get_license(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    license_id: UUID
):
    """
    Get detailed information about a specific license by ID.
    Only superadmins can view licenses.
    """
    # Get license
    license = db.query(License).filter(License.id == license_id).first()

    if not license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )

    # Calculate usage
    usage = {"current_users": 0, "current_locations": 0}

    if license.organization_id:
        # Count users in the organization
        user_count = db.query(func.count(User.id)).filter(
            User.organization_id == license.organization_id
        ).scalar() or 0

        # Count locations in the organization
        from app.models.location import Location
        location_count = db.query(func.count(Location.id)).filter(
            Location.organization_id == license.organization_id
        ).scalar() or 0

        usage = {
            "current_users": user_count,
            "current_locations": location_count
        }

    # Determine license status
    now = datetime.utcnow()
    if not license.is_active:
        status = "inactive"
    elif now > license.expiration_date:
        status = "expired"
    else:
        status = "active"

    # Prepare response
    response_data = {
        **license.__dict__,
        "status": status,
        "usage": usage
    }

    return response_data

@router.patch("/licenses/{license_id}", response_model=LicenseResponse)
async def update_license(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    license_id: UUID,
    license_data: LicenseUpdate
):
    """
    Update a license's details.
    Only superadmins can update licenses.
    """
    # Get license
    license = db.query(License).filter(License.id == license_id).first()

    if not license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )

    # Update license
    update_data = license_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(license, key, value)

    db.commit()
    db.refresh(license)

    # Calculate usage for response
    usage = {"current_users": 0, "current_locations": 0}

    if license.organization_id:
        # Count users in the organization
        user_count = db.query(func.count(User.id)).filter(
            User.organization_id == license.organization_id
        ).scalar() or 0

        # Count locations in the organization
        from app.models.location import Location
        location_count = db.query(func.count(Location.id)).filter(
            Location.organization_id == license.organization_id
        ).scalar() or 0

        usage = {
            "current_users": user_count,
            "current_locations": location_count
        }

    # Determine license status
    now = datetime.utcnow()
    if not license.is_active:
        status = "inactive"
    elif now > license.expiration_date:
        status = "expired"
    else:
        status = "active"

    # Prepare response
    response_data = {
        **license.__dict__,
        "status": status,
        "usage": usage
    }

    return response_data

@router.post("/licenses/{license_id}/assign/{organization_id}", response_model=LicenseResponse)
async def assign_license_to_organization(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    license_id: UUID,
    organization_id: UUID
):
    """
    Assign a license to an organization.
    Only superadmins can assign licenses.
    """
    # Get license
    license = db.query(License).filter(License.id == license_id).first()

    if not license:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="License not found"
        )

    # Get organization
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Check if license is already assigned to another organization
    if license.organization_id and license.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="License is already assigned to another organization"
        )

    # Check if organization already has a license
    existing_license = db.query(License).filter(License.organization_id == organization_id).first()
    if existing_license and existing_license.id != license_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization already has a license assigned"
        )

    # Assign license to organization
    license.organization_id = organization_id
    db.commit()
    db.refresh(license)

    # Calculate usage for response
    usage = {"current_users": 0, "current_locations": 0}

    # Count users in the organization
    user_count = db.query(func.count(User.id)).filter(
        User.organization_id == license.organization_id
    ).scalar() or 0

    # Count locations in the organization
    from app.models.location import Location
    location_count = db.query(func.count(Location.id)).filter(
        Location.organization_id == license.organization_id
    ).scalar() or 0

    usage = {
        "current_users": user_count,
        "current_locations": location_count
    }

    # Determine license status
    now = datetime.utcnow()
    if not license.is_active:
        status = "inactive"
    elif now > license.expiration_date:
        status = "expired"
    else:
        status = "active"

    # Prepare response
    response_data = {
        **license.__dict__,
        "status": status,
        "usage": usage
    }

    return response_data

# Platform Analytics Endpoints
@router.get("/analytics/platform", response_model=PlatformAnalyticsResponse)
async def get_platform_analytics(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    interval: str = Query("day", regex="^(hour|day|week|month)$")
):
    """
    Get platform-wide analytics data.
    Only superadmins can view platform analytics.
    """
    # Validate time range
    if end_date <= start_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="End date must be after start date"
        )

    # Get analytics data
    # In a real implementation, this would query from actual metrics tables
    # For this example, we'll generate mock data

    # Time range for response
    time_range = {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "interval": interval
    }

    # Summary metrics
    summary_metrics = [
        {
            "name": "total_organizations",
            "value": db.query(func.count(Organization.id)).scalar() or 0,
            "change": 5.2,  # Mock percentage change
            "trend": "up"
        },
        {
            "name": "total_users",
            "value": db.query(func.count(User.id)).scalar() or 0,
            "change": 8.7,
            "trend": "up"
        },
        {
            "name": "active_users_last_30_days",
            "value": db.query(func.count(User.id)).filter(
                User.last_login >= (datetime.utcnow() - timedelta(days=30))
            ).scalar() or 0,
            "change": 12.3,
            "trend": "up"
        },
        {
            "name": "security_events",
            "value": db.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.created_at.between(start_date, end_date)
            ).scalar() or 0,
            "change": -3.5,
            "trend": "down"
        }
    ]

    # Generate time series data based on interval
    # For demonstration purposes, we'll create mock time series
    user_growth_series = []
    login_activity_series = []
    security_events_series = []

    current_date = start_date
    while current_date <= end_date:
        # Format date based on interval
        if interval == "hour":
            date_key = current_date.strftime("%Y-%m-%d %H:00")
            next_date = current_date + timedelta(hours=1)
        elif interval == "day":
            date_key = current_date.strftime("%Y-%m-%d")
            next_date = current_date + timedelta(days=1)
        elif interval == "week":
            date_key = current_date.strftime("%Y-%m-%d")
            next_date = current_date + timedelta(weeks=1)
        else:  # month
            date_key = current_date.strftime("%Y-%m")
            # Add 1 month - a bit tricky in Python
            if current_date.month == 12:
                next_date = datetime(current_date.year + 1, 1, 1)
            else:
                next_date = datetime(current_date.year, current_date.month + 1, 1)

        # In a real implementation, these would query actual data for each period
        # Here we're using mock data
        user_growth_series.append({
            "timestamp": date_key,
            "value": 50 + (current_date - start_date).days * 2  # Mock increasing trend
        })

        login_activity_series.append({
            "timestamp": date_key,
            "value": 200 + (current_date - start_date).days * 5  # Mock increasing trend
        })

        security_events_series.append({
            "timestamp": date_key,
            "value": 10 - (current_date - start_date).days * 0.5  # Mock decreasing trend
        })

        current_date = next_date

    series_data = [
        {
            "name": "user_growth",
            "data": user_growth_series
        },
        {
            "name": "login_activity",
            "data": login_activity_series
        },
        {
            "name": "security_events",
            "data": security_events_series
        }
    ]

    return {
        "time_range": time_range,
        "summary_metrics": summary_metrics,
        "series_data": series_data
    }

@router.get("/analytics/organizations/{organization_id}", response_model=OrganizationAnalyticsResponse)
async def get_organization_analytics(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    organization_id: UUID,
    start_date: datetime = Query(...),
    end_date: datetime = Query(...),
    interval: str = Query("day", regex="^(hour|day|week|month)$")
):
    """
    Get analytics data for a specific organization.
    Only superadmins can view organization analytics.
    """
    # Check if organization exists
    organization = db.query(Organization).filter(Organization.id == organization_id).first()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )

    # Validate time range
    if end_date <= start_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="End date must be after start date"
        )

    # Time range for response
    time_range = {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "interval": interval
    }

    # Summary metrics for the organization
    summary_metrics = [
        {
            "name": "total_users",
            "value": db.query(func.count(User.id)).filter(
                User.organization_id == organization_id
            ).scalar() or 0,
            "change": 3.8,  # Mock percentage change
            "trend": "up"
        },
        {
            "name": "active_users_last_30_days",
            "value": db.query(func.count(User.id)).filter(
                User.organization_id == organization_id,
                User.last_login >= (datetime.utcnow() - timedelta(days=30))
            ).scalar() or 0,
            "change": 5.2,
            "trend": "up"
        },
        {
            "name": "security_events",
            "value": db.query(func.count(SecurityEvent.id)).filter(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.created_at.between(start_date, end_date)
            ).scalar() or 0,
            "change": -2.1,
            "trend": "down"
        },
        {
            "name": "login_success_rate",
            "value": 97.5,  # Mock percentage
            "change": 0.8,
            "trend": "up"
        }
    ]

    # Generate time series data based on interval
    # For demonstration purposes, we'll create mock time series
    user_activity_series = []
    login_series = []
    security_events_series = []

    current_date = start_date
    while current_date <= end_date:
        # Format date based on interval
        if interval == "hour":
            date_key = current_date.strftime("%Y-%m-%d %H:00")
            next_date = current_date + timedelta(hours=1)
        elif interval == "day":
            date_key = current_date.strftime("%Y-%m-%d")
            next_date = current_date + timedelta(days=1)
        elif interval == "week":
            date_key = current_date.strftime("%Y-%m-%d")
            next_date = current_date + timedelta(weeks=1)
        else:  # month
            date_key = current_date.strftime("%Y-%m")
            # Add 1 month - a bit tricky in Python
            if current_date.month == 12:
                next_date = datetime(current_date.year + 1, 1, 1)
            else:
                next_date = datetime(current_date.year, current_date.month + 1, 1)

        # In a real implementation, these would query actual data for each period
        # Here we're using mock data
        user_activity_series.append({
            "timestamp": date_key,
            "value": 30 + (current_date - start_date).days * 1.5  # Mock increasing trend
        })

        login_series.append({
            "timestamp": date_key,
            "value": 100 + (current_date - start_date).days * 3  # Mock increasing trend
        })

        security_events_series.append({
            "timestamp": date_key,
            "value": 5 - (current_date - start_date).days * 0.2  # Mock decreasing trend
        })

        current_date = next_date

    series_data = [
        {
            "name": "user_activity",
            "data": user_activity_series
        },
        {
            "name": "logins",
            "data": login_series
        },
        {
            "name": "security_events",
            "data": security_events_series
        }
    ]

    return {
        "organization_id": organization_id,
        "time_range": time_range,
        "summary_metrics": summary_metrics,
        "series_data": series_data
    }

# User Impersonation Endpoints
@router.post("/impersonate", response_model=ImpersonationResponse, status_code=status.HTTP_201_CREATED)
async def impersonate_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    impersonation_data: ImpersonationRequest
):
    """
    Impersonate a user for support purposes.
    Only superadmins can impersonate users.
    """
    # Get user to impersonate
    user = db.query(User).filter(User.id == impersonation_data.user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Create impersonation session
    expires_at = datetime.utcnow() + timedelta(minutes=impersonation_data.max_duration_minutes)

    # Generate special token for impersonation
    access_token = create_access_token(
        data={"sub": str(user.id), "impersonator": str(current_user.id)},
        expires_delta=timedelta(minutes=impersonation_data.max_duration_minutes)
    )

    # Store impersonation record
    impersonation = UserImpersonation(
        user_id=user.id,
        impersonator_id=current_user.id,
        reason=impersonation_data.reason,
        token=access_token,
        expires_at=expires_at,
        is_active=True
    )
    db.add(impersonation)
    db.commit()
    db.refresh(impersonation)

    # Create audit log for impersonation
    audit_log = AuditLog(
        user_id=current_user.id,
        user_email=current_user.email,
        event_type="impersonation",
        resource_type="user",
        resource_id=str(user.id),
        action="impersonate",
        description=f"User {current_user.email} impersonated user {user.email}",
        status="success",
        details={"reason": impersonation_data.reason},
        organization_id=current_user.organization_id
    )
    db.add(audit_log)
    db.commit()

    return {
        "id": impersonation.id,
        "user_id": user.id,
        "impersonator_id": current_user.id,
        "reason": impersonation_data.reason,
        "token": access_token,
        "expires_at": expires_at,
        "is_active": True,
        "created_at": impersonation.created_at,
        "updated_at": impersonation.updated_at
    }

@router.post("/impersonate/end", status_code=status.HTTP_204_NO_CONTENT)
async def end_impersonation(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin),
    end_data: ImpersonationEndRequest
):
    """
    End an active impersonation session.
    Only superadmins can end impersonation sessions.
    """
    # Get impersonation session
    impersonation = db.query(UserImpersonation).filter(
        UserImpersonation.id == end_data.session_id,
        UserImpersonation.is_active == True
    ).first()

    if not impersonation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active impersonation session not found"
        )

    # Check if current user is the impersonator
    if impersonation.impersonator_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to end this impersonation session"
        )

    # End impersonation session
    impersonation.is_active = False
    impersonation.ended_at = datetime.utcnow()
    db.commit()

    # Create audit log for ending impersonation
    audit_log = AuditLog(
        user_id=current_user.id,
        user_email=current_user.email,
        event_type="impersonation",
        resource_type="user",
        resource_id=str(impersonation.user_id),
        action="end_impersonate",
        description=f"User {current_user.email} ended impersonation of user {impersonation.user.email}",
        status="success",
        organization_id=current_user.organization_id
    )
    db.add(audit_log)
    db.commit()

    return None

# System Health Endpoints
@router.get("/system/health", response_model=SystemHealthResponse)
async def get_system_health(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_superadmin)
):
    """
    Get the current health status of the system.
    Only superadmins can view system health.
    """
    components = []
    overall_status = "healthy"

    # Check database connection
    try:
        db.execute("SELECT 1").scalar()
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"
        overall_status = "degraded"

    components.append({
        "name": "database",
        "status": db_status,
        "details": {
            "type": "postgresql",
            "connection_pool": "active"
        }
    })

    # Check authentication service
    auth_status = "healthy"  # Mock status
    components.append({
        "name": "authentication",
        "status": auth_status,
        "details": {
            "provider": "internal",
            "jwt_signing": "active"
        }
    })

    # Check cache service
    cache_status = "healthy"  # Mock status
    components.append({
        "name": "cache",
        "status": cache_status,
        "details": {
            "type": "redis",
            "connection": "active"
        }
    })

    # Check email service
    email_status = "healthy"  # Mock status
    components.append({
        "name": "email",
        "status": email_status,
        "details": {
            "provider": "smtp",
            "queue": "active"
        }
    })

    return {
        "status": overall_status,
        "components": components,
        "timestamp": datetime.utcnow()
    }
