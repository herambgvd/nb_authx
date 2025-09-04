"""
Super Admin API endpoints for AuthX.
Provides comprehensive super admin functionality for system management.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime
from uuid import UUID

from app.db.session import get_async_db
from app.api.deps import get_current_super_admin, get_current_active_user
from app.schemas.admin import (
    SuperAdminDashboard, OrganizationApprovalRequest, OrganizationRejectionRequest,
    UserManagementAction, AuditLogFilter, UserFilter, SystemAlert, PerformanceMetrics
)
from app.services.super_admin_service import super_admin_service
from app.services.monitoring_service import monitoring_service
from app.models.user import User

router = APIRouter()

@router.get("/dashboard", response_model=SuperAdminDashboard)
async def get_dashboard(
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Get super admin dashboard with system statistics."""
    return await super_admin_service.get_dashboard_stats(db)

@router.get("/organizations/pending")
async def get_pending_organizations(
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Get organizations pending approval."""
    return await super_admin_service.get_pending_organizations(db)

@router.post("/organizations/approve")
async def approve_organization(
    request: OrganizationApprovalRequest,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Approve an organization registration."""
    success = await super_admin_service.approve_organization(
        db=db,
        organization_id=request.organization_id,
        approved_by=current_user.id,
        approval_notes=request.approval_notes
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to approve organization"
        )

    return {"message": "Organization approved successfully"}

@router.post("/organizations/reject")
async def reject_organization(
    request: OrganizationRejectionRequest,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Reject an organization registration."""
    success = await super_admin_service.reject_organization(
        db=db,
        organization_id=request.organization_id,
        rejected_by=current_user.id,
        rejection_reason=request.rejection_reason
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to reject organization"
        )

    return {"message": "Organization rejected successfully"}

@router.get("/users")
async def get_system_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None),
    organization_id: Optional[UUID] = Query(None),
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Get system users with pagination and filtering."""
    return await super_admin_service.get_system_users(
        db=db,
        page=page,
        limit=limit,
        search=search,
        organization_id=organization_id
    )

@router.post("/users/manage")
async def manage_user(
    request: UserManagementAction,
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Perform user management actions."""
    success = await super_admin_service.manage_user(
        db=db,
        user_id=request.user_id,
        action=request.action,
        performed_by=current_user.id,
        details=request.details
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to {request.action} user"
        )

    return {"message": f"User {request.action} completed successfully"}

@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    action_filter: Optional[str] = Query(None),
    user_id: Optional[UUID] = Query(None),
    organization_id: Optional[UUID] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: User = Depends(get_current_super_admin),
    db: AsyncSession = Depends(get_async_db)
):
    """Get audit logs with filtering and pagination."""
    return await super_admin_service.get_audit_logs(
        db=db,
        page=page,
        limit=limit,
        action_filter=action_filter,
        user_id=user_id,
        organization_id=organization_id,
        start_date=start_date,
        end_date=end_date
    )

@router.get("/system/health")
async def get_system_health(
    current_user: User = Depends(get_current_super_admin)
):
    """Get system health status."""
    return monitoring_service.get_health_status()

@router.get("/system/metrics/current")
async def get_current_metrics(
    current_user: User = Depends(get_current_super_admin)
):
    """Get current system metrics."""
    metrics = monitoring_service.get_current_metrics()
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No metrics available"
        )
    return metrics

@router.get("/system/metrics/history")
async def get_metrics_history(
    hours: int = Query(24, ge=1, le=168),  # Max 7 days
    current_user: User = Depends(get_current_super_admin)
):
    """Get system metrics history."""
    return monitoring_service.get_metrics_history(hours=hours)

@router.get("/system/performance")
async def get_performance_summary(
    current_user: User = Depends(get_current_super_admin)
):
    """Get performance summary for the last 24 hours."""
    return monitoring_service.get_performance_summary()

@router.get("/system/alerts")
async def get_system_alerts(
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_super_admin)
):
    """Get recent system alerts."""
    return await monitoring_service.get_recent_alerts(limit=limit)

@router.post("/system/alerts")
async def create_system_alert(
    alert_type: str,
    message: str,
    severity: str = "warning",
    current_user: User = Depends(get_current_super_admin)
):
    """Create a system alert."""
    await monitoring_service.create_alert(alert_type, message, severity)
    return {"message": "Alert created successfully"}

@router.get("/system/prometheus-metrics")
async def get_prometheus_metrics(
    current_user: User = Depends(get_current_super_admin)
):
    """Get Prometheus formatted metrics."""
    from fastapi.responses import Response
    metrics = monitoring_service.get_prometheus_metrics()
    return Response(content=metrics, media_type="text/plain")

@router.post("/init-super-admin")
async def initialize_super_admin(
    db: AsyncSession = Depends(get_async_db)
):
    """Initialize the super admin user (development/setup only)."""
    try:
        user = await super_admin_service.create_super_admin_user(db)
        if user:
            return {
                "message": "Super admin user created successfully",
                "email": user.email
            }
        else:
            return {"message": "Super admin user already exists"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create super admin: {str(e)}"
        )
