"""
Audit and activity logging API routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from datetime import datetime
from app.database import get_async_session
from app.dependencies import get_current_user, get_current_super_admin
from app.models import User
from app.schemas import (
    AuditLogResponse, PaginatedResponse, ActionStatus
)
from app.services.audit_service import AuditService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource: Optional[str] = Query(None, description="Filter by resource"),
    status: Optional[str] = Query(None, description="Filter by status (success/failure)"),
    start_date: Optional[datetime] = Query(None, description="Filter from date"),
    end_date: Optional[datetime] = Query(None, description="Filter to date"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    List audit logs with access control:
    - Super Admin: Can see all audit logs across organizations
    - Organization User: Can only see audit logs for their organization
    """
    audit_service = AuditService(db)

    audit_logs, total = await audit_service.list_audit_logs_with_access_control(
        page=page,
        size=size,
        user_id=user_id,
        organization_id=organization_id if current_user.is_super_admin else None,
        action=action,
        resource=resource,
        status=status,
        start_date=start_date,
        end_date=end_date,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    return PaginatedResponse(
        items=audit_logs,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )


@router.get("/{audit_id}", response_model=AuditLogResponse)
async def get_audit_log(
    audit_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get audit log by ID with access control:
    - Super Admin: Can access any audit log
    - Organization User: Can only access audit logs for their organization
    """
    audit_service = AuditService(db)

    audit_log = await audit_service.get_audit_log_with_access_control(
        audit_id=audit_id,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    if not audit_log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found or access denied"
        )

    return audit_log


@router.get("/stats/summary")
async def get_audit_statistics(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in statistics"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get audit statistics with access control:
    - Super Admin: Can get statistics for any organization or system-wide
    - Organization User: Can only get statistics for their organization
    """
    audit_service = AuditService(db)

    stats = await audit_service.get_audit_statistics_with_access_control(
        days=days,
        organization_id=organization_id if current_user.is_super_admin else None,
        user_org_id=current_user.organization_id,
        is_super_admin=current_user.is_super_admin
    )

    return stats


@router.get("/user/{user_id}/activity")
async def get_user_activity_summary(
    user_id: str,
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get user activity summary with access control:
    - Super Admin: Can see any user's activity
    - Organization User: Can see activity of users in their organization
    - Users can see their own activity
    """
    audit_service = AuditService(db)

    # Users can always see their own activity
    if user_id == current_user.id:
        summary = await audit_service.get_user_activity_summary(user_id, days)
        return summary
    elif current_user.is_super_admin:
        # Super admin can see any user's activity
        summary = await audit_service.get_user_activity_summary(user_id, days)
        return summary
    else:
        # Organization users can only see users in their organization
        from app.services.user_service import UserService
        user_service = UserService(db)
        target_user = await user_service.get_user_with_access_control(
            user_id=user_id,
            user_org_id=current_user.organization_id,
            is_super_admin=current_user.is_super_admin
        )

        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or access denied"
            )

        summary = await audit_service.get_user_activity_summary(user_id, days)
        return summary


@router.get("/organization/{org_id}/activity")
async def get_organization_activity_summary(
    org_id: str,
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get organization activity summary with access control:
    - Super Admin: Can see any organization's activity
    - Organization User: Can only see their own organization's activity
    """
    audit_service = AuditService(db)

    # Check access permissions
    if not current_user.is_super_admin:
        if not current_user.organization_id or current_user.organization_id != org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. You can only view your own organization's activity."
            )

    summary = await audit_service.get_organization_activity_summary(org_id, days)
    return summary


@router.get("/security/events")
async def get_security_events(
    hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
    severity: str = Query("high", regex="^(high|medium|low)$", description="Severity level"),
    organization_id: Optional[str] = Query(None, description="Filter by organization (Super Admin only)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_session)
):
    """
    Get security events with access control:
    - Super Admin: Can see security events across all organizations
    - Organization User: Can only see security events for their organization
    """
    audit_service = AuditService(db)

    # Determine organization filter
    if current_user.is_super_admin:
        filter_org_id = organization_id
    else:
        filter_org_id = current_user.organization_id

    events = await audit_service.get_security_events(
        organization_id=filter_org_id,
        hours=hours,
        severity=severity
    )

    return {
        "security_events": events,
        "count": len(events),
        "hours": hours,
        "severity": severity,
        "organization_id": filter_org_id
    }
