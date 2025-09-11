"""
Audit and logging API endpoints for the AuthX service.
This module provides API endpoints for audit, security event monitoring, and compliance reporting.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.api.deps import get_current_active_user
from app.db.session import get_async_db
from app.models.user import User
from app.models.audit import AuditLog, SecurityEvent

router = APIRouter()

@router.get("/logs", response_model=list)
async def get_audit_logs(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[UUID] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    """
    Get audit logs with filtering and pagination.
    Users can only see logs from their organization unless they are superusers.
    """
    try:
        # Build query based on user permissions
        if current_user.is_superuser:
            query = select(AuditLog)
        else:
            query = select(AuditLog).where(AuditLog.organization_id == current_user.organization_id)

        # Apply filters
        if action:
            query = query.where(AuditLog.action.ilike(f"%{action}%"))
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)

        # Add ordering and pagination
        query = query.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        logs = result.scalars().all()

        # Convert to simple dict format to avoid serialization issues
        return [
            {
                "id": str(log.id),
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "event_type": log.event_type,
                "resource_type": log.resource_type,
                "action": log.action,
                "user_id": str(log.user_id) if log.user_id else None,
                "organization_id": str(log.organization_id) if log.organization_id else None,
                "description": log.description,
                "status": log.status
            }
            for log in logs
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve audit logs: {str(e)}"
        )

@router.get("/security-events", response_model=list)
async def get_security_events(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_active_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    """
    Get security events with filtering and pagination.
    Users can only see events from their organization unless they are superusers.
    """
    try:
        # Build query based on user permissions
        if current_user.is_superuser:
            query = select(SecurityEvent)
        else:
            query = select(SecurityEvent).where(SecurityEvent.organization_id == current_user.organization_id)

        # Apply filters
        if event_type:
            query = query.where(SecurityEvent.event_type == event_type)
        if severity:
            query = query.where(SecurityEvent.severity == severity)
        if status_filter:
            query = query.where(SecurityEvent.status == status_filter)
        if start_date:
            query = query.where(SecurityEvent.created_at >= start_date)
        if end_date:
            query = query.where(SecurityEvent.created_at <= end_date)

        # Apply ordering and pagination
        query = query.order_by(desc(SecurityEvent.created_at)).offset(skip).limit(limit)
        result = await db.execute(query)
        events = result.scalars().all()

        # Convert to simple dict format to avoid serialization issues
        return [
            {
                "id": str(event.id),
                "timestamp": event.created_at.isoformat() if event.created_at else None,
                "event_type": event.event_type,
                "severity": event.severity,
                "status": event.status,
                "description": event.description,
                "user_id": str(event.user_id) if event.user_id else None,
                "organization_id": str(event.organization_id) if event.organization_id else None,
                "ip_address": event.ip_address
            }
            for event in events
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve security events: {str(e)}"
        )
