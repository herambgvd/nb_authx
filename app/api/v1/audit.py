"""
Audit and logging API endpoints for the AuthX service.
This module provides API endpoints for audit, security event monitoring, and compliance reporting.
"""
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timedelta
import json
import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func

from app.api.deps import get_current_user, get_async_db, get_organization_admin, get_current_superuser
from app.models.user import User
from app.models.audit import AuditLog, SecurityEvent, ComplianceReport, ForensicSnapshot
from app.schemas.audit import (
    AuditLogCreate,
    AuditLogResponse,
    AuditLogListResponse,
    AuditLogFilterRequest,
    SecurityEventCreate,
    SecurityEventUpdate,
    SecurityEventResponse,
    SecurityEventListResponse,
    SecurityEventFilterRequest,
    ComplianceReportCreate,
    ComplianceReportResponse,
    ComplianceReportListResponse,
    ForensicSnapshotCreate,
    ForensicSnapshotResponse,
    ForensicSnapshotListResponse,
    AlertConfigCreate,
    AlertConfigResponse,
    AlertTriggerRequest
)

router = APIRouter()

# Audit Log Endpoints
@router.post("/logs", response_model=AuditLogResponse, status_code=status.HTTP_201_CREATED)
async def create_audit_log(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    log_data: AuditLogCreate
):
    """
    Create a new audit log entry.
    """
    # Set user and organization info
    log_data.user_id = current_user.id
    log_data.organization_id = current_user.organization_id

    # Create new audit log
    new_log = AuditLog(**log_data.dict())
    db.add(new_log)
    await db.commit()
    await db.refresh(new_log)

    return new_log

@router.get("/logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[UUID] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    risk_level: Optional[str] = None
):
    """
    Get audit logs with filtering and pagination.
    Users can only see logs from their organization unless they are superusers.
    """
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
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)
    if risk_level:
        query = query.where(AuditLog.risk_level == risk_level)

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply ordering and pagination
    query = query.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return AuditLogListResponse(
        logs=[AuditLogResponse.from_orm(log) for log in logs],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.get("/logs/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    log_id: UUID
):
    """Get audit log by ID."""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != log.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    return log

# Security Event Endpoints
@router.post("/security-events", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
async def create_security_event(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    event_data: SecurityEventCreate
):
    """
    Create a new security event.
    """
    # Set organization info
    event_data.organization_id = current_user.organization_id

    # Create new security event
    new_event = SecurityEvent(**event_data.dict())
    db.add(new_event)
    await db.commit()
    await db.refresh(new_event)

    return new_event

@router.get("/security-events", response_model=SecurityEventListResponse)
async def get_security_events(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    """
    Get security events with filtering and pagination.
    Users can only see events from their organization unless they are superusers.
    """
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
    if status:
        query = query.where(SecurityEvent.status == status)
    if start_date:
        query = query.where(SecurityEvent.timestamp >= start_date)
    if end_date:
        query = query.where(SecurityEvent.timestamp <= end_date)

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply ordering and pagination
    query = query.order_by(desc(SecurityEvent.timestamp)).offset(skip).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()

    return SecurityEventListResponse(
        events=[SecurityEventResponse.from_orm(event) for event in events],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.put("/security-events/{event_id}", response_model=SecurityEventResponse)
async def update_security_event(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    event_id: UUID,
    event_data: SecurityEventUpdate
):
    """Update security event information."""
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != event.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Update event with provided data
    update_data = event_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(event, key, value)

    await db.commit()
    await db.refresh(event)

    return event

# Compliance Report Endpoints
@router.post("/compliance-reports", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
async def create_compliance_report(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_organization_admin),
    report_data: ComplianceReportCreate,
    background_tasks: BackgroundTasks
):
    """
    Create a new compliance report.
    Organization admins can create compliance reports for their organization.
    """
    # Set organization info
    report_data.organization_id = current_user.organization_id
    report_data.requested_by = current_user.id

    # Create new compliance report
    new_report = ComplianceReport(**report_data.dict())
    db.add(new_report)
    await db.commit()
    await db.refresh(new_report)

    # Generate report in background
    background_tasks.add_task(generate_compliance_report, new_report.id)

    return new_report

@router.get("/compliance-reports", response_model=ComplianceReportListResponse)
async def get_compliance_reports(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    report_type: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Get compliance reports with filtering and pagination.
    Users can only see reports from their organization unless they are superusers.
    """
    # Build query based on user permissions
    if current_user.is_superuser:
        query = select(ComplianceReport)
    else:
        query = select(ComplianceReport).where(ComplianceReport.organization_id == current_user.organization_id)

    # Apply filters
    if report_type:
        query = query.where(ComplianceReport.report_type == report_type)
    if status:
        query = query.where(ComplianceReport.status == status)

    # Get total count
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_result.scalar()

    # Apply ordering and pagination
    query = query.order_by(desc(ComplianceReport.created_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()

    return ComplianceReportListResponse(
        reports=[ComplianceReportResponse.from_orm(report) for report in reports],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
        has_next=skip + limit < total,
        has_prev=skip > 0
    )

@router.get("/compliance-reports/{report_id}/download")
async def download_compliance_report(
    *,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    report_id: UUID,
    format: str = Query("pdf", regex="^(pdf|csv|json)$")
):
    """
    Download a compliance report in the specified format.
    """
    result = await db.execute(select(ComplianceReport).where(ComplianceReport.id == report_id))
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance report not found"
        )

    # Check access permissions
    if not current_user.is_superuser and current_user.organization_id != report.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    if report.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report is not ready for download"
        )

    # Generate download content based on format
    if format == "csv":
        content = generate_csv_content(report)
        media_type = "text/csv"
        filename = f"compliance_report_{report_id}.csv"
    elif format == "json":
        content = json.dumps(report.report_data, indent=2)
        media_type = "application/json"
        filename = f"compliance_report_{report_id}.json"
    else:  # pdf
        content = generate_pdf_content(report)
        media_type = "application/pdf"
        filename = f"compliance_report_{report_id}.pdf"

    return StreamingResponse(
        io.BytesIO(content.encode() if isinstance(content, str) else content),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# Helper functions
async def generate_compliance_report(report_id: UUID):
    """Generate compliance report data in background."""
    # This would implement the actual report generation logic
    pass

def generate_csv_content(report: ComplianceReport) -> str:
    """Generate CSV content for compliance report."""
    # This would implement CSV generation logic
    return "placeholder,csv,content"

def generate_pdf_content(report: ComplianceReport) -> bytes:
    """Generate PDF content for compliance report."""
    # This would implement PDF generation logic
    return b"placeholder pdf content"
