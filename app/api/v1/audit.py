"""
Audit and logging API endpoints for the AuthX service.
This module provides API endpoints for audit, security event monitoring, and compliance reporting.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timedelta
import json
import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func

from app.api.deps import get_current_user, get_db, get_organization_admin, get_current_superadmin
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    log_data: AuditLogCreate
):
    """
    Create a new audit log entry.
    This endpoint is typically called internally by the system when actions are performed.
    """
    # Set organization_id from current user if not provided
    if not log_data.organization_id:
        log_data.organization_id = current_user.organization_id

    # Set user information if not provided
    if not log_data.user_id and current_user:
        log_data.user_id = current_user.id
        log_data.user_email = current_user.email

    # Create audit log
    new_log = AuditLog(**log_data.dict())
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log

@router.get("/logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[UUID] = None,
    user_email: Optional[str] = None,
    event_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Get a paginated list of audit logs with optional filtering.
    Organization admins can view audit logs for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view audit logs for this organization"
        )

    # Build query
    query = db.query(AuditLog).filter(AuditLog.organization_id == organization_id)

    # Apply filters
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)

    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    if user_email:
        query = query.filter(AuditLog.user_email.ilike(f"%{user_email}%"))

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)

    if action:
        query = query.filter(AuditLog.action == action)

    if status:
        query = query.filter(AuditLog.status == status)

    # Order by creation date, newest first
    query = query.order_by(desc(AuditLog.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    logs = query.offset(skip).limit(limit).all()

    return {
        "items": logs,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.post("/logs/search", response_model=AuditLogListResponse)
async def search_audit_logs(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    search_data: AuditLogFilterRequest,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    organization_id: Optional[UUID] = None
):
    """
    Advanced search for audit logs with complex filtering.
    Organization admins can search audit logs for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to search audit logs for this organization"
        )

    # Build query
    query = db.query(AuditLog).filter(AuditLog.organization_id == organization_id)

    # Apply filters
    if search_data.start_date:
        query = query.filter(AuditLog.created_at >= search_data.start_date)

    if search_data.end_date:
        query = query.filter(AuditLog.created_at <= search_data.end_date)

    if search_data.user_id:
        query = query.filter(AuditLog.user_id == search_data.user_id)

    if search_data.user_email:
        query = query.filter(AuditLog.user_email.ilike(f"%{search_data.user_email}%"))

    if search_data.event_types:
        query = query.filter(AuditLog.event_type.in_(search_data.event_types))

    if search_data.resource_types:
        query = query.filter(AuditLog.resource_type.in_(search_data.resource_types))

    if search_data.resource_id:
        query = query.filter(AuditLog.resource_id == search_data.resource_id)

    if search_data.actions:
        query = query.filter(AuditLog.action.in_(search_data.actions))

    if search_data.status:
        query = query.filter(AuditLog.status == search_data.status)

    if search_data.ip_address:
        query = query.filter(AuditLog.ip_address == search_data.ip_address)

    if search_data.source:
        query = query.filter(AuditLog.source == search_data.source)

    # Order by creation date, newest first
    query = query.order_by(desc(AuditLog.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    logs = query.offset(skip).limit(limit).all()

    return {
        "items": logs,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/logs/export", status_code=status.HTTP_200_OK)
async def export_audit_logs(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: Optional[UUID] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    format: str = Query("csv", regex="^(csv|json)$")
):
    """
    Export audit logs to CSV or JSON.
    Organization admins can export audit logs for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export audit logs for this organization"
        )

    # Build query
    query = db.query(AuditLog).filter(AuditLog.organization_id == organization_id)

    # Apply filters
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)

    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)

    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    # Order by creation date, newest first
    query = query.order_by(desc(AuditLog.created_at))

    # Get logs (limit to a reasonable number)
    logs = query.limit(10000).all()

    # Export to requested format
    if format == "csv":
        output = io.StringIO()
        fieldnames = ["id", "created_at", "user_id", "user_email", "ip_address",
                     "event_type", "resource_type", "resource_id", "action",
                     "description", "status", "source"]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for log in logs:
            writer.writerow({
                "id": str(log.id),
                "created_at": log.created_at.isoformat() if log.created_at else "",
                "user_id": str(log.user_id) if log.user_id else "",
                "user_email": log.user_email or "",
                "ip_address": log.ip_address or "",
                "event_type": log.event_type,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id or "",
                "action": log.action,
                "description": log.description or "",
                "status": log.status,
                "source": log.source or ""
            })

        # Generate filename
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_logs_{now}.csv"

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    elif format == "json":
        # Convert logs to JSON
        logs_data = []
        for log in logs:
            log_dict = {
                "id": str(log.id),
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "user_id": str(log.user_id) if log.user_id else None,
                "user_email": log.user_email,
                "ip_address": log.ip_address,
                "event_type": log.event_type,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "action": log.action,
                "description": log.description,
                "status": log.status,
                "details": log.details,
                "source": log.source,
                "session_id": log.session_id,
                "request_id": log.request_id,
                "organization_id": str(log.organization_id)
            }
            logs_data.append(log_dict)

        # Generate filename
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_logs_{now}.json"

        return StreamingResponse(
            iter([json.dumps(logs_data, default=str)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

# Security Event Endpoints
@router.post("/security-events", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
async def create_security_event(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    event_data: SecurityEventCreate,
    background_tasks: BackgroundTasks
):
    """
    Create a new security event.
    This endpoint is typically called internally by the system when security-related events are detected.
    """
    # Set organization_id from current user if not provided
    if not event_data.organization_id:
        event_data.organization_id = current_user.organization_id

    # Create security event
    new_event = SecurityEvent(**event_data.dict())
    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    # Check if alerts should be sent for this event
    if new_event.severity in ["high", "critical"]:
        # In a real implementation, this would send alerts to configured recipients
        # based on the organization's alert settings
        # background_tasks.add_task(
        #     send_security_alert,
        #     new_event.id,
        #     new_event.event_type,
        #     new_event.severity,
        #     new_event.description,
        #     new_event.organization_id
        # )

        # Mark as alert sent
        new_event.alert_sent = True
        db.commit()
        db.refresh(new_event)

    return new_event

@router.get("/security-events", response_model=SecurityEventListResponse)
async def get_security_events(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Get a paginated list of security events with optional filtering.
    Organization admins can view security events for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view security events for this organization"
        )

    # Build query
    query = db.query(SecurityEvent).filter(SecurityEvent.organization_id == organization_id)

    # Apply filters
    if start_date:
        query = query.filter(SecurityEvent.created_at >= start_date)

    if end_date:
        query = query.filter(SecurityEvent.created_at <= end_date)

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    if severity:
        query = query.filter(SecurityEvent.severity == severity)

    if status:
        query = query.filter(SecurityEvent.status == status)

    # Order by creation date, newest first
    query = query.order_by(desc(SecurityEvent.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    events = query.offset(skip).limit(limit).all()

    return {
        "items": events,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.post("/security-events/search", response_model=SecurityEventListResponse)
async def search_security_events(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    search_data: SecurityEventFilterRequest,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    organization_id: Optional[UUID] = None
):
    """
    Advanced search for security events with complex filtering.
    Organization admins can search security events for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to search security events for this organization"
        )

    # Build query
    query = db.query(SecurityEvent).filter(SecurityEvent.organization_id == organization_id)

    # Apply filters
    if search_data.start_date:
        query = query.filter(SecurityEvent.created_at >= search_data.start_date)

    if search_data.end_date:
        query = query.filter(SecurityEvent.created_at <= search_data.end_date)

    if search_data.event_types:
        query = query.filter(SecurityEvent.event_type.in_(search_data.event_types))

    if search_data.severities:
        query = query.filter(SecurityEvent.severity.in_(search_data.severities))

    if search_data.user_id:
        query = query.filter(SecurityEvent.user_id == search_data.user_id)

    if search_data.ip_address:
        query = query.filter(SecurityEvent.ip_address == search_data.ip_address)

    if search_data.status:
        query = query.filter(SecurityEvent.status == search_data.status)

    # Order by creation date, newest first
    query = query.order_by(desc(SecurityEvent.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    events = query.offset(skip).limit(limit).all()

    return {
        "items": events,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.patch("/security-events/{event_id}", response_model=SecurityEventResponse)
async def update_security_event(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    event_id: UUID,
    event_data: SecurityEventUpdate
):
    """
    Update a security event's details.
    Organization admins can update security events within their organization.
    """
    # Get security event
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found"
        )

    # Check if user has permission to update this event
    if current_user.organization_id != event.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this security event"
        )

    # Update event
    update_data = event_data.dict(exclude_unset=True)

    # If status is changing to "resolved", update resolved_by and resolved_at
    if "status" in update_data and update_data["status"] == "resolved" and event.status != "resolved":
        update_data["resolved_by"] = current_user.id
        update_data["resolved_at"] = datetime.utcnow()

    for key, value in update_data.items():
        setattr(event, key, value)

    db.commit()
    db.refresh(event)

    return event

@router.post("/security-events/{event_id}/resolve", response_model=SecurityEventResponse)
async def resolve_security_event(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    event_id: UUID,
    resolution: str = Body(..., embed=True)
):
    """
    Resolve a security event.
    Organization admins can resolve security events within their organization.
    """
    # Get security event
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found"
        )

    # Check if user has permission to update this event
    if current_user.organization_id != event.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to resolve this security event"
        )

    # Update event
    event.status = "resolved"
    event.resolution = resolution
    event.resolved_by = current_user.id
    event.resolved_at = datetime.utcnow()

    db.commit()
    db.refresh(event)

    return event

# Compliance Report Endpoints
@router.post("/compliance/reports", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
async def create_compliance_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    report_data: ComplianceReportCreate,
    background_tasks: BackgroundTasks
):
    """
    Create a new compliance report.
    Organization admins can create compliance reports for their organization.
    """
    # Set organization_id from current user if not provided
    if not report_data.organization_id:
        report_data.organization_id = current_user.organization_id

    # Check if user has access to the organization
    if current_user.organization_id != report_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create compliance reports for this organization"
        )

    # Create compliance report
    new_report = ComplianceReport(
        **report_data.dict(),
        generated_by=current_user.id,
        status="generating"
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    # Generate the report in the background
    # background_tasks.add_task(
    #     generate_compliance_report,
    #     new_report.id,
    #     new_report.report_type,
    #     new_report.parameters,
    #     new_report.organization_id
    # )

    return new_report

@router.get("/compliance/reports", response_model=ComplianceReportListResponse)
async def get_compliance_reports(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    report_type: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Get a paginated list of compliance reports with optional filtering.
    Organization admins can view compliance reports for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view compliance reports for this organization"
        )

    # Build query
    query = db.query(ComplianceReport).filter(ComplianceReport.organization_id == organization_id)

    # Apply filters
    if report_type:
        query = query.filter(ComplianceReport.report_type == report_type)

    if status:
        query = query.filter(ComplianceReport.status == status)

    # Order by creation date, newest first
    query = query.order_by(desc(ComplianceReport.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    reports = query.offset(skip).limit(limit).all()

    return {
        "items": reports,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/compliance/reports/{report_id}", response_model=ComplianceReportResponse)
async def get_compliance_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    report_id: UUID
):
    """
    Get detailed information about a specific compliance report by ID.
    Users can only view compliance reports within their organization unless they are superadmins.
    """
    # Get compliance report
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance report not found"
        )

    # Check if user has permission to view this report
    if current_user.organization_id != report.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this compliance report"
        )

    return report

@router.get("/compliance/reports/{report_id}/download")
async def download_compliance_report(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    report_id: UUID
):
    """
    Download a compliance report file.
    Users can only download compliance reports within their organization unless they are superadmins.
    """
    # Get compliance report
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compliance report not found"
        )

    # Check if user has permission to download this report
    if current_user.organization_id != report.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to download this compliance report"
        )

    # Check if report is ready
    if report.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report is not ready for download (status: {report.status})"
        )

    # Check if file path exists
    if not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report file is not available"
        )

    # In a real implementation, this would serve the actual file
    # For this example, we'll generate a mock response

    # Generate mock report data based on report type
    if report.report_type == "user_activity":
        data = [
            {"user": "user1@example.com", "events": 25, "last_activity": "2023-01-01T12:00:00Z"},
            {"user": "user2@example.com", "events": 15, "last_activity": "2023-01-02T10:30:00Z"}
        ]
    elif report.report_type == "security_events":
        data = [
            {"event_type": "login_failure", "count": 12, "severity": "medium"},
            {"event_type": "suspicious_activity", "count": 5, "severity": "high"}
        ]
    else:
        data = [{"message": "Sample report data"}]

    # Return JSON data
    return data

# Forensic Capabilities
@router.post("/forensics/snapshots", response_model=ForensicSnapshotResponse, status_code=status.HTTP_201_CREATED)
async def create_forensic_snapshot(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    snapshot_data: ForensicSnapshotCreate
):
    """
    Create a new forensic snapshot.
    Organization admins can create forensic snapshots for resources within their organization.
    """
    # Set organization_id from current user if not provided
    if not snapshot_data.organization_id:
        snapshot_data.organization_id = current_user.organization_id

    # Check if user has access to the organization
    if current_user.organization_id != snapshot_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create forensic snapshots for this organization"
        )

    # Fetch the resource data based on resource type and ID
    resource_data = {}

    if snapshot_data.resource_type == "user":
        user = db.query(User).filter(
            User.id == UUID(snapshot_data.resource_id),
            User.organization_id == snapshot_data.organization_id
        ).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or belongs to a different organization"
            )

        # Collect user data for the snapshot
        resource_data = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "status": user.status,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "roles": [{"id": str(ur.role_id), "name": ur.role.name if ur.role else None} for ur in user.roles],
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None
        }

    # Add other resource types as needed

    # Create forensic snapshot
    new_snapshot = ForensicSnapshot(
        **snapshot_data.dict(),
        created_by=current_user.id,
        data=resource_data
    )
    db.add(new_snapshot)
    db.commit()
    db.refresh(new_snapshot)

    return new_snapshot

@router.get("/forensics/snapshots", response_model=ForensicSnapshotListResponse)
async def get_forensic_snapshots(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    snapshot_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None
):
    """
    Get a paginated list of forensic snapshots with optional filtering.
    Organization admins can view forensic snapshots for their organization.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view forensic snapshots for this organization"
        )

    # Build query
    query = db.query(ForensicSnapshot).filter(ForensicSnapshot.organization_id == organization_id)

    # Apply filters
    if snapshot_type:
        query = query.filter(ForensicSnapshot.snapshot_type == snapshot_type)

    if resource_type:
        query = query.filter(ForensicSnapshot.resource_type == resource_type)

    if resource_id:
        query = query.filter(ForensicSnapshot.resource_id == resource_id)

    # Order by creation date, newest first
    query = query.order_by(desc(ForensicSnapshot.created_at))

    # Get total count
    total = query.count()

    # Apply pagination
    snapshots = query.offset(skip).limit(limit).all()

    return {
        "items": snapshots,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/forensics/snapshots/{snapshot_id}", response_model=ForensicSnapshotResponse)
async def get_forensic_snapshot(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    snapshot_id: UUID
):
    """
    Get detailed information about a specific forensic snapshot by ID.
    Users can only view forensic snapshots within their organization unless they are superadmins.
    """
    # Get forensic snapshot
    snapshot = db.query(ForensicSnapshot).filter(ForensicSnapshot.id == snapshot_id).first()

    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Forensic snapshot not found"
        )

    # Check if user has permission to view this snapshot
    if current_user.organization_id != snapshot.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this forensic snapshot"
        )

    return snapshot

# Real-time Alerting
@router.post("/alerts/config", response_model=AlertConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_config(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    config_data: AlertConfigCreate
):
    """
    Create a new alert configuration.
    Organization admins can create alert configurations for their organization.
    """
    # In a real implementation, this would create an alert configuration in the database
    # For this example, we'll return a mock response

    return {
        "id": UUID("550e8400-e29b-41d4-a716-446655440000"),  # Mock ID
        "event_types": config_data.event_types,
        "severity_threshold": config_data.severity_threshold,
        "recipients": config_data.recipients,
        "enabled": config_data.enabled,
        "organization_id": config_data.organization_id or current_user.organization_id,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

@router.post("/alerts/trigger", status_code=status.HTTP_204_NO_CONTENT)
async def trigger_alert(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    alert_data: AlertTriggerRequest
):
    """
    Manually trigger an alert.
    Organization admins can trigger alerts for their organization.
    """
    # In a real implementation, this would send the alert to the specified recipients
    # For this example, we'll just acknowledge the request

    return None
