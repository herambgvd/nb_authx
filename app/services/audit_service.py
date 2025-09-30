"""
Audit and logging service layer
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc
from sqlalchemy.orm import selectinload
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timedelta
from app.models import AuditLog, User, Organization
from app.schemas import AuditLogResponse, ActionStatus
from fastapi import HTTPException, status
import logging
import json

logger = logging.getLogger(__name__)


class AuditService:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_audit_log(
        self,
        action: str,
        resource: str,
        status: ActionStatus,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """Create a new audit log entry"""

        audit_log = AuditLog(
            user_id=user_id,
            organization_id=organization_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps(details) if details else None,
            status=status.value
        )

        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)

        return audit_log

    async def get_audit_logs(
        self,
        organization_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        status: Optional[ActionStatus] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        size: int = 50
    ) -> Tuple[List[AuditLog], int]:
        """Get audit logs with filtering"""

        # Build query
        stmt = select(AuditLog).options(
            selectinload(AuditLog.user),
            selectinload(AuditLog.organization)
        )

        # Apply filters
        if organization_id:
            stmt = stmt.where(AuditLog.organization_id == organization_id)

        if user_id:
            stmt = stmt.where(AuditLog.user_id == user_id)

        if action:
            stmt = stmt.where(AuditLog.action == action)

        if resource:
            stmt = stmt.where(AuditLog.resource == resource)

        if status:
            stmt = stmt.where(AuditLog.status == status.value)

        if start_date:
            stmt = stmt.where(AuditLog.created_at >= start_date)

        if end_date:
            stmt = stmt.where(AuditLog.created_at <= end_date)

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination and ordering
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(desc(AuditLog.created_at))

        result = await self.db.execute(stmt)
        audit_logs = result.scalars().all()

        return list(audit_logs), total

    async def get_user_activity_summary(
        self,
        user_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get user activity summary for the last N days"""

        start_date = datetime.utcnow() - timedelta(days=days)

        # Get total activities
        total_stmt = select(func.count()).where(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.created_at >= start_date
            )
        )
        total_result = await self.db.execute(total_stmt)
        total_activities = total_result.scalar()

        # Get activities by action
        action_stmt = select(
            AuditLog.action,
            func.count().label('count')
        ).where(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.created_at >= start_date
            )
        ).group_by(AuditLog.action).order_by(desc(func.count()))

        action_result = await self.db.execute(action_stmt)
        activities_by_action = {row.action: row.count for row in action_result.fetchall()}

        # Get activities by status
        status_stmt = select(
            AuditLog.status,
            func.count().label('count')
        ).where(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.created_at >= start_date
            )
        ).group_by(AuditLog.status)

        status_result = await self.db.execute(status_stmt)
        activities_by_status = {row.status: row.count for row in status_result.fetchall()}

        # Get last login
        last_login_stmt = select(AuditLog.created_at).where(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.action == 'login_success'
            )
        ).order_by(desc(AuditLog.created_at)).limit(1)

        last_login_result = await self.db.execute(last_login_stmt)
        last_login = last_login_result.scalar_one_or_none()

        return {
            "user_id": user_id,
            "period_days": days,
            "total_activities": total_activities,
            "activities_by_action": activities_by_action,
            "activities_by_status": activities_by_status,
            "last_login": last_login.isoformat() if last_login else None
        }

    async def get_organization_activity_summary(
        self,
        organization_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get organization activity summary for the last N days"""

        start_date = datetime.utcnow() - timedelta(days=days)

        # Get total activities
        total_stmt = select(func.count()).where(
            and_(
                AuditLog.organization_id == organization_id,
                AuditLog.created_at >= start_date
            )
        )
        total_result = await self.db.execute(total_stmt)
        total_activities = total_result.scalar()

        # Get unique active users
        active_users_stmt = select(func.count(func.distinct(AuditLog.user_id))).where(
            and_(
                AuditLog.organization_id == organization_id,
                AuditLog.created_at >= start_date,
                AuditLog.user_id.isnot(None)
            )
        )
        active_users_result = await self.db.execute(active_users_stmt)
        active_users = active_users_result.scalar()

        # Get activities by resource
        resource_stmt = select(
            AuditLog.resource,
            func.count().label('count')
        ).where(
            and_(
                AuditLog.organization_id == organization_id,
                AuditLog.created_at >= start_date
            )
        ).group_by(AuditLog.resource).order_by(desc(func.count()))

        resource_result = await self.db.execute(resource_stmt)
        activities_by_resource = {row.resource: row.count for row in resource_result.fetchall()}

        # Get failed activities
        failed_stmt = select(func.count()).where(
            and_(
                AuditLog.organization_id == organization_id,
                AuditLog.created_at >= start_date,
                AuditLog.status == 'failure'
            )
        )
        failed_result = await self.db.execute(failed_stmt)
        failed_activities = failed_result.scalar()

        return {
            "organization_id": organization_id,
            "period_days": days,
            "total_activities": total_activities,
            "active_users": active_users,
            "activities_by_resource": activities_by_resource,
            "failed_activities": failed_activities,
            "success_rate": round(((total_activities - failed_activities) / total_activities * 100), 2) if total_activities > 0 else 0
        }

    async def get_security_events(
        self,
        organization_id: Optional[str] = None,
        hours: int = 24,
        severity: str = "high"
    ) -> List[AuditLog]:
        """Get security-related events"""

        start_date = datetime.utcnow() - timedelta(hours=hours)

        # Define security-related actions
        security_actions = [
            'login_failed',
            'password_reset_requested',
            'password_reset_completed',
            'account_locked',
            'user_deleted',
            'role_deleted',
            'organization_deleted',
            'permission_assigned'
        ]

        stmt = select(AuditLog).where(
            and_(
                AuditLog.created_at >= start_date,
                AuditLog.action.in_(security_actions)
            )
        )

        if organization_id:
            stmt = stmt.where(AuditLog.organization_id == organization_id)

        # Filter by severity
        if severity == "high":
            high_severity_actions = ['login_failed', 'account_locked', 'user_deleted', 'organization_deleted']
            stmt = stmt.where(AuditLog.action.in_(high_severity_actions))
        elif severity == "medium":
            medium_severity_actions = ['password_reset_requested', 'role_deleted', 'permission_assigned']
            stmt = stmt.where(AuditLog.action.in_(medium_severity_actions))

        stmt = stmt.order_by(desc(AuditLog.created_at))

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def cleanup_old_logs(self, days_to_keep: int = 365) -> int:
        """Clean up audit logs older than specified days"""

        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Count logs to be deleted
        count_stmt = select(func.count()).where(AuditLog.created_at < cutoff_date)
        count_result = await self.db.execute(count_stmt)
        logs_to_delete = count_result.scalar()

        # Delete old logs
        from sqlalchemy import delete
        delete_stmt = delete(AuditLog).where(AuditLog.created_at < cutoff_date)
        await self.db.execute(delete_stmt)
        await self.db.commit()

        logger.info(f"Cleaned up {logs_to_delete} audit logs older than {days_to_keep} days")
        return logs_to_delete

    async def list_audit_logs_with_access_control(
        self,
        page: int = 1,
        size: int = 20,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Tuple[List[AuditLog], int]:
        """List audit logs with access control"""

        # Super admin can see all audit logs
        if is_super_admin:
            stmt = select(AuditLog).options(
                selectinload(AuditLog.user),
                selectinload(AuditLog.organization)
            )

            # Apply filters
            if organization_id:
                stmt = stmt.where(AuditLog.organization_id == organization_id)
            if user_id:
                stmt = stmt.where(AuditLog.user_id == user_id)
            if action:
                stmt = stmt.where(AuditLog.action == action)
            if resource:
                stmt = stmt.where(AuditLog.resource == resource)
            if status:
                stmt = stmt.where(AuditLog.status == status)
            if start_date:
                stmt = stmt.where(AuditLog.created_at >= start_date)
            if end_date:
                stmt = stmt.where(AuditLog.created_at <= end_date)

        # Organization users can only see audit logs for their organization
        elif user_org_id:
            stmt = select(AuditLog).options(
                selectinload(AuditLog.user),
                selectinload(AuditLog.organization)
            ).where(AuditLog.organization_id == user_org_id)

            # Apply additional filters
            if user_id:
                stmt = stmt.where(AuditLog.user_id == user_id)
            if action:
                stmt = stmt.where(AuditLog.action == action)
            if resource:
                stmt = stmt.where(AuditLog.resource == resource)
            if status:
                stmt = stmt.where(AuditLog.status == status)
            if start_date:
                stmt = stmt.where(AuditLog.created_at >= start_date)
            if end_date:
                stmt = stmt.where(AuditLog.created_at <= end_date)

        # No access
        else:
            return [], 0

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Apply pagination and ordering
        offset = (page - 1) * size
        stmt = stmt.offset(offset).limit(size).order_by(desc(AuditLog.created_at))

        result = await self.db.execute(stmt)
        audit_logs = result.scalars().all()

        return list(audit_logs), total

    async def get_audit_log_with_access_control(
        self,
        audit_id: str,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Optional[AuditLog]:
        """Get audit log with access control"""

        stmt = select(AuditLog).options(
            selectinload(AuditLog.user),
            selectinload(AuditLog.organization)
        ).where(AuditLog.id == audit_id)

        result = await self.db.execute(stmt)
        audit_log = result.scalar_one_or_none()

        if not audit_log:
            return None

        # Super admin can access any audit log
        if is_super_admin:
            return audit_log

        # Organization users can only access audit logs for their organization
        if user_org_id and audit_log.organization_id == user_org_id:
            return audit_log

        # No access
        return None

    async def get_audit_statistics_with_access_control(
        self,
        days: int = 30,
        organization_id: Optional[str] = None,
        user_org_id: Optional[str] = None,
        is_super_admin: bool = False
    ) -> Dict[str, Any]:
        """Get audit statistics with access control"""

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Base query
        base_stmt = select(AuditLog).where(
            and_(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date
            )
        )

        # Apply access control
        if is_super_admin:
            if organization_id:
                base_stmt = base_stmt.where(AuditLog.organization_id == organization_id)
        elif user_org_id:
            base_stmt = base_stmt.where(AuditLog.organization_id == user_org_id)
        else:
            # No access
            return {
                "total_events": 0,
                "success_events": 0,
                "failure_events": 0,
                "top_actions": [],
                "top_resources": [],
                "daily_counts": [],
                "period_days": days
            }

        # Get total counts
        total_stmt = select(func.count()).select_from(base_stmt.subquery())
        total_result = await self.db.execute(total_stmt)
        total_events = total_result.scalar()

        # Get success counts
        success_stmt = select(func.count()).select_from(
            base_stmt.where(AuditLog.status == "success").subquery()
        )
        success_result = await self.db.execute(success_stmt)
        success_events = success_result.scalar()

        # Get failure counts
        failure_stmt = select(func.count()).select_from(
            base_stmt.where(AuditLog.status == "failure").subquery()
        )
        failure_result = await self.db.execute(failure_stmt)
        failure_events = failure_result.scalar()

        # Get top actions
        top_actions_stmt = select(
            AuditLog.action,
            func.count(AuditLog.action).label('count')
        ).select_from(base_stmt.subquery()).group_by(
            AuditLog.action
        ).order_by(desc('count')).limit(10)

        top_actions_result = await self.db.execute(top_actions_stmt)
        top_actions = [
            {"action": row.action, "count": row.count}
            for row in top_actions_result
        ]

        # Get top resources
        top_resources_stmt = select(
            AuditLog.resource,
            func.count(AuditLog.resource).label('count')
        ).select_from(base_stmt.subquery()).group_by(
            AuditLog.resource
        ).order_by(desc('count')).limit(10)

        top_resources_result = await self.db.execute(top_resources_stmt)
        top_resources = [
            {"resource": row.resource, "count": row.count}
            for row in top_resources_result
        ]

        return {
            "total_events": total_events,
            "success_events": success_events,
            "failure_events": failure_events,
            "top_actions": top_actions,
            "top_resources": top_resources,
            "period_days": days
        }
