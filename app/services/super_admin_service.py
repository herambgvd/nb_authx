"""
Super Admin Service for AuthX.
Handles organization onboarding, super admin operations, and system-wide management.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, update
from sqlalchemy.orm import selectinload

from app.models.user import User
from app.models.organization import Organization
from app.models.role import Role
from app.models.audit import AuditLog
from app.schemas.admin import (
    SuperAdminDashboard, OrganizationApprovalRequest,
    SystemStats, UserManagementAction
)
from app.services.email_service import email_service
from app.services.monitoring_service import monitoring_service
from app.utils.security import get_password_hash
from app.core.config import settings

logger = logging.getLogger(__name__)

class SuperAdminService:
    """Super admin service for system-wide management."""

    async def get_dashboard_stats(self, db: AsyncSession) -> SuperAdminDashboard:
        """Get super admin dashboard statistics."""
        try:
            # Organization statistics
            total_orgs = await db.scalar(select(func.count(Organization.id)))
            pending_orgs = await db.scalar(
                select(func.count(Organization.id)).where(Organization.is_active == False)
            )
            active_orgs = await db.scalar(
                select(func.count(Organization.id)).where(Organization.is_active == True)
            )

            # User statistics
            total_users = await db.scalar(select(func.count(User.id)))
            active_users = await db.scalar(
                select(func.count(User.id)).where(User.is_active == True)
            )

            # Recent registrations (last 30 days)
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_users = await db.scalar(
                select(func.count(User.id)).where(User.created_at >= thirty_days_ago)
            )
            recent_orgs = await db.scalar(
                select(func.count(Organization.id)).where(Organization.created_at >= thirty_days_ago)
            )

            # System health
            health_status = monitoring_service.get_health_status()
            current_metrics = monitoring_service.get_current_metrics()

            # Recent audit logs
            recent_audits = await db.execute(
                select(AuditLog)
                .order_by(AuditLog.created_at.desc())
                .limit(10)
            )
            recent_audit_logs = recent_audits.scalars().all()

            return SuperAdminDashboard(
                organization_stats={
                    "total": total_orgs or 0,
                    "active": active_orgs or 0,
                    "pending": pending_orgs or 0,
                    "recent": recent_orgs or 0
                },
                user_stats={
                    "total": total_users or 0,
                    "active": active_users or 0,
                    "recent": recent_users or 0
                },
                system_health=health_status,
                current_metrics=current_metrics,
                recent_audit_logs=[
                    {
                        "id": str(log.id),
                        "action": log.action,
                        "user_id": str(log.user_id) if log.user_id else None,
                        "organization_id": str(log.organization_id) if log.organization_id else None,
                        "timestamp": log.created_at,
                        "ip_address": log.ip_address
                    }
                    for log in recent_audit_logs
                ]
            )

        except Exception as e:
            logger.error(f"Error getting dashboard stats: {str(e)}")
            raise

    async def get_pending_organizations(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get organizations pending approval."""
        try:
            result = await db.execute(
                select(Organization)
                .where(Organization.is_active == False)
                .options(selectinload(Organization.users))
                .order_by(Organization.created_at.desc())
            )
            organizations = result.scalars().all()

            pending_orgs = []
            for org in organizations:
                # Get the admin user for this organization
                admin_user = next((user for user in org.users if user.is_organization_admin), None)

                pending_orgs.append({
                    "id": str(org.id),
                    "name": org.name,
                    "slug": org.slug,
                    "description": org.description,
                    "email": org.email,
                    "phone": org.phone,
                    "website": org.website,
                    "address": {
                        "line1": org.address_line1,
                        "line2": org.address_line2,
                        "city": org.city,
                        "state": org.state,
                        "postal_code": org.postal_code,
                        "country": org.country
                    },
                    "subscription_tier": org.subscription_tier,
                    "created_at": org.created_at,
                    "admin_user": {
                        "id": str(admin_user.id),
                        "email": admin_user.email,
                        "first_name": admin_user.first_name,
                        "last_name": admin_user.last_name,
                        "phone": admin_user.phone
                    } if admin_user else None
                })

            return pending_orgs

        except Exception as e:
            logger.error(f"Error getting pending organizations: {str(e)}")
            raise

    async def approve_organization(
        self,
        db: AsyncSession,
        organization_id: UUID,
        approved_by: UUID,
        approval_notes: Optional[str] = None
    ) -> bool:
        """Approve an organization registration."""
        try:
            # Get organization
            result = await db.execute(
                select(Organization)
                .where(Organization.id == organization_id)
                .options(selectinload(Organization.users))
            )
            organization = result.scalar_one_or_none()

            if not organization:
                raise ValueError("Organization not found")

            if organization.is_active:
                raise ValueError("Organization is already approved")

            # Activate organization
            organization.is_active = True
            organization.updated_at = datetime.utcnow()

            # Activate admin user
            admin_user = next((user for user in organization.users if user.is_organization_admin), None)
            if admin_user:
                admin_user.is_active = True
                admin_user.email_verified = True
                admin_user.updated_at = datetime.utcnow()

            # Create audit log
            audit_log = AuditLog(
                action="organization_approved",
                user_id=approved_by,
                organization_id=organization_id,
                details={
                    "organization_name": organization.name,
                    "approval_notes": approval_notes
                }
            )
            db.add(audit_log)

            await db.commit()

            # Send welcome email to organization admin
            if admin_user:
                await email_service.send_organization_welcome_email(
                    admin_email=admin_user.email,
                    admin_name=f"{admin_user.first_name} {admin_user.last_name}",
                    organization_name=organization.name,
                    login_url=f"{settings.FRONTEND_URL}/login" if hasattr(settings, 'FRONTEND_URL') else "#"
                )

            logger.info(f"Organization {organization.name} approved by user {approved_by}")
            return True

        except Exception as e:
            await db.rollback()
            logger.error(f"Error approving organization {organization_id}: {str(e)}")
            raise

    async def reject_organization(
        self,
        db: AsyncSession,
        organization_id: UUID,
        rejected_by: UUID,
        rejection_reason: str
    ) -> bool:
        """Reject an organization registration."""
        try:
            # Get organization
            result = await db.execute(
                select(Organization)
                .where(Organization.id == organization_id)
                .options(selectinload(Organization.users))
            )
            organization = result.scalar_one_or_none()

            if not organization:
                raise ValueError("Organization not found")

            # Get admin user email before deletion
            admin_user = next((user for user in organization.users if user.is_organization_admin), None)
            admin_email = admin_user.email if admin_user else None
            admin_name = f"{admin_user.first_name} {admin_user.last_name}" if admin_user else "Admin"

            # Create audit log before deletion
            audit_log = AuditLog(
                action="organization_rejected",
                user_id=rejected_by,
                organization_id=organization_id,
                details={
                    "organization_name": organization.name,
                    "rejection_reason": rejection_reason
                }
            )
            db.add(audit_log)

            # Delete organization and associated users
            await db.delete(organization)
            await db.commit()

            # Send rejection email
            if admin_email:
                await email_service.send_template_email(
                    template_name="organization_rejection",
                    to=admin_email,
                    subject="Organization Registration Update",
                    context={
                        "admin_name": admin_name,
                        "organization_name": organization.name,
                        "rejection_reason": rejection_reason,
                        "company_name": settings.PROJECT_NAME,
                        "support_email": settings.EMAIL_FROM
                    }
                )

            logger.info(f"Organization {organization.name} rejected by user {rejected_by}")
            return True

        except Exception as e:
            await db.rollback()
            logger.error(f"Error rejecting organization {organization_id}: {str(e)}")
            raise

    async def get_system_users(
        self,
        db: AsyncSession,
        page: int = 1,
        limit: int = 50,
        search: Optional[str] = None,
        organization_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Get system users with pagination and filtering."""
        try:
            offset = (page - 1) * limit

            # Build query
            query = select(User).options(selectinload(User.organization))

            # Add filters
            if search:
                search_term = f"%{search}%"
                query = query.where(
                    or_(
                        User.email.ilike(search_term),
                        User.first_name.ilike(search_term),
                        User.last_name.ilike(search_term)
                    )
                )

            if organization_id:
                query = query.where(User.organization_id == organization_id)

            # Get total count
            count_query = select(func.count(User.id))
            if search:
                search_term = f"%{search}%"
                count_query = count_query.where(
                    or_(
                        User.email.ilike(search_term),
                        User.first_name.ilike(search_term),
                        User.last_name.ilike(search_term)
                    )
                )
            if organization_id:
                count_query = count_query.where(User.organization_id == organization_id)

            total_count = await db.scalar(count_query) or 0

            # Get users
            result = await db.execute(
                query.order_by(User.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            users = result.scalars().all()

            user_list = []
            for user in users:
                user_list.append({
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "phone": user.phone,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "is_super_admin": user.is_superuser,
                    "is_organization_admin": user.is_organization_admin,
                    "last_login": user.last_login,
                    "created_at": user.created_at,
                    "organization": {
                        "id": str(user.organization.id),
                        "name": user.organization.name,
                        "slug": user.organization.slug
                    } if user.organization else None
                })

            return {
                "users": user_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                }
            }

        except Exception as e:
            logger.error(f"Error getting system users: {str(e)}")
            raise

    async def manage_user(
        self,
        db: AsyncSession,
        user_id: UUID,
        action: str,
        performed_by: UUID,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Perform user management actions."""
        try:
            # Get user
            result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()

            if not user:
                raise ValueError("User not found")

            # Perform action
            if action == "activate":
                user.is_active = True
            elif action == "deactivate":
                user.is_active = False
            elif action == "verify_email":
                user.email_verified = True
            elif action == "reset_password":
                # Generate temporary password
                temp_password = "TempPass123!"  # In production, generate random password
                user.password_hash = get_password_hash(temp_password)
                user.password_reset_required = True
                details = details or {}
                details["temp_password"] = temp_password
            elif action == "make_super_admin":
                user.is_superuser = True
            elif action == "remove_super_admin":
                user.is_superuser = False
            else:
                raise ValueError(f"Invalid action: {action}")

            user.updated_at = datetime.utcnow()

            # Create audit log
            audit_log = AuditLog(
                action=f"user_{action}",
                user_id=performed_by,
                target_user_id=user_id,
                organization_id=user.organization_id,
                details=details or {}
            )
            db.add(audit_log)

            await db.commit()

            # Send notification email
            if action in ["activate", "deactivate", "reset_password"]:
                await self._send_user_management_email(user, action, details)

            logger.info(f"User {user.email} {action} performed by {performed_by}")
            return True

        except Exception as e:
            await db.rollback()
            logger.error(f"Error managing user {user_id}: {str(e)}")
            raise

    async def _send_user_management_email(
        self,
        user: User,
        action: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Send email notification for user management actions."""
        try:
            context = {
                "user_name": f"{user.first_name} {user.last_name}",
                "action": action,
                "company_name": settings.PROJECT_NAME,
                "support_email": settings.EMAIL_FROM
            }

            if details:
                context.update(details)

            template_map = {
                "activate": "user_activated",
                "deactivate": "user_deactivated",
                "reset_password": "password_reset_admin"
            }

            template_name = template_map.get(action)
            if template_name:
                await email_service.send_template_email(
                    template_name=template_name,
                    to=user.email,
                    subject=f"Account {action.title()} - {settings.PROJECT_NAME}",
                    context=context
                )

        except Exception as e:
            logger.error(f"Error sending user management email: {str(e)}")

    async def get_audit_logs(
        self,
        db: AsyncSession,
        page: int = 1,
        limit: int = 50,
        action_filter: Optional[str] = None,
        user_id: Optional[UUID] = None,
        organization_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get audit logs with filtering and pagination."""
        try:
            offset = (page - 1) * limit

            # Build query
            query = select(AuditLog).options(
                selectinload(AuditLog.user),
                selectinload(AuditLog.organization)
            )

            # Add filters
            filters = []
            if action_filter:
                filters.append(AuditLog.action.ilike(f"%{action_filter}%"))
            if user_id:
                filters.append(AuditLog.user_id == user_id)
            if organization_id:
                filters.append(AuditLog.organization_id == organization_id)
            if start_date:
                filters.append(AuditLog.created_at >= start_date)
            if end_date:
                filters.append(AuditLog.created_at <= end_date)

            if filters:
                query = query.where(and_(*filters))

            # Get total count
            count_query = select(func.count(AuditLog.id))
            if filters:
                count_query = count_query.where(and_(*filters))

            total_count = await db.scalar(count_query) or 0

            # Get audit logs
            result = await db.execute(
                query.order_by(AuditLog.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            audit_logs = result.scalars().all()

            log_list = []
            for log in audit_logs:
                log_list.append({
                    "id": str(log.id),
                    "action": log.action,
                    "timestamp": log.created_at,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "details": log.details,
                    "user": {
                        "id": str(log.user.id),
                        "email": log.user.email,
                        "name": f"{log.user.first_name} {log.user.last_name}"
                    } if log.user else None,
                    "organization": {
                        "id": str(log.organization.id),
                        "name": log.organization.name
                    } if log.organization else None
                })

            return {
                "audit_logs": log_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                }
            }

        except Exception as e:
            logger.error(f"Error getting audit logs: {str(e)}")
            raise

    async def create_super_admin_user(self, db: AsyncSession) -> Optional[User]:
        """Create the initial super admin user if it doesn't exist."""
        try:
            # Check if super admin already exists
            result = await db.execute(
                select(User).where(User.is_superuser == True)
            )
            if result.scalar_one_or_none():
                logger.info("Super admin user already exists")
                return None

            # Create super admin user
            super_admin = User(
                email=settings.SUPER_ADMIN_EMAIL,
                username="superadmin",
                hashed_password=get_password_hash(settings.SUPER_ADMIN_PASSWORD),
                first_name="Super",
                last_name="Admin",
                is_active=True,
                is_superuser=True,
                is_verified=True
            )

            db.add(super_admin)
            await db.commit()
            await db.refresh(super_admin)

            logger.info(f"Super admin user created successfully: {super_admin.email}")
            return super_admin

        except Exception as e:
            logger.error(f"Error creating super admin user: {e}")
            await db.rollback()
            raise

# Global service instance
super_admin_service = SuperAdminService()
