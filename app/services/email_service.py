"""
Email service for sending authentication-related emails.
This module provides comprehensive email functionality for notifications, verification, and alerts.
"""
import asyncio
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
from datetime import datetime
import jinja2
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Comprehensive email service with template support and advanced features."""

    def __init__(self):
        self.template_env = self._setup_template_environment()

    def _setup_template_environment(self) -> jinja2.Environment:
        """Set up Jinja2 template environment."""
        template_dir = Path(__file__).parent.parent / "templates" / "emails"
        template_dir.mkdir(parents=True, exist_ok=True)

        return jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )

    async def send_email(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        sender: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Send an email to one or more recipients.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content of the email
            sender: Sender email address
            attachments: List of attachments

        Returns:
            bool: True if email sent successfully
        """
        if not settings.SMTP_HOST or not settings.SMTP_PORT:
            logger.warning("SMTP settings not configured. Email logged instead.")
            logger.info(f"Email would be sent to: {recipients}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Content: {html_content}")
            return True

        sender = sender or settings.FROM_EMAIL
        if not sender:
            logger.error("Sender email not configured")
            return False

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{settings.FROM_NAME} <{sender}>"
            msg['To'] = ", ".join(recipients)

            # Add text content
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                msg.attach(text_part)

            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)

            # Add attachments
            if attachments:
                for attachment in attachments:
                    self._add_attachment(msg, attachment)

            # Send email
            await self._send_smtp_email(msg, sender, recipients)

            logger.info(f"Email sent successfully to {recipients}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    async def send_verification_email(
        self,
        recipient: str,
        user_name: str,
        verification_token: str,
        organization_name: Optional[str] = None
    ) -> bool:
        """Send email verification email."""
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"

        context = {
            'user_name': user_name,
            'verification_url': verification_url,
            'organization_name': organization_name or 'AuthX',
            'app_name': settings.APP_NAME,
            'support_email': settings.FROM_EMAIL
        }

        try:
            html_content = self.template_env.get_template('verification.html').render(context)
            text_content = self.template_env.get_template('verification.txt').render(context)
        except jinja2.TemplateNotFound:
            # Fallback to basic template
            html_content = self._get_basic_verification_template(context)
            text_content = f"Please verify your email by clicking: {verification_url}"

        return await self.send_email(
            recipients=[recipient],
            subject="Verify your email address",
            html_content=html_content,
            text_content=text_content
        )

    async def send_password_reset_email(
        self,
        recipient: str,
        user_name: str,
        reset_token: str,
        organization_name: Optional[str] = None
    ) -> bool:
        """Send password reset email."""
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"

        context = {
            'user_name': user_name,
            'reset_url': reset_url,
            'organization_name': organization_name or 'AuthX',
            'app_name': settings.APP_NAME,
            'support_email': settings.FROM_EMAIL,
            'expires_in': settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS
        }

        try:
            html_content = self.template_env.get_template('password_reset.html').render(context)
            text_content = self.template_env.get_template('password_reset.txt').render(context)
        except jinja2.TemplateNotFound:
            html_content = self._get_basic_password_reset_template(context)
            text_content = f"Reset your password by clicking: {reset_url}"

        return await self.send_email(
            recipients=[recipient],
            subject="Reset your password",
            html_content=html_content,
            text_content=text_content
        )

    async def send_mfa_code_email(
        self,
        recipient: str,
        user_name: str,
        mfa_code: str
    ) -> bool:
        """Send MFA code via email."""
        context = {
            'user_name': user_name,
            'mfa_code': mfa_code,
            'app_name': settings.APP_NAME,
            'expires_in': settings.MFA_CODE_EXPIRE_MINUTES
        }

        try:
            html_content = self.template_env.get_template('mfa_code.html').render(context)
            text_content = self.template_env.get_template('mfa_code.txt').render(context)
        except jinja2.TemplateNotFound:
            html_content = self._get_basic_mfa_template(context)
            text_content = f"Your verification code is: {mfa_code}"

        return await self.send_email(
            recipients=[recipient],
            subject="Your verification code",
            html_content=html_content,
            text_content=text_content
        )

    async def send_security_alert_email(
        self,
        recipient: str,
        user_name: str,
        alert_type: str,
        alert_details: Dict[str, Any]
    ) -> bool:
        """Send security alert email."""
        context = {
            'user_name': user_name,
            'alert_type': alert_type,
            'alert_details': alert_details,
            'app_name': settings.APP_NAME,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'support_email': settings.FROM_EMAIL
        }

        try:
            html_content = self.template_env.get_template('security_alert.html').render(context)
            text_content = self.template_env.get_template('security_alert.txt').render(context)
        except jinja2.TemplateNotFound:
            html_content = self._get_basic_security_alert_template(context)
            text_content = f"Security Alert: {alert_type} detected on your account."

        return await self.send_email(
            recipients=[recipient],
            subject=f"Security Alert: {alert_type}",
            html_content=html_content,
            text_content=text_content
        )

    async def send_organization_invitation_email(
        self,
        recipient: str,
        inviter_name: str,
        organization_name: str,
        invitation_token: str,
        role: str
    ) -> bool:
        """Send organization invitation email."""
        invitation_url = f"{settings.FRONTEND_URL}/accept-invitation?token={invitation_token}"

        context = {
            'inviter_name': inviter_name,
            'organization_name': organization_name,
            'invitation_url': invitation_url,
            'role': role,
            'app_name': settings.APP_NAME,
            'support_email': settings.FROM_EMAIL
        }

        try:
            html_content = self.template_env.get_template('organization_invitation.html').render(context)
            text_content = self.template_env.get_template('organization_invitation.txt').render(context)
        except jinja2.TemplateNotFound:
            html_content = self._get_basic_invitation_template(context)
            text_content = f"You've been invited to join {organization_name}. Click: {invitation_url}"

        return await self.send_email(
            recipients=[recipient],
            subject=f"Invitation to join {organization_name}",
            html_content=html_content,
            text_content=text_content
        )

    async def _send_smtp_email(self, msg: MIMEMultipart, sender: str, recipients: List[str]):
        """Send email via SMTP."""
        def send_sync():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()

                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

                server.send_message(msg, sender, recipients)

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_sync)

    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]):
        """Add attachment to email message."""
        filename = attachment.get('filename')
        content = attachment.get('content')
        content_type = attachment.get('content_type', 'application/octet-stream')

        if not filename or not content:
            return

        part = MIMEBase(*content_type.split('/'))
        part.set_payload(content)
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {filename}'
        )
        msg.attach(part)

    def _get_basic_verification_template(self, context: Dict[str, Any]) -> str:
        """Basic verification email template."""
        return f"""
        <html>
        <body>
            <h2>Welcome to {context['app_name']}!</h2>
            <p>Hello {context['user_name']},</p>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="{context['verification_url']}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
            <p>If you didn't create this account, you can safely ignore this email.</p>
            <p>Best regards,<br>The {context['app_name']} Team</p>
        </body>
        </html>
        """

    def _get_basic_password_reset_template(self, context: Dict[str, Any]) -> str:
        """Basic password reset email template."""
        return f"""
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {context['user_name']},</p>
            <p>We received a request to reset your password. Click the link below to reset it:</p>
            <p><a href="{context['reset_url']}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>This link will expire in {context['expires_in']} hours.</p>
            <p>If you didn't request this reset, you can safely ignore this email.</p>
            <p>Best regards,<br>The {context['app_name']} Team</p>
        </body>
        </html>
        """

    def _get_basic_mfa_template(self, context: Dict[str, Any]) -> str:
        """Basic MFA code email template."""
        return f"""
        <html>
        <body>
            <h2>Your Verification Code</h2>
            <p>Hello {context['user_name']},</p>
            <p>Your verification code is:</p>
            <p style="font-size: 24px; font-weight: bold; letter-spacing: 3px; text-align: center; background-color: #f8f9fa; padding: 20px; border-radius: 5px;">{context['mfa_code']}</p>
            <p>This code will expire in {context['expires_in']} minutes.</p>
            <p>If you didn't request this code, please contact support immediately.</p>
            <p>Best regards,<br>The {context['app_name']} Team</p>
        </body>
        </html>
        """

    def _get_basic_security_alert_template(self, context: Dict[str, Any]) -> str:
        """Basic security alert email template."""
        return f"""
        <html>
        <body>
            <h2>Security Alert</h2>
            <p>Hello {context['user_name']},</p>
            <p>We detected a security event on your account:</p>
            <p><strong>Alert Type:</strong> {context['alert_type']}</p>
            <p><strong>Time:</strong> {context['timestamp']}</p>
            <p>If this was you, no action is needed. If you don't recognize this activity, please contact support immediately.</p>
            <p>Contact support: {context['support_email']}</p>
            <p>Best regards,<br>The {context['app_name']} Team</p>
        </body>
        </html>
        """

    def _get_basic_invitation_template(self, context: Dict[str, Any]) -> str:
        """Basic organization invitation email template."""
        return f"""
        <html>
        <body>
            <h2>You're Invited!</h2>
            <p>Hello,</p>
            <p>{context['inviter_name']} has invited you to join <strong>{context['organization_name']}</strong> as a {context['role']}.</p>
            <p><a href="{context['invitation_url']}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Accept Invitation</a></p>
            <p>If you don't want to join this organization, you can safely ignore this email.</p>
            <p>Best regards,<br>The {context['app_name']} Team</p>
        </body>
        </html>
        """

# Global email service instance
email_service = EmailService()
