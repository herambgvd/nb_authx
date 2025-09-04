"""
Email service for sending authentication-related emails.
This module provides comprehensive email functionality for notifications, verification, and alerts.
"""
import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Comprehensive email service with template support and advanced features."""

    def __init__(self):
        pass

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
        This is a placeholder implementation - integrate with your email provider.
        """
        try:
            # Log email sending (in production, integrate with SMTP/email service)
            logger.info(f"Sending email to {recipients}: {subject}")

            # Simulate email sending
            await asyncio.sleep(0.1)

            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    async def send_verification_email(
        self,
        email: str,
        name: str,
        verification_token: str
    ) -> bool:
        """Send email verification email."""
        subject = "Verify Your Email Address"
        html_content = f"""
        <h2>Welcome {name}!</h2>
        <p>Please click the link below to verify your email address:</p>
        <a href="{settings.FRONTEND_URL}/verify-email?token={verification_token}">Verify Email</a>
        <p>If you didn't create this account, please ignore this email.</p>
        """

        return await self.send_email([email], subject, html_content)

    async def send_password_reset_email(
        self,
        email: str,
        name: str,
        reset_token: str
    ) -> bool:
        """Send password reset email."""
        subject = "Reset Your Password"
        html_content = f"""
        <h2>Password Reset Request</h2>
        <p>Hi {name},</p>
        <p>Click the link below to reset your password:</p>
        <a href="{settings.FRONTEND_URL}/reset-password?token={reset_token}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this reset, please ignore this email.</p>
        """

        return await self.send_email([email], subject, html_content)

    async def send_security_alert_email(
        self,
        email: str,
        name: str,
        alert_type: str,
        details: Dict[str, Any]
    ) -> bool:
        """Send security alert email."""
        subject = f"Security Alert: {alert_type}"
        html_content = f"""
        <h2>Security Alert</h2>
        <p>Hi {name},</p>
        <p>We detected a security event on your account:</p>
        <ul>
        <li><strong>Event:</strong> {alert_type}</li>
        <li><strong>Time:</strong> {details.get('timestamp', 'Unknown')}</li>
        <li><strong>IP Address:</strong> {details.get('ip_address', 'Unknown')}</li>
        <li><strong>Location:</strong> {details.get('location', 'Unknown')}</li>
        </ul>
        <p>If this was not you, please change your password immediately.</p>
        """

        return await self.send_email([email], subject, html_content)

# Create a singleton instance
email_service = EmailService()
