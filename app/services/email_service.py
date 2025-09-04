"""
Enhanced Email Service for AuthX with SMTP support and template rendering.
Provides comprehensive email functionality with async support, templates, and monitoring.
"""
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from dataclasses import dataclass
import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape
import premailer
from markdown import markdown

from app.core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class EmailAttachment:
    """Email attachment data structure."""
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"

@dataclass
class EmailMessage:
    """Email message data structure."""
    to: Union[str, List[str]]
    subject: str
    body: str
    html_body: Optional[str] = None
    cc: Optional[List[str]] = None
    bcc: Optional[List[str]] = None
    attachments: Optional[List[EmailAttachment]] = None
    reply_to: Optional[str] = None
    priority: str = "normal"  # low, normal, high

class EmailService:
    """Enhanced email service with SMTP support and template rendering."""

    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_use_tls = settings.SMTP_USE_TLS
        self.smtp_use_ssl = settings.SMTP_USE_SSL
        self.email_from = settings.EMAIL_FROM
        self.email_from_name = settings.EMAIL_FROM_NAME
        self.templates_dir = settings.EMAIL_TEMPLATES_DIR

        # Initialize Jinja2 environment for template rendering
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        # Email statistics
        self.emails_sent = 0
        self.emails_failed = 0

    async def send_email(self, message: EmailMessage) -> bool:
        """
        Send an email message using SMTP.

        Args:
            message: EmailMessage object containing email details

        Returns:
            True if email was sent successfully, False otherwise
        """
        try:
            # Create MIME message
            mime_message = self._create_mime_message(message)

            # Send email using aiosmtplib for async support
            if self.smtp_use_ssl:
                smtp_client = aiosmtplib.SMTP(
                    hostname=self.smtp_server,
                    port=self.smtp_port,
                    use_tls=False,
                    start_tls=False
                )
            else:
                smtp_client = aiosmtplib.SMTP(
                    hostname=self.smtp_server,
                    port=self.smtp_port,
                    use_tls=self.smtp_use_tls
                )

            await smtp_client.connect()

            if self.smtp_username and self.smtp_password:
                await smtp_client.login(self.smtp_username, self.smtp_password)

            # Send email
            await smtp_client.send_message(mime_message)
            await smtp_client.quit()

            self.emails_sent += 1
            logger.info(f"Email sent successfully to {message.to}")
            return True

        except Exception as e:
            self.emails_failed += 1
            logger.error(f"Failed to send email to {message.to}: {str(e)}")
            return False

    async def send_template_email(
        self,
        template_name: str,
        to: Union[str, List[str]],
        subject: str,
        context: Dict[str, Any],
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        attachments: Optional[List[EmailAttachment]] = None
    ) -> bool:
        """
        Send an email using a template.

        Args:
            template_name: Name of the template file (without extension)
            to: Recipient email address(es)
            subject: Email subject
            context: Template context variables
            cc: CC recipients
            bcc: BCC recipients
            attachments: Email attachments

        Returns:
            True if email was sent successfully, False otherwise
        """
        try:
            # Render template
            html_content = await self._render_template(f"{template_name}.html", context)

            # Try to render text version
            try:
                text_content = await self._render_template(f"{template_name}.txt", context)
            except Exception:
                # Fallback: convert HTML to text
                text_content = self._html_to_text(html_content)

            # Create email message
            message = EmailMessage(
                to=to,
                subject=subject,
                body=text_content,
                html_body=html_content,
                cc=cc,
                bcc=bcc,
                attachments=attachments
            )

            return await self.send_email(message)

        except Exception as e:
            logger.error(f"Failed to send template email '{template_name}' to {to}: {str(e)}")
            return False

    async def send_welcome_email(self, user_email: str, user_name: str, verification_url: str) -> bool:
        """Send welcome email to new user."""
        context = {
            'user_name': user_name,
            'verification_url': verification_url,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="welcome",
            to=user_email,
            subject=f"Welcome to {settings.PROJECT_NAME}!",
            context=context
        )

    async def send_password_reset_email(
        self,
        user_email: str,
        user_name: str,
        reset_url: str
    ) -> bool:
        """Send password reset email."""
        context = {
            'user_name': user_name,
            'reset_url': reset_url,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="password_reset",
            to=user_email,
            subject="Password Reset Request",
            context=context
        )

    async def send_organization_approval_email(
        self,
        admin_email: str,
        admin_name: str,
        organization_name: str,
        approval_url: str
    ) -> bool:
        """Send organization approval email to super admin."""
        context = {
            'admin_name': admin_name,
            'organization_name': organization_name,
            'approval_url': approval_url,
            'company_name': settings.PROJECT_NAME
        }

        return await self.send_template_email(
            template_name="organization_approval",
            to=admin_email,
            subject=f"New Organization Registration: {organization_name}",
            context=context
        )

    async def send_organization_welcome_email(
        self,
        admin_email: str,
        admin_name: str,
        organization_name: str,
        login_url: str
    ) -> bool:
        """Send welcome email to organization admin."""
        context = {
            'admin_name': admin_name,
            'organization_name': organization_name,
            'login_url': login_url,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="organization_welcome",
            to=admin_email,
            subject=f"Welcome to {settings.PROJECT_NAME} - Organization Setup Complete",
            context=context
        )

    async def send_security_alert_email(
        self,
        user_email: str,
        user_name: str,
        alert_type: str,
        details: Dict[str, Any]
    ) -> bool:
        """Send security alert email."""
        context = {
            'user_name': user_name,
            'alert_type': alert_type,
            'details': details,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="security_alert",
            to=user_email,
            subject=f"Security Alert - {alert_type}",
            context=context
        )

    async def send_bulk_email(
        self,
        recipients: List[str],
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        batch_size: int = 50
    ) -> Dict[str, int]:
        """
        Send bulk emails in batches.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            template_name: Template name
            context: Template context
            batch_size: Number of emails to send per batch

        Returns:
            Dictionary with success and failure counts
        """
        results = {"sent": 0, "failed": 0}

        # Process in batches
        for i in range(0, len(recipients), batch_size):
            batch = recipients[i:i + batch_size]

            # Send emails concurrently within batch
            tasks = []
            for recipient in batch:
                task = self.send_template_email(
                    template_name=template_name,
                    to=recipient,
                    subject=subject,
                    context=context
                )
                tasks.append(task)

            # Wait for batch completion
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count results
            for result in batch_results:
                if isinstance(result, Exception):
                    results["failed"] += 1
                elif result:
                    results["sent"] += 1
                else:
                    results["failed"] += 1

            # Small delay between batches to avoid overwhelming SMTP server
            await asyncio.sleep(1)

        logger.info(f"Bulk email completed: {results['sent']} sent, {results['failed']} failed")
        return results

    def _create_mime_message(self, message: EmailMessage) -> MIMEMultipart:
        """Create MIME message from EmailMessage object."""
        mime_message = MIMEMultipart('alternative')

        # Set headers
        mime_message['From'] = f"{self.email_from_name} <{self.email_from}>"
        mime_message['To'] = message.to if isinstance(message.to, str) else ', '.join(message.to)
        mime_message['Subject'] = message.subject

        if message.cc:
            mime_message['Cc'] = ', '.join(message.cc)

        if message.reply_to:
            mime_message['Reply-To'] = message.reply_to

        # Set priority
        if message.priority == "high":
            mime_message['X-Priority'] = '1'
            mime_message['X-MSMail-Priority'] = 'High'
        elif message.priority == "low":
            mime_message['X-Priority'] = '5'
            mime_message['X-MSMail-Priority'] = 'Low'

        # Add text part
        if message.body:
            text_part = MIMEText(message.body, 'plain', 'utf-8')
            mime_message.attach(text_part)

        # Add HTML part
        if message.html_body:
            # Inline CSS using premailer
            inlined_html = premailer.transform(message.html_body)
            html_part = MIMEText(inlined_html, 'html', 'utf-8')
            mime_message.attach(html_part)

        # Add attachments
        if message.attachments:
            for attachment in message.attachments:
                self._add_attachment(mime_message, attachment)

        return mime_message

    def _add_attachment(self, mime_message: MIMEMultipart, attachment: EmailAttachment):
        """Add attachment to MIME message."""
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.content)
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {attachment.filename}'
        )
        mime_message.attach(part)

    async def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render Jinja2 template."""
        try:
            template = self.jinja_env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render template '{template_name}': {str(e)}")
            raise

    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text()
        except ImportError:
            # Fallback: simple HTML tag removal
            import re
            clean = re.compile('<.*?>')
            return re.sub(clean, '', html_content)

    def get_email_stats(self) -> Dict[str, int]:
        """Get email statistics."""
        return {
            "emails_sent": self.emails_sent,
            "emails_failed": self.emails_failed,
            "success_rate": (
                self.emails_sent / (self.emails_sent + self.emails_failed) * 100
                if (self.emails_sent + self.emails_failed) > 0 else 0
            )
        }

# Global service instance
email_service = EmailService()
