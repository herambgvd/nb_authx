"""
Enhanced Email Service for AuthX with multiple provider support.
Supports Gmail (development), AWS SES, Mailgun, SendGrid with fallback mechanisms.
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
import httpx
from enum import Enum

from app.core.config import settings

logger = logging.getLogger(__name__)

class EmailProvider(Enum):
    """Email service providers."""
    SMTP = "smtp"  # Generic SMTP (Gmail, etc.)
    AWS_SES = "aws_ses"
    MAILGUN = "mailgun"
    SENDGRID = "sendgrid"

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
    """Enhanced email service with multiple provider support and fallback mechanisms."""

    def __init__(self):
        # SMTP Configuration
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_use_tls = settings.SMTP_USE_TLS
        self.smtp_use_ssl = settings.SMTP_USE_SSL
        self.email_from = settings.EMAIL_FROM
        self.email_from_name = settings.EMAIL_FROM_NAME
        self.templates_dir = settings.EMAIL_TEMPLATES_DIR

        # Third-party service configurations
        self.mailgun_api_key = getattr(settings, 'MAILGUN_API_KEY', None)
        self.mailgun_domain = getattr(settings, 'MAILGUN_DOMAIN', None)
        self.mailgun_base_url = getattr(settings, 'MAILGUN_BASE_URL', 'https://api.mailgun.net/v3')

        self.sendgrid_api_key = getattr(settings, 'SENDGRID_API_KEY', None)

        # Determine primary provider based on configuration
        self.primary_provider = self._determine_primary_provider()

        # Initialize Jinja2 environment for template rendering
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        # Email statistics
        self.emails_sent = 0
        self.emails_failed = 0
        self.provider_stats = {provider.value: {"sent": 0, "failed": 0} for provider in EmailProvider}

    def _determine_primary_provider(self) -> EmailProvider:
        """Determine the primary email provider based on configuration."""
        if self.sendgrid_api_key:
            return EmailProvider.SENDGRID
        elif self.mailgun_api_key and self.mailgun_domain:
            return EmailProvider.MAILGUN
        elif (settings.ENVIRONMENT == "production" and
              "amazonaws.com" in self.smtp_server):
            return EmailProvider.AWS_SES
        else:
            return EmailProvider.SMTP

    async def send_email(self, message: EmailMessage) -> bool:
        """
        Send an email using the configured provider with fallback support.

        Args:
            message: EmailMessage object containing email details

        Returns:
            True if email was sent successfully, False otherwise
        """
        providers_to_try = [self.primary_provider]

        # Add fallback providers
        if self.primary_provider != EmailProvider.SMTP:
            providers_to_try.append(EmailProvider.SMTP)

        for provider in providers_to_try:
            try:
                success = await self._send_with_provider(message, provider)
                if success:
                    self.emails_sent += 1
                    self.provider_stats[provider.value]["sent"] += 1
                    logger.info(f"Email sent successfully to {message.to} using {provider.value}")
                    return True
            except Exception as e:
                self.provider_stats[provider.value]["failed"] += 1
                logger.warning(f"Failed to send email with {provider.value}: {str(e)}")
                continue

        self.emails_failed += 1
        logger.error(f"Failed to send email to {message.to} with all providers")
        return False

    async def _send_with_provider(self, message: EmailMessage, provider: EmailProvider) -> bool:
        """Send email using specific provider."""
        if provider == EmailProvider.SMTP:
            return await self._send_with_smtp(message)
        elif provider == EmailProvider.MAILGUN:
            return await self._send_with_mailgun(message)
        elif provider == EmailProvider.SENDGRID:
            return await self._send_with_sendgrid(message)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    async def _send_with_smtp(self, message: EmailMessage) -> bool:
        """Send email using SMTP (Gmail, AWS SES, etc.)."""
        try:
            # Create MIME message
            mime_message = self._create_mime_message(message)

            # Configure SMTP client
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

            return True

        except Exception as e:
            logger.error(f"SMTP send failed: {str(e)}")
            raise

    async def _send_with_mailgun(self, message: EmailMessage) -> bool:
        """Send email using Mailgun API."""
        if not self.mailgun_api_key or not self.mailgun_domain:
            raise ValueError("Mailgun credentials not configured")

        try:
            url = f"{self.mailgun_base_url}/{self.mailgun_domain}/messages"

            # Prepare recipients
            to_list = message.to if isinstance(message.to, list) else [message.to]

            data = {
                "from": f"{self.email_from_name} <{self.email_from}>",
                "to": to_list,
                "subject": message.subject,
                "text": message.body,
            }

            if message.html_body:
                data["html"] = message.html_body

            if message.cc:
                data["cc"] = message.cc

            if message.bcc:
                data["bcc"] = message.bcc

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    auth=("api", self.mailgun_api_key),
                    data=data,
                    timeout=30.0
                )
                response.raise_for_status()

            return True

        except Exception as e:
            logger.error(f"Mailgun send failed: {str(e)}")
            raise

    async def _send_with_sendgrid(self, message: EmailMessage) -> bool:
        """Send email using SendGrid API."""
        if not self.sendgrid_api_key:
            raise ValueError("SendGrid API key not configured")

        try:
            url = "https://api.sendgrid.com/v3/mail/send"

            # Prepare recipients
            to_list = message.to if isinstance(message.to, list) else [message.to]
            personalizations = [{
                "to": [{"email": email} for email in to_list],
                "subject": message.subject
            }]

            if message.cc:
                personalizations[0]["cc"] = [{"email": email} for email in message.cc]

            if message.bcc:
                personalizations[0]["bcc"] = [{"email": email} for email in message.bcc]

            payload = {
                "personalizations": personalizations,
                "from": {
                    "email": self.email_from,
                    "name": self.email_from_name
                },
                "content": [
                    {
                        "type": "text/plain",
                        "value": message.body
                    }
                ]
            }

            if message.html_body:
                payload["content"].append({
                    "type": "text/html",
                    "value": message.html_body
                })

            headers = {
                "Authorization": f"Bearer {self.sendgrid_api_key}",
                "Content-Type": "application/json"
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()

            return True

        except Exception as e:
            logger.error(f"SendGrid send failed: {str(e)}")
            raise

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

    async def send_verification_email(
        self,
        user_email: str,
        user_name: str,
        verification_url: str
    ) -> bool:
        """Send email verification email."""
        context = {
            'user_name': user_name,
            'verification_url': verification_url,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="email_verification",
            to=user_email,
            subject="Verify Your Email Address",
            context=context
        )

    async def send_security_alert_email(
        self,
        user_email: str,
        user_name: str,
        alert_message: str,
        alert_type: str = "security"
    ) -> bool:
        """Send security alert email."""
        context = {
            'user_name': user_name,
            'alert_message': alert_message,
            'alert_type': alert_type,
            'company_name': settings.PROJECT_NAME,
            'support_email': self.email_from
        }

        return await self.send_template_email(
            template_name="security_alert",
            to=user_email,
            subject=f"Security Alert - {settings.PROJECT_NAME}",
            context=context
        )

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on email service."""
        status = {
            "status": "healthy",
            "provider": self.primary_provider.value,
            "stats": self.get_email_stats(),
            "provider_stats": self.provider_stats
        }

        # Test connection for SMTP
        if self.primary_provider == EmailProvider.SMTP:
            try:
                smtp_client = aiosmtplib.SMTP(
                    hostname=self.smtp_server,
                    port=self.smtp_port,
                    use_tls=self.smtp_use_tls
                )
                await smtp_client.connect()
                await smtp_client.quit()
                status["smtp_connection"] = "ok"
            except Exception as e:
                status["status"] = "unhealthy"
                status["smtp_connection"] = f"failed: {str(e)}"

        return status

# Global service instance
email_service = EmailService()
