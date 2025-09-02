"""
Email service for sending authentication-related emails.
This module provides functions for sending verification emails, password reset emails, and MFA codes.
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Service for sending emails."""

    @staticmethod
    async def send_email(
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        sender: Optional[str] = None
    ) -> bool:
        """
        Send an email to one or more recipients.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content of the email (optional)
            sender: Sender email address (optional, uses EMAILS_FROM_EMAIL from settings if not provided)

        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        if not settings.SMTP_HOST or not settings.SMTP_PORT:
            logger.warning("SMTP settings not configured. Email not sent.")
            # In development, log the email instead
            logger.info(f"Email would be sent to: {recipients}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Content: {html_content}")
            return True

        # Use default sender if not provided
        sender = sender or settings.EMAILS_FROM_EMAIL
        if not sender:
            logger.error("Sender email not configured")
            return False

        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{settings.EMAILS_FROM_NAME} <{sender}>" if settings.EMAILS_FROM_NAME else sender
        message["To"] = ", ".join(recipients)

        # Add text content if provided
        if text_content:
            message.attach(MIMEText(text_content, "plain"))

        # Add HTML content
        message.attach(MIMEText(html_content, "html"))

        try:
            # Connect to SMTP server
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()

                # Login if credentials are provided
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

                # Send email
                server.sendmail(sender, recipients, message.as_string())

            logger.info(f"Email sent successfully to {recipients}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

    @staticmethod
    async def send_verification_email(email: str, token: str) -> bool:
        """
        Send an email verification link.

        Args:
            email: Recipient's email address
            token: Verification token

        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Create verification URL
        # In a real production environment, this would be a frontend URL
        verification_url = f"{settings.API_V1_PREFIX}/auth/verify-email?token={token}"

        # Create email content
        subject = "Verify your email address"
        html_content = f"""
        <html>
            <body>
                <h1>Verify your email address</h1>
                <p>Thank you for registering with AuthX. Please click the link below to verify your email address:</p>
                <p><a href="{verification_url}">Verify Email</a></p>
                <p>Or copy and paste this token in the verification page:</p>
                <p><strong>{token}</strong></p>
                <p>This link will expire in 3 days.</p>
                <p>If you did not request this verification, please ignore this email.</p>
            </body>
        </html>
        """

        text_content = f"""
        Verify your email address

        Thank you for registering with AuthX. Please visit the following link to verify your email address:
        
        {verification_url}
        
        Or copy and paste this token in the verification page:
        {token}
        
        This link will expire in 3 days.
        
        If you did not request this verification, please ignore this email.
        """

        return await EmailService.send_email([email], subject, html_content, text_content)

    @staticmethod
    async def send_password_reset_email(email: str, token: str) -> bool:
        """
        Send a password reset link.

        Args:
            email: Recipient's email address
            token: Password reset token

        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Create reset URL
        # In a real production environment, this would be a frontend URL
        reset_url = f"{settings.API_V1_PREFIX}/auth/reset-password?token={token}"

        # Create email content
        subject = "Reset your password"
        html_content = f"""
        <html>
            <body>
                <h1>Reset your password</h1>
                <p>You have requested to reset your password. Please click the link below to reset your password:</p>
                <p><a href="{reset_url}">Reset Password</a></p>
                <p>Or copy and paste this token in the password reset page:</p>
                <p><strong>{token}</strong></p>
                <p>This link will expire in 24 hours.</p>
                <p>If you did not request this password reset, please ignore this email.</p>
            </body>
        </html>
        """

        text_content = f"""
        Reset your password

        You have requested to reset your password. Please visit the following link to reset your password:
        
        {reset_url}
        
        Or copy and paste this token in the password reset page:
        {token}
        
        This link will expire in 24 hours.
        
        If you did not request this password reset, please ignore this email.
        """

        return await EmailService.send_email([email], subject, html_content, text_content)

    @staticmethod
    async def send_mfa_code_email(email: str, code: str) -> bool:
        """
        Send an MFA verification code via email.

        Args:
            email: Recipient's email address
            code: MFA verification code

        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        # Create email content
        subject = "Your Authentication Code"
        html_content = f"""
        <html>
            <body>
                <h1>Your Authentication Code</h1>
                <p>You have requested an authentication code. Please use the following code to complete your login:</p>
                <p style="font-size: 24px; font-weight: bold;">{code}</p>
                <p>This code will expire in 5 minutes.</p>
                <p>If you did not request this code, please ignore this email and secure your account.</p>
            </body>
        </html>
        """

        text_content = f"""
        Your Authentication Code

        You have requested an authentication code. Please use the following code to complete your login:
        
        {code}
        
        This code will expire in 5 minutes.
        
        If you did not request this code, please ignore this email and secure your account.
        """

        return await EmailService.send_email([email], subject, html_content, text_content)
