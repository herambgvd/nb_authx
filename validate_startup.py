"""
AuthX Startup Validation Script
Validates configuration and system health before starting the application.
"""
import logging
import sys
from typing import Dict, Any

from app.core.config import settings

logger = logging.getLogger(__name__)

def validate_startup() -> Dict[str, Any]:
    """
    Validate system configuration and dependencies before startup.

    Returns:
        Validation results with status and issues
    """
    print("🔍 AuthX Startup Validation")
    print("=" * 50)

    validation_result = {
        "status": "valid",
        "critical_issues": [],
        "warnings": [],
        "recommendations": []
    }

    # 1. Configuration Validation
    print("\n📋 Validating Configuration...")
    config_validation = settings.validate_configuration()

    if config_validation["status"] != "valid":
        validation_result["status"] = "invalid"
        validation_result["critical_issues"].extend(config_validation["critical_issues"])

    validation_result["warnings"].extend(config_validation["warnings"])

    # Print configuration issues
    for issue in config_validation["critical_issues"]:
        print(f"❌ CRITICAL: {issue}")

    for warning in config_validation["warnings"]:
        print(f"⚠️  WARNING: {warning}")

    # 2. Email Service Validation
    print("\n📧 Validating Email Configuration...")
    if not settings.email_service_configured:
        validation_result["critical_issues"].append("No email service configured")
        print("❌ No email service configured - emails will fail")
    else:
        print("✅ Email service configured")

        # Check for Gmail in production
        if (settings.ENVIRONMENT == "production" and
            settings.SMTP_SERVER == "smtp.gmail.com"):
            validation_result["warnings"].append(
                "Using Gmail SMTP in production - consider a dedicated email service"
            )
            print("⚠️  Using Gmail in production - consider AWS SES, Mailgun, or SendGrid")

    # 3. Security Validation
    print("\n🔒 Validating Security Settings...")
    security_issues = []

    if settings.SECRET_KEY == "your-super-secret-key-change-in-production":
        security_issues.append("Default SECRET_KEY detected")

    if len(settings.SECRET_KEY) < 32:
        security_issues.append("SECRET_KEY too short")

    if settings.SUPER_ADMIN_PASSWORD == "SuperSecurePassword123!":
        security_issues.append("Default SUPER_ADMIN_PASSWORD detected")

    if security_issues:
        validation_result["status"] = "invalid"
        validation_result["critical_issues"].extend(security_issues)
        for issue in security_issues:
            print(f"❌ SECURITY RISK: {issue}")
    else:
        print("✅ Security settings validated")

    # 4. Production Readiness
    print("\n🚀 Checking Production Readiness...")
    if settings.ENVIRONMENT == "production":
        prod_issues = []

        if settings.DEBUG:
            prod_issues.append("DEBUG mode enabled in production")

        if "*" in settings.ALLOWED_HOSTS:
            prod_issues.append("CORS allows all hosts in production")

        if "localhost" in settings.DATABASE_URL:
            prod_issues.append("Using localhost database in production")

        if prod_issues:
            validation_result["warnings"].extend(prod_issues)
            for issue in prod_issues:
                print(f"⚠️  PRODUCTION: {issue}")
        else:
            print("✅ Production settings look good")

    # 5. Recommendations
    print("\n💡 Recommendations for Production:")
    recommendations = []

    if not settings.MAILGUN_API_KEY and not settings.SENDGRID_API_KEY:
        recommendations.append("Consider Mailgun or SendGrid for reliable email delivery")

    if not settings.PROMETHEUS_ENABLED:
        recommendations.append("Enable Prometheus monitoring for production insights")

    if not settings.BACKUP_ENABLED:
        recommendations.append("Enable database backups for data protection")

    validation_result["recommendations"] = recommendations

    for rec in recommendations:
        print(f"💡 {rec}")

    # Summary
    print(f"\n📊 Validation Summary:")
    print(f"Status: {'✅ PASS' if validation_result['status'] == 'valid' else '❌ FAIL'}")
    print(f"Critical Issues: {len(validation_result['critical_issues'])}")
    print(f"Warnings: {len(validation_result['warnings'])}")
    print(f"Recommendations: {len(validation_result['recommendations'])}")

    return validation_result

if __name__ == "__main__":
    result = validate_startup()

    if result["status"] != "valid":
        print("\n❌ Startup validation failed. Please fix critical issues before proceeding.")
        sys.exit(1)
    else:
        print("\n✅ Startup validation passed. AuthX is ready to start!")
        sys.exit(0)
