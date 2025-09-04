"""
Advanced security services for the AuthX service.
This module provides implementations for brute force protection, anomaly detection,
risk scoring, fraud detection, and bot detection.
"""
import time
import hashlib
import json
import re
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc, select

from app.core.infrastructure import redis_client, REDIS_AVAILABLE
from app.models.user import User
from app.models.audit import AuditLog

# Import password utilities from app.utils.security
from app.utils.security import get_password_hash, verify_password

# Brute Force Protection
async def check_brute_force(
    ip_address: str,
    username: str,
    max_attempts: int = 5,
    window_minutes: int = 15
) -> Tuple[bool, int]:
    """
    Check if a login attempt should be blocked due to brute force protection.

    Args:
        ip_address: The IP address of the request
        username: The username being used
        max_attempts: Maximum allowed attempts
        window_minutes: Time window in minutes

    Returns:
        Tuple of (is_blocked, remaining_attempts)
    """
    if not REDIS_AVAILABLE:
        # Simple fallback without Redis
        return False, max_attempts

    # Use Redis for tracking attempts
    key = f"brute_force:{username}:{ip_address}"

    # Get current attempt count
    attempts = redis_client.get(key)
    if attempts is None:
        attempts = 0
    else:
        attempts = int(attempts)

    # Check if blocked
    is_blocked = attempts >= max_attempts
    remaining_attempts = max(0, max_attempts - attempts)

    return is_blocked, remaining_attempts

async def record_failed_login(ip_address: str, username: str, window_minutes: int = 15):
    """
    Record a failed login attempt for brute force protection.

    Args:
        ip_address: The IP address of the request
        username: The username being used
        window_minutes: Time window in minutes
    """
    if not REDIS_AVAILABLE:
        return

    # Use Redis for tracking attempts
    key = f"brute_force:{username}:{ip_address}"

    # Get current attempt count
    attempts = redis_client.get(key)
    if attempts is None:
        attempts = 0
    else:
        attempts = int(attempts)

    # Increment attempts
    redis_client.setex(key, window_minutes * 60, attempts + 1)

async def reset_brute_force_counter(ip_address: str, username: str):
    """
    Reset the brute force counter after a successful login.

    Args:
        ip_address: The IP address of the request
        username: The username being used
    """
    if not REDIS_AVAILABLE:
        return

    # Use Redis for tracking attempts
    key = f"brute_force:{username}:{ip_address}"

    # Delete the key
    redis_client.delete(key)

# Risk Scoring System
async def calculate_login_risk_score(
    user: User,
    request_info: Dict[str, Any],
    db: AsyncSession
) -> float:
    """
    Calculate a risk score for a login attempt.

    Args:
        user: The user attempting to login
        request_info: Request context information
        db: Database session

    Returns:
        Risk score between 0.0 and 1.0 (higher is riskier)
    """
    # Initialize risk score (0.0 - 1.0, higher is riskier)
    risk_score = 0.0

    ip_address = request_info.get("ip_address", "")
    user_agent = request_info.get("user_agent", "")

    # 1. Check if it's a new device (20% risk)
    device_fingerprint = generate_device_fingerprint(request_info)
    if device_fingerprint:
        # Simple check - in production, you'd check against stored devices
        if not user.last_login:  # Fixed: use last_login instead of last_login_at
            risk_score += 0.1  # New user, slight risk

    # 2. Check time patterns (10% risk for unusual hours)
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 23:  # Night hours
        risk_score += 0.1

    # 3. Check for suspicious user agent patterns (15% risk)
    if not user_agent or len(user_agent) < 10:
        risk_score += 0.15

    # 4. Check login frequency (20% risk for rapid attempts)
    if user.last_login:  # Fixed: use last_login instead of last_login_at
        time_since_last = datetime.utcnow() - user.last_login
        if time_since_last.total_seconds() < 60:  # Less than 1 minute
            risk_score += 0.2

    # Cap at 1.0
    return min(risk_score, 1.0)

def generate_device_fingerprint(request_info: Dict[str, Any]) -> str:
    """
    Generate a device fingerprint from request information.

    Args:
        request_info: Request context information

    Returns:
        Device fingerprint string
    """
    # Create fingerprint from available request data
    fingerprint_data = {
        "user_agent": request_info.get("user_agent", ""),
        "ip": request_info.get("ip_address", ""),
        # Add more device characteristics as available
    }

    # Create hash of the fingerprint data
    fingerprint_json = json.dumps(fingerprint_data, sort_keys=True)
    fingerprint_hash = hashlib.sha256(fingerprint_json.encode()).hexdigest()

    return fingerprint_hash

def detect_bot(request_info: Dict[str, Any]) -> bool:
    """
    Simple bot detection based on user agent patterns.

    Args:
        request_info: Request context information

    Returns:
        True if request appears to be from a bot
    """
    user_agent = request_info.get("user_agent", "").lower()

    # Common bot patterns
    bot_patterns = [
        "bot", "crawler", "spider", "scraper", "automated",
        "python-requests", "curl", "wget", "httpclient"
    ]

    return any(pattern in user_agent for pattern in bot_patterns)

def get_country_from_ip(ip_address: str) -> Optional[str]:
    """
    Get country code from IP address.
    This is a placeholder - in production, use a geolocation service.

    Args:
        ip_address: The IP address

    Returns:
        Country code or None
    """
    # Placeholder implementation
    # In production, integrate with MaxMind GeoIP2 or similar service
    if ip_address.startswith("127.") or ip_address.startswith("192.168."):
        return "LOCAL"
    return "US"  # Default fallback

# Token verification utility
def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode JWT token.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload
    """
    from jose import jwt, JWTError
    from app.core.config import settings

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid token")

async def check_ip_risk(ip_address: str) -> float:
    """
    Check IP address risk score.

    Args:
        ip_address: IP address to check

    Returns:
        Risk score between 0.0 and 1.0
    """
    # Simple IP risk assessment
    if ip_address.startswith("127.") or ip_address.startswith("192.168."):
        return 0.0  # Local network, low risk

    # Check for common suspicious patterns
    if any(pattern in ip_address for pattern in ["10.", "172."]):
        return 0.1  # Private networks, slightly higher risk

    return 0.2  # External IP, moderate baseline risk

def is_suspicious_user_agent(user_agent: str) -> bool:
    """
    Check if user agent appears suspicious.

    Args:
        user_agent: User agent string

    Returns:
        True if suspicious
    """
    if not user_agent:
        return True

    suspicious_patterns = [
        "bot", "crawler", "spider", "scraper", "automated",
        "python", "curl", "wget", "httpclient", "scanner"
    ]

    user_agent_lower = user_agent.lower()
    return any(pattern in user_agent_lower for pattern in suspicious_patterns)

async def detect_anomalies(user_data: Dict[str, Any], request_info: Dict[str, Any]) -> List[str]:
    """
    Detect anomalies in user behavior.

    Args:
        user_data: User information
        request_info: Request context

    Returns:
        List of detected anomalies
    """
    anomalies = []

    # Check for unusual login times
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 23:
        anomalies.append("unusual_login_time")

    # Check for suspicious user agent
    if is_suspicious_user_agent(request_info.get("user_agent", "")):
        anomalies.append("suspicious_user_agent")

    return anomalies

async def detect_fraud(user_data: Dict[str, Any], request_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect potential fraud indicators.

    Args:
        user_data: User information
        request_info: Request context

    Returns:
        Fraud detection results
    """
    fraud_score = 0.0
    fraud_indicators = []

    # Check for bot-like behavior
    if detect_bot(request_info):
        fraud_score += 0.3
        fraud_indicators.append("bot_behavior")

    # Check IP risk
    ip_risk = await check_ip_risk(request_info.get("ip_address", ""))
    fraud_score += ip_risk

    if ip_risk > 0.5:
        fraud_indicators.append("high_risk_ip")

    return {
        "fraud_score": min(fraud_score, 1.0),
        "indicators": fraud_indicators,
        "risk_level": "high" if fraud_score > 0.7 else "medium" if fraud_score > 0.3 else "low"
    }

async def detect_bot_advanced(request_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Advanced bot detection with detailed analysis.

    Args:
        request_info: Request context

    Returns:
        Bot detection results
    """
    is_bot = detect_bot(request_info)
    confidence = 0.8 if is_bot else 0.2

    return {
        "is_bot": is_bot,
        "confidence": confidence,
        "indicators": ["user_agent_pattern"] if is_bot else []
    }
