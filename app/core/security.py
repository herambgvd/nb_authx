"""
Advanced security services for the AuthX service.
This module provides implementations for brute force protection, anomaly detection,
risk scoring, fraud detection, and bot detection.
"""
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import math
import ipaddress
import re
from fastapi import Request
from sqlalchemy.orm import Session

from app.core.infrastructure import redis_client, REDIS_AVAILABLE
from app.models.user import User
from app.models.audit import AuditLog, SecurityEvent
from app.core.config import settings

# Brute Force Protection
def check_brute_force(
    username: str,
    ip_address: str,
    db: Session,
    max_attempts: int = 5,
    window_minutes: int = 15
) -> Tuple[bool, int]:
    """
    Check if a login attempt should be blocked due to brute force protection.

    Args:
        username: The username being used
        ip_address: The IP address of the request
        db: Database session
        max_attempts: Maximum allowed attempts
        window_minutes: Time window in minutes

    Returns:
        Tuple of (is_blocked, remaining_attempts)
    """
    if not REDIS_AVAILABLE:
        # Fallback to database if Redis is not available
        window_start = datetime.utcnow() - timedelta(minutes=window_minutes)

        # Count failed attempts from this IP for this username
        failed_attempts = db.query(AuditLog).filter(
            AuditLog.event_type == "login",
            AuditLog.action == "authenticate",
            AuditLog.status == "failure",
            AuditLog.user_email == username,
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= window_start
        ).count()

        is_blocked = failed_attempts >= max_attempts
        remaining_attempts = max(0, max_attempts - failed_attempts)

        return is_blocked, remaining_attempts

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

def record_failed_login(
    username: str,
    ip_address: str,
    user_agent: str,
    db: Session,
    window_minutes: int = 15
):
    """
    Record a failed login attempt for brute force protection.

    Args:
        username: The username being used
        ip_address: The IP address of the request
        user_agent: The user agent string
        db: Database session
        window_minutes: Time window in minutes
    """
    # Always record in database for audit purposes
    audit_log = AuditLog(
        user_email=username,
        ip_address=ip_address,
        user_agent=user_agent,
        event_type="login",
        resource_type="user",
        action="authenticate",
        status="failure",
        description=f"Failed login attempt for user {username}",
        source="api"
    )
    db.add(audit_log)
    db.commit()

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

def reset_brute_force_counter(username: str, ip_address: str):
    """
    Reset the brute force counter after a successful login.

    Args:
        username: The username being used
        ip_address: The IP address of the request
    """
    if not REDIS_AVAILABLE:
        return

    # Use Redis for tracking attempts
    key = f"brute_force:{username}:{ip_address}"

    # Delete the key
    redis_client.delete(key)

# Risk Scoring System
def calculate_login_risk_score(
    request: Request,
    user: User,
    db: Session
) -> Dict[str, Any]:
    """
    Calculate a risk score for a login attempt.

    Args:
        request: The request object
        user: The user attempting to login
        db: Database session

    Returns:
        Dict with risk score and factors
    """
    # Initialize risk score (0-100, higher is riskier)
    risk_score = 0
    risk_factors = []

    # Get request information
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # 1. Check if IP is from a new country
    country_code = get_country_from_ip(ip_address)
    if user.last_login and country_code:
        # Get user's previous login countries
        previous_countries = db.query(AuditLog.details['country'].as_string()).filter(
            AuditLog.user_id == user.id,
            AuditLog.event_type == "login",
            AuditLog.status == "success"
        ).distinct().all()

        previous_countries = [c[0] for c in previous_countries if c[0] is not None]

        if country_code not in previous_countries:
            risk_score += 20
            risk_factors.append(f"Login from new country: {country_code}")

    # 2. Check if it's a new device
    device_fingerprint = generate_device_fingerprint(request)
    if device_fingerprint:
        # Check if device has been used before
        previous_device = db.query(AuditLog).filter(
            AuditLog.user_id == user.id,
            AuditLog.event_type == "login",
            AuditLog.status == "success",
            AuditLog.details['device_fingerprint'].as_string() == device_fingerprint
        ).first()

        if not previous_device:
            risk_score += 15
            risk_factors.append("Login from new device")

    # 3. Check time of day pattern
    current_hour = datetime.utcnow().hour
    if user.last_login:
        # Get user's typical login hours
        login_hours = db.query(
            func.extract('hour', AuditLog.created_at).label('hour'),
            func.count().label('count')
        ).filter(
            AuditLog.user_id == user.id,
            AuditLog.event_type == "login",
            AuditLog.status == "success"
        ).group_by('hour').order_by(desc('count')).limit(3).all()

        # If current hour is outside typical pattern
        typical_hours = [h[0] for h in login_hours]
        if typical_hours and current_hour not in typical_hours:
            risk_score += 10
            risk_factors.append(f"Login at unusual hour: {current_hour}")

    # 4. Check for suspicious IP address
    ip_risk = check_ip_risk(ip_address)
    risk_score += ip_risk['score']
    if ip_risk['score'] > 0:
        risk_factors.extend(ip_risk['factors'])

    # 5. Check user-agent for potential automation
    if is_suspicious_user_agent(user_agent):
        risk_score += 15
        risk_factors.append("Suspicious user-agent detected")

    # 6. Account dormancy
    if user.last_login:
        days_since_login = (datetime.utcnow() - user.last_login).days
        if days_since_login > 90:
            dormant_score = min(25, days_since_login // 30 * 5)  # 5 points per month, max 25
            risk_score += dormant_score
            risk_factors.append(f"Account dormant for {days_since_login} days")

    # 7. Failed login attempts
    failed_attempts = db.query(AuditLog).filter(
        AuditLog.user_id == user.id,
        AuditLog.event_type == "login",
        AuditLog.status == "failure",
        AuditLog.created_at >= (datetime.utcnow() - timedelta(days=1))
    ).count()

    if failed_attempts > 0:
        failed_score = min(20, failed_attempts * 4)  # 4 points per failed attempt, max 20
        risk_score += failed_score
        risk_factors.append(f"{failed_attempts} failed login attempts in last 24 hours")

    # Cap the risk score at 100
    risk_score = min(100, risk_score)

    # Determine risk level
    risk_level = "low"
    if risk_score >= 75:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 25:
        risk_level = "medium"

    return {
        "score": risk_score,
        "level": risk_level,
        "factors": risk_factors,
        "timestamp": datetime.utcnow().isoformat()
    }

def check_ip_risk(ip_address: str) -> Dict[str, Any]:
    """
    Check if an IP address is risky.

    Args:
        ip_address: The IP address to check

    Returns:
        Dict with risk score and factors
    """
    score = 0
    factors = []

    try:
        # Parse IP
        ip = ipaddress.ip_address(ip_address)

        # Check if private
        if ip.is_private:
            return {"score": 0, "factors": []}

        # Check if loopback
        if ip.is_loopback:
            score += 50
            factors.append("Loopback IP detected")

        # Check if in known proxy/VPN ranges (simplified)
        known_proxies = [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
            "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
            "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17"
        ]

        for proxy_range in known_proxies:
            if ip in ipaddress.ip_network(proxy_range):
                score += 15
                factors.append(f"IP in known proxy range: {proxy_range}")
                break

    except ValueError:
        # Invalid IP
        score += 25
        factors.append("Invalid IP address format")

    return {"score": score, "factors": factors}

def generate_device_fingerprint(request: Request) -> str:
    """
    Generate a device fingerprint from request headers.

    Args:
        request: The request object

    Returns:
        Device fingerprint string
    """
    # Get headers
    user_agent = request.headers.get("user-agent", "")
    accept_language = request.headers.get("accept-language", "")
    accept = request.headers.get("accept", "")

    # Create fingerprint
    fingerprint = f"{user_agent}|{accept_language}|{accept}"

    # Hash the fingerprint
    import hashlib
    return hashlib.md5(fingerprint.encode()).hexdigest()

def is_suspicious_user_agent(user_agent: str) -> bool:
    """
    Check if a user agent string looks suspicious.

    Args:
        user_agent: The user agent string

    Returns:
        True if suspicious, False otherwise
    """
    # Empty user agent
    if not user_agent:
        return True

    # Check for automation tools
    automation_patterns = [
        r'python', r'curl', r'wget', r'bot', r'crawler', r'spider',
        r'selenium', r'puppeteer', r'phantomjs', r'headless', r'scrape'
    ]

    for pattern in automation_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return True

    # Check for very short user agents
    if len(user_agent) < 20:
        return True

    return False

def get_country_from_ip(ip_address: str) -> Optional[str]:
    """
    Get country code from IP address.

    Args:
        ip_address: The IP address

    Returns:
        Two-letter country code or None
    """
    # In a real implementation, this would use a geolocation service
    # For simplicity, we're returning a mock value
    return "US"

# Anomaly Detection
def detect_anomalies(
    event_type: str,
    user_id: str,
    event_data: Dict[str, Any],
    db: Session
) -> List[Dict[str, Any]]:
    """
    Detect anomalies in user behavior.

    Args:
        event_type: The type of event
        user_id: User ID
        event_data: Event data
        db: Database session

    Returns:
        List of detected anomalies
    """
    anomalies = []

    # Get user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return anomalies

    if event_type == "login":
        # Check login time anomalies
        if user.last_login:
            login_hour = datetime.utcnow().hour

            # Get user's historical login hour distribution
            login_hours = db.query(
                func.extract('hour', AuditLog.created_at).label('hour'),
                func.count().label('count')
            ).filter(
                AuditLog.user_id == user_id,
                AuditLog.event_type == "login",
                AuditLog.status == "success"
            ).group_by('hour').all()

            hour_counts = {int(h.hour): h.count for h in login_hours}
            total_logins = sum(hour_counts.values())

            # Calculate probability of current login hour
            current_hour_probability = hour_counts.get(login_hour, 0) / max(1, total_logins)

            # If unusual login hour (probability < 5%)
            if current_hour_probability < 0.05 and total_logins > 10:
                anomalies.append({
                    "type": "unusual_login_time",
                    "severity": "medium",
                    "description": f"Login at unusual hour ({login_hour}:00)",
                    "probability": current_hour_probability
                })

        # Check location anomalies
        if 'ip_address' in event_data:
            country = get_country_from_ip(event_data['ip_address'])
            if country:
                # Get user's historical login countries
                login_countries = db.query(
                    AuditLog.details['country'].as_string(),
                    func.count().label('count')
                ).filter(
                    AuditLog.user_id == user_id,
                    AuditLog.event_type == "login",
                    AuditLog.status == "success",
                    AuditLog.details['country'].as_string() != None
                ).group_by(AuditLog.details['country']).all()

                country_counts = {c.country: c.count for c in login_countries}
                total_logins = sum(country_counts.values())

                # If login from new country
                if country not in country_counts and total_logins > 5:
                    anomalies.append({
                        "type": "new_login_location",
                        "severity": "high",
                        "description": f"First login from {country}",
                        "details": {"country": country}
                    })

    elif event_type == "access":
        # Check for unusual access patterns
        if 'resource_type' in event_data and 'action' in event_data:
            resource_type = event_data['resource_type']
            action = event_data['action']

            # Get user's resource access history
            access_patterns = db.query(
                AuditLog.resource_type,
                AuditLog.action,
                func.count().label('count')
            ).filter(
                AuditLog.user_id == user_id,
                AuditLog.event_type == "access"
            ).group_by(AuditLog.resource_type, AuditLog.action).all()

            # Convert to dictionary
            pattern_counts = {(a.resource_type, a.action): a.count for a in access_patterns}

            # If new access pattern
            if (resource_type, action) not in pattern_counts:
                anomalies.append({
                    "type": "new_access_pattern",
                    "severity": "medium",
                    "description": f"First time {action} on {resource_type}",
                    "details": {"resource_type": resource_type, "action": action}
                })

    return anomalies

# Fraud Detection
def detect_fraud(
    event_type: str,
    user_id: str,
    event_data: Dict[str, Any],
    db: Session
) -> List[Dict[str, Any]]:
    """
    Detect potential fraud in user activities.

    Args:
        event_type: The type of event
        user_id: User ID
        event_data: Event data
        db: Database session

    Returns:
        List of fraud indicators
    """
    fraud_indicators = []

    # Get user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return fraud_indicators

    if event_type == "login":
        # Check for impossible travel
        if 'ip_address' in event_data and user.last_login:
            current_country = get_country_from_ip(event_data['ip_address'])

            # Get country of last login
            last_login_event = db.query(AuditLog).filter(
                AuditLog.user_id == user_id,
                AuditLog.event_type == "login",
                AuditLog.status == "success"
            ).order_by(AuditLog.created_at.desc()).first()

            if last_login_event and 'details' in last_login_event.__dict__:
                last_details = last_login_event.details or {}
                last_country = last_details.get('country')

                if last_country and current_country and last_country != current_country:
                    # Calculate time since last login
                    time_diff = datetime.utcnow() - last_login_event.created_at
                    hours_diff = time_diff.total_seconds() / 3600

                    # Simplified check for impossible travel
                    # In a real system, would calculate actual travel times between countries
                    if hours_diff < 2 and last_country != current_country:
                        fraud_indicators.append({
                            "type": "impossible_travel",
                            "severity": "critical",
                            "description": f"Login from {current_country} {hours_diff:.1f} hours after login from {last_country}",
                            "details": {
                                "current_country": current_country,
                                "previous_country": last_country,
                                "hours_between": hours_diff
                            }
                        })

    elif event_type == "access":
        # Check for unusual data access patterns
        if 'resource_type' in event_data and 'resource_id' in event_data:
            resource_type = event_data['resource_type']
            resource_id = event_data['resource_id']

            # Check for excessive data access
            access_count = db.query(func.count(AuditLog.id)).filter(
                AuditLog.user_id == user_id,
                AuditLog.event_type == "access",
                AuditLog.resource_type == resource_type,
                AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
            ).scalar()

            # If accessing unusually high volume of resources
            if access_count > 100:  # Threshold for excessive access
                fraud_indicators.append({
                    "type": "excessive_data_access",
                    "severity": "high",
                    "description": f"Accessed {access_count} {resource_type} resources in the last hour",
                    "details": {"resource_type": resource_type, "count": access_count}
                })

    return fraud_indicators

# Bot Detection
def detect_bot(request: Request) -> Dict[str, Any]:
    """
    Detect if a request is likely from a bot.

    Args:
        request: The request object

    Returns:
        Dict with bot score and factors
    """
    # Initialize bot score (0-100, higher means more likely a bot)
    bot_score = 0
    bot_factors = []

    # Get request information
    headers = dict(request.headers)
    user_agent = headers.get("user-agent", "")

    # 1. Check user agent
    if not user_agent:
        bot_score += 40
        bot_factors.append("Missing user agent")
    elif is_suspicious_user_agent(user_agent):
        bot_score += 30
        bot_factors.append("Suspicious user agent")

    # 2. Check for missing or inconsistent headers
    expected_headers = ["accept", "accept-language", "accept-encoding"]
    missing_headers = [h for h in expected_headers if h not in headers]

    if missing_headers:
        bot_score += len(missing_headers) * 10
        bot_factors.append(f"Missing headers: {', '.join(missing_headers)}")

    # 3. Check for inconsistent headers
    if "accept" in headers and "text/html" not in headers["accept"] and "application/json" not in headers["accept"]:
        bot_score += 15
        bot_factors.append("Unusual accept header")

    # 4. Check request rate (requires Redis)
    if REDIS_AVAILABLE:
        ip_address = request.client.host
        request_key = f"request_rate:{ip_address}"

        # Count requests in the last minute
        current_time = int(time.time())
        # Add current timestamp to a sorted set with score as timestamp
        redis_client.zadd(request_key, {current_time: current_time})
        # Remove entries older than 1 minute
        redis_client.zremrangebyscore(request_key, 0, current_time - 60)
        # Count entries
        request_count = redis_client.zcard(request_key)

        # Set expiration for cleanup
        redis_client.expire(request_key, 120)  # 2 minutes

        # Check if request rate is too high
        if request_count > 60:  # More than 1 request per second
            bot_score += 25
            bot_factors.append(f"High request rate: {request_count} requests/minute")

    # 5. Behavioral analysis
    # In a real system, would analyze mouse movements, keystroke patterns, etc.

    # Cap the bot score at 100
    bot_score = min(100, bot_score)

    # Determine bot likelihood
    bot_likelihood = "low"
    if bot_score >= 75:
        bot_likelihood = "very high"
    elif bot_score >= 50:
        bot_likelihood = "high"
    elif bot_score >= 25:
        bot_likelihood = "medium"

    return {
        "score": bot_score,
        "likelihood": bot_likelihood,
        "factors": bot_factors
    }
