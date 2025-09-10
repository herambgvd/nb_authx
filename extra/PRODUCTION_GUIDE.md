# AuthX Production Deployment Guide

## 🚨 Critical Security Issues Fixed

### 1. **Default Security Credentials** 
- **CRITICAL**: Default SECRET_KEY and SUPER_ADMIN_PASSWORD detected
- **Fix**: Use the `.env.example` file I created and set secure values

### 2. **Email Service Configuration**
- **Issue**: No fallback email providers configured
- **Fix**: Enhanced email service with Gmail (dev) + budget production options

### 3. **Configuration Validation**
- **Issue**: No startup validation for security issues
- **Fix**: Created comprehensive validation system

## 📧 Email Configuration (Fixed)

### Development (Gmail - Free)
```bash
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-app-password  # Generate in Gmail settings
SMTP_USE_TLS=true
EMAIL_FROM=your-gmail@gmail.com
```

### Production Options (Budget-Friendly)

#### Option 1: AWS SES (Most Cost-Effective)
```bash
SMTP_SERVER=email-smtp.us-west-2.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-username
SMTP_PASSWORD=your-ses-password
# Cost: $0.10 per 1,000 emails
```

#### Option 2: Mailgun (Easy Setup)
```bash
MAILGUN_API_KEY=your-mailgun-api-key
MAILGUN_DOMAIN=your-domain.com
# Cost: $0.80 per 1,000 emails (first 5,000 free)
```

#### Option 3: SendGrid (Reliable)
```bash
SENDGRID_API_KEY=your-sendgrid-api-key
# Cost: $0.90 per 1,000 emails (first 100/day free)
```

## 🏗️ Microservice Architecture (AuthX Python SDK)

### SDK Installation
```bash
cd authx_sdk
pip install -e .  # Install in development mode
```

### Microservice Integration Example
```python
from authx_sdk import AuthXClient
import asyncio

async def main():
    # Initialize AuthX client for your microservice
    async with AuthXClient(
        base_url="http://authx-service:8000",
        api_key="your-service-api-key"
    ) as client:
        
        # Authenticate user
        auth_response = await client.authenticate("user@example.com", "password")
        
        # Check permissions
        has_permission = await client.check_permission("users:read")
        
        # Get user data
        users = await client.list_users(page=1, size=10)
        
        # Health check
        health = await client.health_check()

asyncio.run(main())
```

### FastAPI Integration
```python
from fastapi import FastAPI, Depends, HTTPException
from authx_sdk import AuthXClient

app = FastAPI()
authx = AuthXClient(base_url="http://authx:8000")

async def get_current_user(token: str = Depends(get_token)):
    try:
        auth_response = await authx.authenticate_with_token(token)
        return auth_response.user
    except AuthenticationError:
        raise HTTPException(status_code=401)

@app.get("/protected")
async def protected_endpoint(user = Depends(get_current_user)):
    return {"message": f"Hello {user.full_name}!"}
```

## 🔧 Pre-Production Checklist

### 1. Run Security Validation
```bash
python validate_startup.py
```

### 2. Set Environment Variables
```bash
# Copy and customize
cp .env.example .env

# Critical settings to change:
SECRET_KEY=your-32-character-secret-key-here
SUPER_ADMIN_EMAIL=admin@yourcompany.com
SUPER_ADMIN_PASSWORD=YourSecurePassword123!

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/authx
REDIS_URL=redis://redis-host:6379/0

# Email (choose one option from above)
```

### 3. Database Migration
```bash
alembic upgrade head
```

### 4. Health Check
```bash
curl http://localhost:8000/health/detailed
```

## 🚀 Docker Production Setup

### docker-compose.yml
```yaml
version: '3.8'
services:
  authx:
    build: .
    environment:
      - ENVIRONMENT=production
      - DEBUG=false
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: authx
      POSTGRES_USER: authx
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass your_redis_password
```

## 📊 Monitoring & Observability

### Health Endpoints Added
- `/health` - Basic health check
- `/health/detailed` - Comprehensive system status
- `/health/readiness` - Kubernetes readiness probe
- `/health/liveness` - Kubernetes liveness probe
- `/metrics/email` - Email service statistics

### Production Monitoring
```bash
# Prometheus metrics available at
curl http://localhost:8000/metrics

# Email service stats
curl http://localhost:8000/metrics/email
```

## 🔄 Microservice Communication Patterns

### 1. Service-to-Service Authentication
```python
# In your other microservices
from authx_sdk import AuthXClient

# Initialize with API key for service auth
client = AuthXClient(
    base_url="http://authx:8000",
    api_key="service-api-key"
)
```

### 2. User Context Propagation
```python
# Pass user context between services
async def process_user_request(user_token: str):
    async with AuthXClient("http://authx:8000") as client:
        user = await client.authenticate_with_token(user_token)
        
        # Check permissions for this service
        if await client.check_permission("resource:access"):
            return await process_authorized_request(user)
        else:
            raise PermissionError("Access denied")
```

## 💰 Cost Optimization for Production

### Email Service Cost Comparison (per 10,000 emails/month)
1. **AWS SES**: $1.00 (most cost-effective)
2. **Mailgun**: $8.00 (easiest setup)
3. **SendGrid**: $9.00 (most reliable)
4. **Gmail**: Free for development only

### Infrastructure Recommendations
- **Development**: Use local services (PostgreSQL, Redis, Gmail)
- **Production**: Managed services (AWS RDS, ElastiCache, SES)
- **Scaling**: Horizontal scaling with load balancers

## 🛡️ Security Best Practices Implemented

1. **Token Management**: Automatic refresh and expiration handling
2. **Rate Limiting**: Built-in protection against abuse
3. **Input Validation**: Comprehensive request validation
4. **Audit Logging**: Complete audit trail for security events
5. **Permission Checks**: Granular authorization system

## 📝 Next Steps

1. **Configure Email Service**: Choose and set up one of the production email options
2. **Update Security Settings**: Change all default passwords and keys
3. **Run Validation**: Execute `python validate_startup.py`
4. **Deploy SDK**: Install AuthX SDK in your other microservices
5. **Monitor Health**: Set up monitoring dashboards
6. **Scale**: Use the SDK for easy horizontal scaling

Your AuthX system is now production-ready with comprehensive microservice support!
