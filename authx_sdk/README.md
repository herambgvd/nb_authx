# AuthX Python SDK

Official Python SDK for AuthX Authentication Service - designed for easy microservice integration.

## Features

- 🔐 **Complete Authentication**: Login, logout, token refresh, and user management
- 🛡️ **Authorization Support**: Permission checking and role-based access control
- 🔄 **Automatic Token Management**: Handles token refresh and expiration
- 🌐 **Async/Await Support**: Built for modern Python async applications
- 📊 **Health Monitoring**: Service health checks and monitoring
- 🚨 **Error Handling**: Comprehensive exception handling with retries
- 📈 **Production Ready**: Circuit breakers, rate limiting, and logging

## Installation

```bash
pip install authx-sdk
```

## Quick Start

### Basic Usage

```python
from authx_sdk import AuthXClient
import asyncio

async def main():
    # Initialize client
    async with AuthXClient(
        base_url="http://localhost:8000",
        api_key="your-api-key"  # Optional for service-to-service auth
    ) as client:
        
        # Authenticate user
        auth_response = await client.authenticate("user@example.com", "password")
        print(f"Welcome {auth_response.user.full_name}!")
        
        # Check permissions
        has_permission = await client.check_permission("users:read")
        if has_permission:
            # Get user list
            users = await client.list_users(page=1, size=10)
            print(f"Found {users.total} users")

asyncio.run(main())
```

### Microservice Integration Example

```python
from fastapi import FastAPI, Depends, HTTPException
from authx_sdk import AuthXClient, AuthenticationError
import os

app = FastAPI()

# Initialize AuthX client
authx_client = AuthXClient(
    base_url=os.getenv("AUTHX_URL", "http://authx:8000"),
    api_key=os.getenv("AUTHX_API_KEY")
)

async def get_current_user(token: str = Depends(get_token)):
    """Dependency to get current user from token."""
    try:
        auth_response = await authx_client.authenticate_with_token(token)
        return auth_response.user
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected-resource")
async def protected_endpoint(user = Depends(get_current_user)):
    # Check specific permission
    if not await authx_client.check_permission("resource:read"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {"message": f"Hello {user.full_name}!"}
```

### Error Handling

```python
from authx_sdk import AuthXClient, AuthenticationError, AuthorizationError

async with AuthXClient(base_url="http://localhost:8000") as client:
    try:
        await client.authenticate("user@example.com", "wrong_password")
    except AuthenticationError as e:
        print(f"Login failed: {e.message}")
    except AuthorizationError as e:
        print(f"Access denied: {e.message}")
```

## Configuration

### Environment Variables for Production

```bash
# Gmail for Development
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-gmail@gmail.com
SMTP_PASSWORD=your-app-password  # Use App Password, not regular password
SMTP_USE_TLS=true
EMAIL_FROM=your-gmail@gmail.com

# Production - AWS SES (Budget-friendly)
SMTP_SERVER=email-smtp.us-west-2.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-username
SMTP_PASSWORD=your-ses-password

# Production - Mailgun (Alternative)
MAILGUN_API_KEY=your-mailgun-api-key
MAILGUN_DOMAIN=your-domain.com

# Production - SendGrid (Alternative)
SENDGRID_API_KEY=your-sendgrid-api-key
```

## API Reference

### Authentication Methods

- `authenticate(username, password)` - Login with credentials
- `authenticate_with_token(token)` - Authenticate with existing token
- `refresh_token()` - Refresh access token
- `logout()` - Logout and invalidate tokens
- `get_current_user()` - Get current authenticated user

### User Management

- `create_user(user_data)` - Create new user
- `get_user(user_id)` - Get user by ID
- `update_user(user_id, user_data)` - Update user
- `delete_user(user_id)` - Delete user
- `list_users(page, size)` - List users with pagination

### Authorization

- `check_permission(permission, resource_id)` - Check user permission
- `get_user_permissions(user_id)` - Get user's permissions

### Health Monitoring

- `health_check()` - Basic health check
- `detailed_health_check()` - Detailed health status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
