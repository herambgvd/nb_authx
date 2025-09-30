# AuthX API Documentation

## Table of Contents

1. [Authentication & Authorization Overview](#authentication--authorization-overview)
2. [Authentication Endpoints](#authentication-endpoints)
3. [Organization Management](#organization-management)
4. [User Management](#user-management)
5. [Role & Permission Management](#role--permission-management)
6. [Location Management](#location-management)
7. [Audit & Logging](#audit--logging)
8. [Health & Info](#health--info)

---

## Authentication & Authorization Overview

### Access Levels:
- **Super Admin**: Full access to all endpoints and all organizations
- **Organization Admin**: Access to organization-scoped endpoints (users, roles, locations within their org)
- **Regular User**: Access to their own profile and organization info

### Base URL
```
http://127.0.0.1:8000
```

### Authentication
All protected endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <access_token>
```

---

## Authentication Endpoints

### 1. Register User
**POST** `/api/v1/auth/register`

Create a new user account.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "SecurePassword123!",
    "first_name": "Test",
    "last_name": "User",
    "organization_id": "org_uuid_here"
  }'
```

**Response:**
```json
{
  "id": "user_uuid",
  "email": "user@example.com",
  "username": "testuser",
  "first_name": "Test",
  "last_name": "User",
  "is_active": true,
  "is_verified": false,
  "organization_id": "org_uuid_here",
  "created_at": "2025-09-12T10:30:00Z",
  "updated_at": "2025-09-12T10:30:00Z"
}
```

### 2. Login
**POST** `/api/v1/auth/login`

Authenticate and get access tokens.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "organization_slug": "test-org"
  }'
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "refresh_token_here",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "user_uuid",
    "email": "user@example.com",
    "username": "testuser",
    "first_name": "Test",
    "last_name": "User",
    "is_active": true,
    "organization_id": "org_uuid_here"
  }
}
```

### 3. Refresh Token
**POST** `/api/v1/auth/refresh`

Get a new access token using refresh token.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "refresh_token_here"
  }'
```

**Response:**
```json
{
  "access_token": "new_access_token_here",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 4. Logout
**POST** `/api/v1/auth/logout`

Logout and invalidate tokens.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "refresh_token_here"
  }'
```

### 5. Change Password
**POST** `/api/v1/auth/change-password`

Change user password.

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/auth/change-password" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "CurrentPassword123!",
    "new_password": "NewPassword123!"
  }'
```

---

## Organization Management
**Access:** Super Admin Only

### 1. Create Organization
**POST** `/api/v1/organizations`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/organizations" \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Organization",
    "slug": "test-org",
    "description": "A test organization",
    "max_users": 100
  }'
```

### 2. List Organizations
**GET** `/api/v1/organizations`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/organizations?page=1&size=20&is_active=true" \
  -H "Authorization: Bearer <super_admin_token>"
```

### 3. Get Organization by ID
**GET** `/api/v1/organizations/{organization_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/organizations/org_uuid_here" \
  -H "Authorization: Bearer <super_admin_token>"
```

### 4. Update Organization
**PUT** `/api/v1/organizations/{organization_id}`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/organizations/org_uuid_here" \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Organization Name",
    "description": "Updated description",
    "is_active": true
  }'
```

### 5. Delete Organization
**DELETE** `/api/v1/organizations/{organization_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/organizations/org_uuid_here" \
  -H "Authorization: Bearer <super_admin_token>"
```

### 6. Get My Organization Info
**GET** `/api/v1/organizations/my/info`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/organizations/my/info" \
  -H "Authorization: Bearer <access_token>"
```

---

## User Management
**Access:** Super Admin (all users) | Organization Admin (their org users only)

### 1. Create User
**POST** `/api/v1/users`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/users" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "username": "newuser",
    "password": "SecurePassword123!",
    "first_name": "New",
    "last_name": "User",
    "organization_id": "org_uuid_here"
  }'
```

### 2. List Users
**GET** `/api/v1/users`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/users?skip=0&limit=100&search=&is_active=true" \
  -H "Authorization: Bearer <admin_token>"
```

### 3. Get My Profile
**GET** `/api/v1/users/me`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/users/me" \
  -H "Authorization: Bearer <access_token>"
```

### 4. Update My Profile
**PUT** `/api/v1/users/me`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/users/me" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "updatedusername",
    "first_name": "Updated",
    "last_name": "Name"
  }'
```

### 5. Get User by ID
**GET** `/api/v1/users/{user_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/users/user_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 6. Update User
**PUT** `/api/v1/users/{user_id}`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/users/user_uuid_here" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "updateduser",
    "first_name": "Updated",
    "last_name": "User",
    "is_active": true,
    "is_verified": true
  }'
```

### 7. Delete User
**DELETE** `/api/v1/users/{user_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/users/user_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 8. Assign Roles to User
**POST** `/api/v1/users/{user_id}/roles`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/users/user_uuid_here/roles" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": ["role_uuid_1", "role_uuid_2"]
  }'
```

### 9. Remove User Roles
**DELETE** `/api/v1/users/{user_id}/roles`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/users/user_uuid_here/roles" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": ["role_uuid_1", "role_uuid_2"]
  }'
```

---

## Role & Permission Management

### Roles (Organization Scoped)
**Access:** Super Admin (all orgs) | Organization Admin (their org only)

#### 1. Create Role
**POST** `/api/v1/roles`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/roles" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Manager",
    "description": "Manager role with specific permissions",
    "is_active": true
  }'
```

#### 2. List Roles
**GET** `/api/v1/roles`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/roles?skip=0&limit=100&search=&is_active=true" \
  -H "Authorization: Bearer <admin_token>"
```

#### 3. Get Role by ID
**GET** `/api/v1/roles/{role_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/roles/role_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

#### 4. Update Role
**PUT** `/api/v1/roles/{role_id}`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/roles/role_uuid_here" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Manager",
    "description": "Updated role description",
    "is_active": true
  }'
```

#### 5. Delete Role
**DELETE** `/api/v1/roles/{role_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/roles/role_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

#### 6. Assign Permissions to Role
**POST** `/api/v1/roles/{role_id}/permissions`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/roles/role_uuid_here/permissions" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_ids": ["perm_uuid_1", "perm_uuid_2"]
  }'
```

#### 7. Remove Permissions from Role
**DELETE** `/api/v1/roles/{role_id}/permissions`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/roles/role_uuid_here/permissions" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_ids": ["perm_uuid_1", "perm_uuid_2"]
  }'
```

### Permissions (Global)
**Access:** Super Admin Only (manage) | All authenticated users (view)

#### 1. Create Permission
**POST** `/api/v1/permissions`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/permissions" \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user:create",
    "description": "Create users",
    "resource": "user",
    "action": "create"
  }'
```

#### 2. List Permissions (Grouped)
**GET** `/api/v1/permissions/grouped`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/permissions/grouped?search=&resource=&action=" \
  -H "Authorization: Bearer <access_token>"
```

#### 3. Get Permission by ID
**GET** `/api/v1/permissions/{permission_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/permissions/perm_uuid_here" \
  -H "Authorization: Bearer <access_token>"
```

#### 4. Update Permission
**PUT** `/api/v1/permissions/{permission_id}`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/permissions/perm_uuid_here" \
  -H "Authorization: Bearer <super_admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user:update",
    "description": "Update users",
    "resource": "user",
    "action": "update"
  }'
```

#### 5. Delete Permission
**DELETE** `/api/v1/permissions/{permission_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/permissions/perm_uuid_here" \
  -H "Authorization: Bearer <super_admin_token>"
```

---

## Location Management
**Access:** Super Admin (all orgs) | Organization Admin (their org only)

### 1. Create Location
**POST** `/api/v1/locations`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/locations" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Office",
    "code": "MAIN-001",
    "description": "Main office location",
    "address": "123 Business Street",
    "city": "New York",
    "state": "NY",
    "country": "USA",
    "postal_code": "10001"
  }'
```

### 2. List Locations
**GET** `/api/v1/locations`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/locations?skip=0&limit=100&search=&is_active=true" \
  -H "Authorization: Bearer <admin_token>"
```

### 3. Get Location by ID
**GET** `/api/v1/locations/{location_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/locations/location_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 4. Update Location
**PUT** `/api/v1/locations/{location_id}`

```bash
curl -X PUT "http://127.0.0.1:8000/api/v1/locations/location_uuid_here" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Main Office",
    "description": "Updated main office location",
    "address": "456 Updated Business Street",
    "city": "New York",
    "state": "NY",
    "country": "USA",
    "postal_code": "10002",
    "is_active": true
  }'
```

### 5. Delete Location
**DELETE** `/api/v1/locations/{location_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/locations/location_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 6. Assign Locations to User
**POST** `/api/v1/locations/assign`

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/locations/assign" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_uuid_here",
    "location_ids": ["location_uuid_1", "location_uuid_2"],
    "primary_location_id": "location_uuid_1"
  }'
```

### 7. Get User Locations
**GET** `/api/v1/locations/user/{user_id}`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/locations/user/user_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 8. Remove User from Location
**DELETE** `/api/v1/locations/user/{user_id}/location/{location_id}`

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/locations/user/user_uuid_here/location/location_uuid_here" \
  -H "Authorization: Bearer <admin_token>"
```

### 9. Get Location Users
**GET** `/api/v1/locations/{location_id}/users`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/locations/location_uuid_here/users?skip=0&limit=100" \
  -H "Authorization: Bearer <admin_token>"
```

---

## Audit & Logging
**Access:** Super Admin (all) | Organization users (their org data)

### 1. Get Audit Logs
**GET** `/api/v1/audit/logs`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/audit/logs?page=1&size=50&user_id=&action=&resource=&status=" \
  -H "Authorization: Bearer <access_token>"
```

### 2. Get User Activity Summary
**GET** `/api/v1/audit/user/{user_id}/activity`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/audit/user/user_uuid_here/activity?days=30" \
  -H "Authorization: Bearer <access_token>"
```

### 3. Get Organization Statistics
**GET** `/api/v1/audit/organization/{organization_id}/stats`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/audit/organization/org_uuid_here/stats?days=30" \
  -H "Authorization: Bearer <access_token>"
```

### 4. Export Audit Logs
**GET** `/api/v1/audit/export`

```bash
curl -X GET "http://127.0.0.1:8000/api/v1/audit/export?format=csv&start_date=2025-01-01&end_date=2025-12-31" \
  -H "Authorization: Bearer <access_token>"
```

---

## Health & Info
**Access:** Public

### 1. Health Check
**GET** `/health`

```bash
curl -X GET "http://127.0.0.1:8000/health"
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "environment": "development"
}
```

### 2. Root Endpoint
**GET** `/`

```bash
curl -X GET "http://127.0.0.1:8000/"
```

### 3. API Documentation
**GET** `/docs`

```bash
curl -X GET "http://127.0.0.1:8000/docs"
```

### 4. OpenAPI Schema
**GET** `/openapi.json`

```bash
curl -X GET "http://127.0.0.1:8000/openapi.json"
```

---

## Error Responses

### Common HTTP Status Codes

- **200 OK**: Successful GET request
- **201 Created**: Successful POST request (resource created)
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **422 Unprocessable Entity**: Validation error
- **500 Internal Server Error**: Server error

### Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

### Validation Error Response Format

```json
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "name"],
      "msg": "String should have at least 1 character",
      "input": "",
      "ctx": {"min_length": 1}
    }
  ]
}
```

---

## Environment Variables

Create a `.env` file with the following variables:

```env
# Database
DATABASE_URL=postgresql+asyncpg://username:password@localhost/authx_db
DATABASE_URL_SYNC=postgresql://username:password@localhost/authx_db

# Security
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# Application
APP_NAME=AuthX
APP_VERSION=1.0.0
DEBUG=true
LOG_LEVEL=INFO

# CORS
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]
```

---

## Postman Collection

Import the provided `AuthX_API_Collection.postman_collection.json` file into Postman for easy testing of all endpoints. The collection includes:

- Pre-configured requests for all endpoints
- Environment variables for tokens and IDs
- Test scripts to automatically capture response data
- Organized folders for each module

### Collection Variables

The following variables are used throughout the collection:

- `base_url`: API base URL (default: http://127.0.0.1:8000)
- `access_token`: JWT access token
- `refresh_token`: JWT refresh token
- `organization_id`: Organization UUID
- `organization_slug`: Organization slug
- `user_id`: User UUID
- `created_user_id`: Created user UUID
- `role_id`: Role UUID
- `permission_id`: Permission UUID
- `location_id`: Location UUID
- `location_code`: Location code

### Testing Workflow

1. **Setup**: Create organization (Super Admin)
2. **Auth**: Register user and login
3. **Users**: Create and manage users
4. **Roles**: Create roles and assign permissions
5. **Locations**: Create locations and assign to users
6. **Testing**: Use various endpoints to test functionality

---

This documentation provides comprehensive coverage of all AuthX API endpoints with proper access control implemented as requested. Super Admins have full access, while Organization Admins are restricted to their organization's resources only.
