# AuthX API Complete Documentation

## Table of Contents

1. [Authentication](#authentication)
2. [Organizations](#organizations)
3. [Users](#users)
4. [Roles & Permissions](#roles--permissions)
5. [Locations](#locations)
6. [Audit Logs](#audit-logs)
7. [Access Control Summary](#access-control-summary)
8. [Error Responses](#error-responses)

---

## Authentication

### 1. Login
**Endpoint:** `POST /auth/login`
**Access:** Public
**Description:** Authenticate user and get access token

**Request:**
```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com&password=password123"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 2. Get Current User Profile
**Endpoint:** `GET /auth/me`
**Access:** Authenticated users
**Description:** Get current authenticated user's profile

**Request:**
```bash
curl -X GET "http://localhost:8000/auth/me" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Response:**
```json
{
  "id": "uuid-here",
  "email": "admin@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "is_super_admin": true,
  "organization_id": "org-uuid",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### 3. Refresh Token
**Endpoint:** `POST /auth/refresh`
**Access:** Authenticated users
**Description:** Refresh access token

**Request:**
```bash
curl -X POST "http://localhost:8000/auth/refresh" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

---

## Organizations

### 1. Create Organization
**Endpoint:** `POST /organizations`
**Access:** Super Admin only
**Description:** Create a new organization

**Request:**
```bash
curl -X POST "http://localhost:8000/organizations" \
  -H "Authorization: Bearer YOUR_SUPER_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "description": "A sample organization",
    "max_users": 100
  }'
```

**Response:**
```json
{
  "id": "org-uuid",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "description": "A sample organization",
  "max_users": 100,
  "is_active": true,
  "locations": [],
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### 2. List Organizations
**Endpoint:** `GET /organizations`
**Access:** 
- Super Admin: Can see all organizations
- Organization Users: Can only see their own organization

**Request (Super Admin):**
```bash
curl -X GET "http://localhost:8000/organizations?page=1&size=20&is_active=true&search=acme" \
  -H "Authorization: Bearer YOUR_SUPER_ADMIN_TOKEN"
```

**Request (Organization User):**
```bash
curl -X GET "http://localhost:8000/organizations" \
  -H "Authorization: Bearer YOUR_ORG_USER_TOKEN"
```

**Response:**
```json
[
  {
    "id": "org-uuid",
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "description": "A sample organization",
    "max_users": 100,
    "is_active": true,
    "locations": [
      {
        "id": "location-uuid",
        "name": "Main Office",
        "code": "MAIN",
        "is_active": true
      }
    ],
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
]
```

### 3. Get Organization by ID
**Endpoint:** `GET /organizations/{organization_id}`
**Access:**
- Super Admin: Can access any organization
- Organization Users: Can only access their own organization

**Request:**
```bash
curl -X GET "http://localhost:8000/organizations/org-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Update Organization
**Endpoint:** `PUT /organizations/{organization_id}`
**Access:**
- Super Admin: Can update any organization
- Organization Admin: Can only update their own organization

**Request:**
```bash
curl -X PUT "http://localhost:8000/organizations/org-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Acme Corporation",
    "description": "Updated description",
    "max_users": 200,
    "is_active": true
  }'
```

### 5. Delete Organization
**Endpoint:** `DELETE /organizations/{organization_id}`
**Access:** Super Admin only

**Request:**
```bash
curl -X DELETE "http://localhost:8000/organizations/org-uuid" \
  -H "Authorization: Bearer YOUR_SUPER_ADMIN_TOKEN"
```

### 6. Get Organization Statistics
**Endpoint:** `GET /organizations/{org_id}/stats`
**Access:**
- Super Admin: Can access any organization stats
- Organization Users: Can only access their own organization stats

**Request:**
```bash
curl -X GET "http://localhost:8000/organizations/org-uuid/stats" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "organization_id": "org-uuid",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "is_active": true,
  "max_users": 100,
  "active_users": 25,
  "total_users": 30,
  "total_roles": 3,
  "user_capacity_percentage": 25.0
}
```

### 7. Get My Organization
**Endpoint:** `GET /organizations/my/info`
**Access:** Organization users only

**Request:**
```bash
curl -X GET "http://localhost:8000/organizations/my/info" \
  -H "Authorization: Bearer YOUR_ORG_USER_TOKEN"
```

---

## Users

### 1. Create User
**Endpoint:** `POST /users`
**Access:**
- Super Admin: Can create users in any organization
- Organization Admin: Can create users in their organization

**Request:**
```bash
curl -X POST "http://localhost:8000/users" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "first_name": "Jane",
    "last_name": "Smith",
    "organization_id": "org-uuid",
    "role_ids": ["role-uuid"]
  }'
```

### 2. List Users
**Endpoint:** `GET /users`
**Access:**
- Super Admin: Can see all users
- Organization Users: Can only see users in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/users?page=1&size=20&is_active=true&organization_id=org-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Get User by ID
**Endpoint:** `GET /users/{user_id}`
**Access:**
- Super Admin: Can access any user
- Organization Users: Can only access users in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/users/user-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Update User
**Endpoint:** `PUT /users/{user_id}`
**Access:**
- Super Admin: Can update any user
- Organization Admin: Can update users in their organization

**Request:**
```bash
curl -X PUT "http://localhost:8000/users/user-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Updated Jane",
    "last_name": "Updated Smith",
    "is_active": true
  }'
```

### 5. Delete User
**Endpoint:** `DELETE /users/{user_id}`
**Access:**
- Super Admin: Can delete any user
- Organization Admin: Can delete users in their organization

**Request:**
```bash
curl -X DELETE "http://localhost:8000/users/user-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Roles & Permissions

### 1. Create Role
**Endpoint:** `POST /roles`
**Access:**
- Super Admin: Can create roles in any organization
- Organization Admin: Can create roles in their organization

**Request:**
```bash
curl -X POST "http://localhost:8000/roles" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Manager",
    "description": "Manager role with specific permissions",
    "organization_id": "org-uuid",
    "permission_ids": ["perm-uuid-1", "perm-uuid-2"]
  }'
```

### 2. List Roles
**Endpoint:** `GET /roles`
**Access:**
- Super Admin: Can see all roles
- Organization Users: Can only see roles in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/roles?organization_id=org-uuid&is_active=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Get Role by ID
**Endpoint:** `GET /roles/{role_id}`
**Access:**
- Super Admin: Can access any role
- Organization Users: Can only access roles in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/roles/role-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Update Role
**Endpoint:** `PUT /roles/{role_id}`
**Access:**
- Super Admin: Can update any role
- Organization Admin: Can update roles in their organization

**Request:**
```bash
curl -X PUT "http://localhost:8000/roles/role-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Manager",
    "description": "Updated manager role",
    "permission_ids": ["perm-uuid-1", "perm-uuid-2", "perm-uuid-3"]
  }'
```

### 5. Delete Role
**Endpoint:** `DELETE /roles/{role_id}`
**Access:**
- Super Admin: Can delete any role
- Organization Admin: Can delete roles in their organization

**Request:**
```bash
curl -X DELETE "http://localhost:8000/roles/role-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 6. List Permissions
**Endpoint:** `GET /roles/permissions`
**Access:** All authenticated users

**Request:**
```bash
curl -X GET "http://localhost:8000/roles/permissions" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Locations

### 1. Create Location
**Endpoint:** `POST /locations`
**Access:**
- Super Admin: Can create locations in any organization
- Organization Admin: Can create locations in their organization

**Request:**
```bash
curl -X POST "http://localhost:8000/locations" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Office",
    "code": "MAIN",
    "description": "Main office location",
    "address": "123 Main St",
    "city": "New York",
    "state": "NY",
    "country": "USA",
    "postal_code": "10001",
    "organization_id": "org-uuid"
  }'
```

### 2. List Locations
**Endpoint:** `GET /locations`
**Access:**
- Super Admin: Can see all locations
- Organization Users: Can only see locations in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/locations?organization_id=org-uuid&is_active=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Get Location by ID
**Endpoint:** `GET /locations/{location_id}`
**Access:**
- Super Admin: Can access any location
- Organization Users: Can only access locations in their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/locations/location-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Update Location
**Endpoint:** `PUT /locations/{location_id}`
**Access:**
- Super Admin: Can update any location
- Organization Admin: Can update locations in their organization

**Request:**
```bash
curl -X PUT "http://localhost:8000/locations/location-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Main Office",
    "description": "Updated main office location",
    "address": "456 Updated St",
    "is_active": true
  }'
```

### 5. Delete Location
**Endpoint:** `DELETE /locations/{location_id}`
**Access:**
- Super Admin: Can delete any location
- Organization Admin: Can delete locations in their organization

**Request:**
```bash
curl -X DELETE "http://localhost:8000/locations/location-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 6. Assign Locations to User
**Endpoint:** `POST /locations/assign`
**Access:**
- Super Admin: Can assign any locations
- Organization Admin: Can assign locations in their organization

**Request:**
```bash
curl -X POST "http://localhost:8000/locations/assign" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-uuid",
    "location_ids": ["location-uuid-1", "location-uuid-2"],
    "primary_location_id": "location-uuid-1"
  }'
```

---

## Audit Logs

### 1. List Audit Logs
**Endpoint:** `GET /audit`
**Access:**
- Super Admin: Can see all audit logs
- Organization Users: Can only see audit logs for their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/audit?page=1&size=20&organization_id=org-uuid&action=user_created&resource=user" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Get Audit Log by ID
**Endpoint:** `GET /audit/{audit_id}`
**Access:**
- Super Admin: Can access any audit log
- Organization Users: Can only access audit logs for their organization

**Request:**
```bash
curl -X GET "http://localhost:8000/audit/audit-uuid" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Access Control Summary

| Role | Organizations | Users | Roles | Locations | Permissions | Audit Logs |
|------|---------------|-------|-------|-----------|-------------|------------|
| **Super Admin** | Full access to all organizations | Full access to all users | Full access to all roles | Full access to all locations | Read-only access to all permissions | Full access to all audit logs |
| **Organization Admin** | Read/Update own organization only | Full access to users in own org | Full access to roles in own org | Full access to locations in own org | Read-only access to all permissions | Read access to own org audit logs |
| **Organization User** | Read own organization only | Read users in own org | Read roles in own org | Read locations in own org | Read-only access to all permissions | Read access to own org audit logs |

---

## Error Responses

### Common HTTP Status Codes

| Status Code | Description | Example Response |
|-------------|-------------|------------------|
| **400** | Bad Request | `{"detail": "Invalid input data"}` |
| **401** | Unauthorized | `{"detail": "Not authenticated"}` |
| **403** | Forbidden | `{"detail": "Access denied. Insufficient permissions"}` |
| **404** | Not Found | `{"detail": "Resource not found"}` |
| **422** | Validation Error | `{"detail": [{"loc": ["body", "email"], "msg": "field required", "type": "value_error.missing"}]}` |
| **500** | Internal Server Error | `{"detail": "Internal server error"}` |

### Authentication Errors

**Invalid Credentials:**
```json
{
  "detail": "Incorrect email or password"
}
```

**Token Expired:**
```json
{
  "detail": "Token has expired"
}
```

**Invalid Token:**
```json
{
  "detail": "Could not validate credentials"
}
```

### Access Control Errors

**Organization Access Denied:**
```json
{
  "detail": "Access denied. You can only access your own organization."
}
```

**Super Admin Required:**
```json
{
  "detail": "Super admin access required"
}
```

**Organization Admin Required:**
```json
{
  "detail": "Organization admin access required"
}
```

---

## Environment Setup

### Base URL
- Development: `http://localhost:8000`
- Production: `https://your-domain.com`

### Headers Required
- **Authorization:** `Bearer YOUR_JWT_TOKEN` (for authenticated endpoints)
- **Content-Type:** `application/json` (for POST/PUT requests)

### Getting Started

1. **Start the server:**
   ```bash
   uvicorn main:app --reload
   ```

2. **Create first super admin user** (via database or admin command)

3. **Login to get token:**
   ```bash
   curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin@example.com&password=password123"
   ```

4. **Use the token in subsequent requests:**
   ```bash
   export TOKEN="your-jwt-token-here"
   curl -X GET "http://localhost:8000/auth/me" \
     -H "Authorization: Bearer $TOKEN"
   ```

This documentation provides comprehensive coverage of all API endpoints with proper access control implementation as requested.
