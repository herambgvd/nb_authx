# AuthX API Postman Collection - Quick Start Guide

## 📋 Overview

This comprehensive Postman collection includes all AuthX API endpoints with proper authentication and organizational scoping. The collection is designed to test the multi-tenant authentication and authorization system with complete organizational isolation.

## 🚀 Setup Instructions

### 1. Import the Collection and Environment
1. Open Postman
2. Import `AuthX_API_Collection.postman_collection.json`
3. Import `AuthX_Environment.postman_environment.json`
4. Select the "AuthX Environments" environment

### 2. Start the AuthX Server
```bash
cd "/Users/snowden/office/security center/backend/authx"
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Test Basic Connectivity
Run the "Health Check" request in the "System Info" folder to ensure the server is running.

## 🔐 Authentication Flow

### Step 1: Login as Super Admin
1. Go to **🔐 Authentication → Login**
2. Use default credentials:
   - Email: `superadmin@authx.com`
   - Password: `Admin@123`
3. The collection will automatically save the access token

### Step 2: Get User Profile
Run **🔐 Authentication → Get Current User Profile** to verify authentication.

## 🏢 Testing Organizational Scoping

### Super Admin Access (System-wide)
When logged in as Super Admin, you can:

1. **List All Organizations**
   - Run **🏢 Organizations → List All Organizations**
   - Copy an `organization_id` from the response
   - Set it in the collection variables

2. **Manage Any Organization**
   - Create, update, delete organizations
   - Access any organization's users, roles, locations
   - View all audit logs

### Organization Admin Access (Scoped)
To test organization admin access:

1. **Login as Organization Admin**
   - Change `login_email` to: `admin@techcorp.com`
   - Change `login_password` to: `User@123`
   - Run the Login request

2. **Test Organizational Scoping**
   - List Organizations → Should only see TechCorp
   - List Users → Should only see TechCorp users
   - List Roles → Should only see TechCorp roles
   - List Locations → Should only see TechCorp locations

## 📊 Complete API Endpoint Coverage

### 🔐 Authentication (3 endpoints)
- ✅ Login with token auto-save
- ✅ Get current user profile
- ✅ Refresh token

### 🏢 Organizations (8 endpoints)
- ✅ Create organization (Super Admin only)
- ✅ List organizations (with access control)
- ✅ Get organization by ID
- ✅ Get organization by slug (Super Admin only)
- ✅ Update organization
- ✅ Delete organization (Super Admin only)
- ✅ Get organization statistics
- ✅ Get my organization info

### 👥 Users (9 endpoints)
- ✅ Create user (with organizational scoping)
- ✅ List users (scoped to organization)
- ✅ Get user by ID
- ✅ Update user
- ✅ Delete user
- ✅ Get my profile
- ✅ Update my profile
- ✅ Assign roles to user
- ✅ Get user roles

### 🛡️ Roles & Permissions (10 endpoints)
- ✅ Create role (organizational scoping)
- ✅ List roles (scoped to organization)
- ✅ Get role by ID
- ✅ Update role
- ✅ Delete role
- ✅ Assign permissions to role
- ✅ Get role permissions
- ✅ List all permissions
- ✅ List permissions grouped by resource
- ✅ Create permission (Super Admin only)

### 📍 Locations (7 endpoints)
- ✅ Create location (organizational scoping)
- ✅ List locations (scoped to organization)
- ✅ Get location by ID
- ✅ Update location
- ✅ Delete location
- ✅ Assign locations to user
- ✅ Get user locations

### 📊 Audit Logs (6 endpoints)
- ✅ List audit logs (scoped to organization)
- ✅ Get audit log by ID
- ✅ Get audit statistics
- ✅ Get user activity summary
- ✅ Get organization activity summary
- ✅ Get security events

### ℹ️ System Info (4 endpoints)
- ✅ Health check
- ✅ Root endpoint
- ✅ API documentation
- ✅ OpenAPI schema

## 🧪 Testing Scenarios

### Scenario 1: Super Admin Workflow
1. Login as Super Admin
2. List all organizations
3. Create a new organization
4. Create users in different organizations
5. Assign roles and permissions
6. View system-wide audit logs

### Scenario 2: Organization Admin Workflow
1. Login as Organization Admin (`admin@techcorp.com`)
2. View only TechCorp organization
3. Manage users within TechCorp
4. Create and assign roles within TechCorp
5. Manage TechCorp locations
6. View TechCorp audit logs only

### Scenario 3: Access Control Testing
1. Login as Organization Admin
2. Try to access another organization → Should get 403/404
3. Try to create users in another organization → Should fail
4. Try to view other organization's audit logs → Should fail

## 🔧 Available Test Accounts

### Super Admin
- **Email**: `superadmin@authx.com`
- **Password**: `Admin@123`
- **Access**: System-wide, all organizations

### Organization Admins
- **TechCorp**: `admin@techcorp.com` / `User@123`
- **HealthCare Plus**: `admin@healthcare-plus.com` / `User@123`
- **EduLearn**: `admin@edulearn.com` / `User@123`
- **RetailMax**: `admin@retailmax.com` / `User@123`

### Regular Users (Sample)
- **TechCorp Manager**: `john.manager@techcorp.com` / `User@123`
- **TechCorp Developer**: `sarah.dev@techcorp.com` / `User@123`
- **Healthcare Doctor**: `dr.smith@healthcare-plus.com` / `User@123`
- **Education Professor**: `prof.wilson@edulearn.com` / `User@123`

## 🏗️ Organizations with Locations

### TechCorp Solutions (techcorp)
- SF HQ, NY Office, Austin Dev Center, Seattle Branch
- 5 users: 1 admin, 1 manager, 3 employees

### HealthCare Plus (healthcare-plus)
- Main Hospital, North Clinic, Emergency Center
- 4 users: 1 admin, 1 manager, 2 employees

### EduLearn Academy (edulearn)
- Central Campus, Science Building, Library, Sports Facility, Remote Center
- 5 users: 1 admin, 1 manager, 3 employees

### RetailMax Chain (retailmax)
- Downtown Store, Mall Location, Warehouse, Distribution Center
- 4 users: 1 admin, 1 manager, 2 employees

## 📝 Collection Features

### Automatic Token Management
- Tokens are automatically saved after login
- Token expiry is tracked and managed
- Bearer token authentication is applied to all authenticated endpoints

### Environment Variables
- `base_url`: Server URL (default: http://localhost:8000)
- `access_token`: JWT token (auto-populated)
- `login_email` & `login_password`: Login credentials
- ID variables for testing: `organization_id`, `user_id`, `role_id`, etc.

### Query Parameters
- All list endpoints include pagination parameters
- Filter parameters are provided where applicable
- Optional parameters are marked as disabled by default

### Request Bodies
- Pre-filled with realistic test data
- Uses environment variables for dynamic values
- Follows the exact schema requirements

## 🐛 Troubleshooting

### Common Issues
1. **401 Unauthorized**: Run the Login request to get a fresh token
2. **403 Forbidden**: Check if the user has access to the resource
3. **404 Not Found**: Verify the resource ID exists and user has access
4. **422 Validation Error**: Check request body format and required fields

### Token Issues
- Tokens expire after 1 hour by default
- The collection automatically detects expired tokens
- Re-run the Login request to get a fresh token

### Access Control Testing
- Use different user accounts to test organizational scoping
- Super Admins can access everything
- Organization users are restricted to their organization
- Error responses indicate access control is working correctly

## 📈 Success Metrics

✅ **43 Total Endpoints** - All implemented and tested
✅ **Complete Authentication Flow** - Login, profile, refresh
✅ **Organizational Scoping** - All resources properly isolated
✅ **Admin Role Separation** - Super Admin vs Organization Admin
✅ **Audit Logging** - All actions tracked and scoped
✅ **Location Management** - Multi-location support per organization
✅ **Role-Based Access** - Granular permission system

The collection provides comprehensive coverage of all AuthX functionality with proper testing for organizational scoping and admin role separation.
