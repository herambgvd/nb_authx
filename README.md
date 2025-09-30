# AuthX - Multi-tenant Authentication and Authorization Service

A production-ready FastAPI application providing comprehensive authentication and authorization with organization-scoped user management.

## Features

### ✅ Completed Core Features

1. **Authentication System**
   - User registration, login, logout
   - JWT access tokens with refresh tokens
   - Password reset functionality
   - Account lockout protection
   - Session management

2. **Organization Management (CRUD)**
   - Create, read, update, delete organizations
   - Organization-scoped user management
   - Configurable user limits per organization

3. **Super Admin Capabilities**
   - Global access to all organizations
   - Permission and role management
   - System-wide administration

4. **User Management**
   - Organization-scoped user CRUD
   - User activation/deactivation
   - Role assignment
   - Password management

5. **Organization Admin Features**
   - User onboarding within organization
   - Organization-scoped user management
   - Role and permission assignment

6. **Roles and Permissions**
   - Organization-scoped role management
   - Granular permission system
   - Role-based access control (RBAC)
   - Permission inheritance

7. **Audit and Logging**
   - Comprehensive audit trail
   - Security event monitoring
   - User activity tracking
   - Organization activity summaries

## Project Structure

```
authx/
├── app/
│   ├── __init__.py
│   ├── config.py              # Application configuration
│   ├── database.py            # Database connection setup
│   ├── dependencies.py        # FastAPI dependencies
│   ├── models.py              # SQLAlchemy models
│   ├── schemas.py             # Pydantic schemas
│   ├── security.py            # Security utilities
│   ├── routers/               # API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── organizations.py   # Organization management
│   │   ├── users.py           # User management
│   │   ├── roles.py           # Roles & permissions
│   │   └── audit.py           # Audit & logging
│   ├── services/              # Business logic layer
│   │   ├── __init__.py
│   │   ├── auth_service.py    # Authentication logic
│   │   ├── organization_service.py
│   │   ├── user_service.py
│   │   ├── role_service.py
│   │   └── audit_service.py
│   └── utils/                 # Utility functions
│       ├── __init__.py
│       └── db_init.py         # Database initialization
├── migrations/                # Alembic migrations
├── main.py                    # FastAPI application
├── manage.py                  # CLI management script
├── alembic.ini               # Alembic configuration
├── pyproject.toml            # Project dependencies
└── .env.example              # Environment variables template
```

## Technology Stack

- **Framework**: FastAPI with async/await
- **Database**: PostgreSQL with SQLAlchemy 2.0 (async)
- **Authentication**: JWT tokens with refresh token rotation
- **Password Hashing**: Argon2
- **Migrations**: Alembic (sync mode)
- **Validation**: Pydantic v2
- **Security**: Comprehensive RBAC system

## Setup and Installation

### 1. Environment Setup

```bash
# Clone the repository
cd /path/to/authx

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .
```

### 2. Database Configuration

```bash
# Copy environment file
cp .env.example .env

# Edit .env with your database credentials
# Required variables:
# DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/authx_db
# DATABASE_URL_SYNC=postgresql://user:password@localhost:5432/authx_db
# SECRET_KEY=your-super-secret-key-change-this-in-production
```

### 3. Database Setup

```bash
# Initialize database with default data
python manage.py init-db

# Or step by step:
python manage.py create-tables
python manage.py create-permissions
python manage.py create-superuser
```

### 4. Run the Application

```bash
# Development server
python manage.py runserver

# Or directly with uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints Overview

### Authentication (`/api/v1/auth`)
- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /refresh` - Token refresh
- `POST /logout` - User logout
- `POST /forgot-password` - Password reset request
- `POST /reset-password` - Password reset
- `POST /change-password` - Change password
- `GET /me` - Current user info

### Organizations (`/api/v1/organizations`)
- `POST /` - Create organization (Super Admin)
- `GET /` - List organizations (Super Admin)
- `GET /{org_id}` - Get organization (Super Admin)
- `PUT /{org_id}` - Update organization (Super Admin)
- `DELETE /{org_id}` - Delete organization (Super Admin)
- `GET /my/info` - Current user's organization

### Users (`/api/v1/users`)
- `POST /` - Create user
- `GET /` - List users
- `GET /{user_id}` - Get user
- `PUT /{user_id}` - Update user
- `DELETE /{user_id}` - Delete user
- `POST /{user_id}/roles` - Assign roles
- `GET /{user_id}/roles` - Get user roles

### Roles & Permissions (`/api/v1/roles`, `/api/v1/permissions`)
- `POST /roles` - Create role
- `GET /roles` - List roles
- `PUT /roles/{role_id}` - Update role
- `DELETE /roles/{role_id}` - Delete role
- `POST /roles/{role_id}/permissions` - Assign permissions
- `GET /permissions` - List permissions

### Audit & Logging (`/api/v1/audit`)
- `GET /logs` - Get audit logs
- `GET /user/{user_id}/activity` - User activity summary
- `GET /organization/activity` - Organization activity
- `GET /security-events` - Security events

## Management CLI

The `manage.py` script provides useful commands:

```bash
# Database operations
python manage.py init-db          # Initialize with default data
python manage.py create-tables    # Create database tables
python manage.py drop-db          # Drop all tables (DANGEROUS)
python manage.py reset-db         # Reset database completely

# User management
python manage.py create-superuser # Create super admin user

# Server operations
python manage.py runserver        # Start development server
python manage.py check-db         # Check database status
```

## Security Features

### Authentication
- JWT tokens with configurable expiration
- Refresh token rotation
- Account lockout after failed attempts
- Password strength validation
- Secure password hashing with Argon2

### Authorization
- Role-based access control (RBAC)
- Organization-scoped permissions
- Granular permission system
- Super admin bypass capabilities

### Audit & Monitoring
- Comprehensive audit logging
- Security event tracking
- User activity monitoring
- Failed login attempt tracking

## Default Roles

Each organization gets these default roles:

1. **Admin** - Full access to organization resources
2. **Manager** - User and role management access
3. **Member** - Basic read access to users and roles
4. **Viewer** - Read-only access to users

## Default Permissions

The system includes permissions for:
- User management (create, read, update, delete)
- Role management (create, read, update, delete, assign)
- Permission management (create, read, update, delete, assign)
- Organization management (create, read, update, delete)
- Audit log access (read, export, delete)

## Production Deployment

### Environment Variables
Ensure these are set in production:
```bash
DEBUG=false
SECRET_KEY=<strong-secret-key>
DATABASE_URL=<production-db-url>
LOG_LEVEL=INFO
```

### Database Migrations
```bash
# Generate migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head
```

### Security Considerations
1. Use strong SECRET_KEY
2. Configure CORS properly
3. Use HTTPS in production
4. Set up proper logging
5. Monitor audit logs
6. Regular security updates

## Development

### Code Organization
- **Models**: SQLAlchemy models with proper relationships
- **Schemas**: Pydantic models for validation
- **Services**: Business logic layer
- **Routers**: API endpoint definitions
- **Dependencies**: Authentication and authorization
- **Security**: Cryptographic operations

### Testing
The codebase is organized for easy testing with proper separation of concerns.

## License

This project is licensed under the MIT License.
