"""
Seed script to populate the database with test data.
This script will create test organizations, users, locations, roles, and other entities.
"""
import asyncio
import uuid
import random
import string
import json
from datetime import datetime, timedelta
import argparse
import httpx
from typing import Dict, List, Any

# Base URL for the API
BASE_URL = "http://localhost:8000/api/v1"

# Admin credentials for authentication
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Admin@123"

# Number of entities to create
NUM_ORGANIZATIONS = 2
NUM_USERS_PER_ORG = 5
NUM_LOCATIONS_PER_ORG = 3
NUM_ROLES_PER_ORG = 3
NUM_PERMISSIONS = 10

# Token storage
access_token = None


async def login_admin():
    """Login as admin and get access token."""
    global access_token
    
    url = f"{BASE_URL}/auth/token"
    data = {
        "username": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, data=data)
        
        if response.status_code != 200:
            print(f"Failed to login: {response.text}")
            return False
        
        result = response.json()
        access_token = result.get("access_token")
        
        print(f"Admin login successful. Token: {access_token[:10]}...")
        return True


async def create_organizations() -> List[Dict[str, Any]]:
    """Create test organizations."""
    organizations = []
    headers = {"Authorization": f"Bearer {access_token}"}
    
    for i in range(NUM_ORGANIZATIONS):
        org_name = f"Test Organization {i+1}"
        org_domain = f"org{i+1}.example.com"
        
        org_data = {
            "name": org_name,
            "display_name": org_name,
            "domain": org_domain,
            "description": f"Test organization {i+1} for API testing",
            "contact_email": f"contact@{org_domain}",
            "contact_phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
            "subscription_plan": random.choice(["free", "basic", "premium"]),
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/organizations",
                json=org_data,
                headers=headers
            )
            
            if response.status_code == 201:
                org = response.json()
                organizations.append(org)
                print(f"Created organization: {org['name']} (ID: {org['id']})")
                
                # Create organization settings
                settings_data = {
                    "security": {
                        "password_min_length": 8,
                        "password_require_uppercase": True,
                        "password_require_lowercase": True,
                        "password_require_number": True,
                        "password_require_special": False,
                        "password_expiry_days": 90,
                        "login_attempt_limit": 5,
                        "mfa_required": False,
                        "allowed_ip_ranges": [],
                        "session_timeout_minutes": 60
                    },
                    "branding": {
                        "logo_url": f"https://example.com/{org_domain}/logo.png",
                        "primary_color": "#336699",
                        "secondary_color": "#FF9900"
                    },
                    "notifications": {
                        "email_notifications_enabled": True,
                        "security_alert_contacts": [f"alerts@{org_domain}"]
                    }
                }
                
                await client.patch(
                    f"{BASE_URL}/organizations/{org['id']}/settings",
                    json=settings_data,
                    headers=headers
                )
                
                # Verify organization
                await client.post(
                    f"{BASE_URL}/organizations/{org['id']}/verification/approve",
                    headers=headers
                )
            else:
                print(f"Failed to create organization: {response.text}")
    
    return organizations


async def create_locations(organizations: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Create test locations for each organization."""
    headers = {"Authorization": f"Bearer {access_token}"}
    locations_by_org = {}
    
    for org in organizations:
        org_id = org["id"]
        locations = []
        
        # Create main HQ location
        hq_data = {
            "name": f"{org['name']} Headquarters",
            "code": "HQ",
            "description": "Main headquarters location",
            "organization_id": org_id,
            "address_line1": f"{random.randint(100, 999)} Main Street",
            "city": "San Francisco",
            "state": "CA",
            "postal_code": "94105",
            "country": "United States",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "contact_name": "HQ Manager",
            "contact_email": f"hq@{org['domain']}",
            "contact_phone": "+1-555-000-0000",
            "is_active": True
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/locations",
                json=hq_data,
                headers=headers
            )
            
            if response.status_code == 201:
                hq = response.json()
                locations.append(hq)
                print(f"Created HQ location for {org['name']}: {hq['name']} (ID: {hq['id']})")
                
                # Create branch locations with parent_id as HQ
                for i in range(NUM_LOCATIONS_PER_ORG - 1):
                    city = random.choice(["New York", "Chicago", "Los Angeles", "Miami", "Austin"])
                    state = random.choice(["NY", "IL", "CA", "FL", "TX"])
                    
                    branch_data = {
                        "name": f"{org['name']} {city} Branch",
                        "code": f"BR-{city[:2].upper()}{i+1}",
                        "description": f"Branch office in {city}",
                        "organization_id": org_id,
                        "parent_id": hq["id"],
                        "address_line1": f"{random.randint(100, 999)} {random.choice(['Park', 'Broadway', 'Main', 'Lake'])} Avenue",
                        "city": city,
                        "state": state,
                        "postal_code": f"{random.randint(10000, 99999)}",
                        "country": "United States",
                        "latitude": random.uniform(25.0, 45.0),
                        "longitude": random.uniform(-75.0, -125.0),
                        "contact_name": f"{city} Manager",
                        "contact_email": f"{city.lower()}@{org['domain']}",
                        "contact_phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
                        "is_active": True
                    }
                    
                    response = await client.post(
                        f"{BASE_URL}/locations",
                        json=branch_data,
                        headers=headers
                    )
                    
                    if response.status_code == 201:
                        branch = response.json()
                        locations.append(branch)
                        print(f"Created branch location for {org['name']}: {branch['name']} (ID: {branch['id']})")
                    else:
                        print(f"Failed to create branch location: {response.text}")
                
                # Create location group
                group_data = {
                    "name": f"{org['name']} All Locations",
                    "description": "Group containing all locations",
                    "organization_id": org_id,
                    "location_ids": [loc["id"] for loc in locations]
                }
                
                response = await client.post(
                    f"{BASE_URL}/locations/groups",
                    json=group_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    group = response.json()
                    print(f"Created location group for {org['name']}: {group['name']} (ID: {group['id']})")
                else:
                    print(f"Failed to create location group: {response.text}")
            
            else:
                print(f"Failed to create HQ location: {response.text}")
        
        locations_by_org[org_id] = locations
    
    return locations_by_org


async def create_permissions() -> List[Dict[str, Any]]:
    """Create standard permissions."""
    headers = {"Authorization": f"Bearer {access_token}"}
    permissions = []
    
    resources = ["users", "organizations", "locations", "roles", "permissions", "reports", "settings", "audit_logs"]
    actions = ["create", "read", "update", "delete", "list"]
    
    async with httpx.AsyncClient() as client:
        for resource in resources:
            for action in actions:
                perm_data = {
                    "name": f"{action}:{resource}",
                    "description": f"Ability to {action} {resource}",
                    "resource": resource,
                    "action": action,
                    "is_system_permission": True
                }
                
                response = await client.post(
                    f"{BASE_URL}/rbac/permissions",
                    json=perm_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    perm = response.json()
                    permissions.append(perm)
                    print(f"Created permission: {perm['name']} (ID: {perm['id']})")
                else:
                    print(f"Failed to create permission: {response.text}")
    
    return permissions


async def create_roles(organizations: List[Dict[str, Any]], 
                      permissions: List[Dict[str, Any]], 
                      locations_by_org: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    """Create roles for each organization."""
    headers = {"Authorization": f"Bearer {access_token}"}
    roles_by_org = {}
    
    for org in organizations:
        org_id = org["id"]
        roles = []
        
        # Create Admin role
        admin_perms = [p["id"] for p in permissions]
        
        admin_role_data = {
            "name": "Admin",
            "description": "Organization administrator with full access",
            "organization_id": org_id,
            "is_system_role": True,
            "permission_ids": admin_perms
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/rbac/roles",
                json=admin_role_data,
                headers=headers
            )
            
            if response.status_code == 201:
                admin_role = response.json()
                roles.append(admin_role)
                print(f"Created Admin role for {org['name']} (ID: {admin_role['id']})")
                
                # Create User role (read-only)
                user_perms = [p["id"] for p in permissions if p["action"] == "read" or p["action"] == "list"]
                
                user_role_data = {
                    "name": "User",
                    "description": "Regular user with read-only access",
                    "organization_id": org_id,
                    "is_system_role": True,
                    "permission_ids": user_perms
                }
                
                response = await client.post(
                    f"{BASE_URL}/rbac/roles",
                    json=user_role_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    user_role = response.json()
                    roles.append(user_role)
                    print(f"Created User role for {org['name']} (ID: {user_role['id']})")
                else:
                    print(f"Failed to create User role: {response.text}")
                
                # Create Location Manager role
                if org_id in locations_by_org and locations_by_org[org_id]:
                    location = locations_by_org[org_id][0]
                    
                    location_perms = [
                        p["id"] for p in permissions 
                        if p["resource"] in ["locations", "users"] and p["action"] in ["read", "update", "list"]
                    ]
                    
                    location_role_data = {
                        "name": "Location Manager",
                        "description": "Manager for specific locations",
                        "organization_id": org_id,
                        "is_system_role": False,
                        "is_location_specific": True,
                        "location_id": location["id"],
                        "permission_ids": location_perms
                    }
                    
                    response = await client.post(
                        f"{BASE_URL}/rbac/roles",
                        json=location_role_data,
                        headers=headers
                    )
                    
                    if response.status_code == 201:
                        location_role = response.json()
                        roles.append(location_role)
                        print(f"Created Location Manager role for {org['name']} (ID: {location_role['id']})")
                    else:
                        print(f"Failed to create Location Manager role: {response.text}")
            else:
                print(f"Failed to create Admin role: {response.text}")
        
        roles_by_org[org_id] = roles
    
    return roles_by_org


async def create_users(organizations: List[Dict[str, Any]], 
                      roles_by_org: Dict[str, List[Dict[str, Any]]],
                      locations_by_org: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    """Create users for each organization."""
    headers = {"Authorization": f"Bearer {access_token}"}
    users_by_org = {}
    
    for org in organizations:
        org_id = org["id"]
        users = []
        
        if org_id not in roles_by_org or not roles_by_org[org_id]:
            print(f"No roles found for organization {org_id}, skipping user creation")
            continue
        
        # Get roles for this organization
        admin_role = next((r for r in roles_by_org[org_id] if r["name"] == "Admin"), None)
        user_role = next((r for r in roles_by_org[org_id] if r["name"] == "User"), None)
        location_role = next((r for r in roles_by_org[org_id] if r["name"] == "Location Manager"), None)
        
        # Get locations for this organization
        locations = locations_by_org.get(org_id, [])
        default_location = locations[0] if locations else None
        
        # Create admin user
        admin_data = {
            "email": f"admin@{org['domain']}",
            "password": "Password123!",
            "username": f"admin.{org['domain'].split('.')[0]}",
            "first_name": "Admin",
            "last_name": f"{org['name'].split()[-1]}",
            "organization_id": org_id,
            "is_active": True,
            "is_verified": True,
            "default_location_id": default_location["id"] if default_location else None,
            "role_ids": [admin_role["id"]] if admin_role else []
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_URL}/users",
                json=admin_data,
                headers=headers
            )
            
            if response.status_code == 201:
                admin_user = response.json()
                users.append(admin_user)
                print(f"Created admin user for {org['name']}: {admin_user['email']} (ID: {admin_user['id']})")
                
                # Create regular users
                for i in range(NUM_USERS_PER_ORG - 1):
                    first_name = random.choice(["John", "Jane", "Michael", "Emily", "David", "Sarah", "Robert", "Lisa"])
                    last_name = random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"])
                    email = f"{first_name.lower()}.{last_name.lower()}@{org['domain']}"
                    
                    # Assign different roles
                    if i == 0 and location_role:
                        # Location manager
                        role_ids = [location_role["id"]]
                        location_id = locations[1]["id"] if len(locations) > 1 else default_location["id"]
                    else:
                        # Regular user
                        role_ids = [user_role["id"]] if user_role else []
                        location_id = default_location["id"] if default_location else None
                    
                    user_data = {
                        "email": email,
                        "password": "Password123!",
                        "username": f"{first_name.lower()}.{last_name.lower()}",
                        "first_name": first_name,
                        "last_name": last_name,
                        "organization_id": org_id,
                        "is_active": True,
                        "is_verified": True,
                        "default_location_id": location_id,
                        "role_ids": role_ids
                    }
                    
                    response = await client.post(
                        f"{BASE_URL}/users",
                        json=user_data,
                        headers=headers
                    )
                    
                    if response.status_code == 201:
                        user = response.json()
                        users.append(user)
                        print(f"Created user for {org['name']}: {user['email']} (ID: {user['id']})")
                    else:
                        print(f"Failed to create user: {response.text}")
            else:
                print(f"Failed to create admin user: {response.text}")
        
        users_by_org[org_id] = users
    
    return users_by_org


async def create_audit_logs(users_by_org: Dict[str, List[Dict[str, Any]]]):
    """Create sample audit logs."""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    event_types = ["login", "access", "create", "update", "delete"]
    resource_types = ["user", "organization", "location", "role", "permission"]
    actions = ["authenticate", "view", "create", "update", "delete"]
    
    for org_id, users in users_by_org.items():
        for user in users:
            # Create 3-5 audit logs per user
            num_logs = random.randint(3, 5)
            
            for _ in range(num_logs):
                event_idx = random.randint(0, len(event_types) - 1)
                resource_idx = random.randint(0, len(resource_types) - 1)
                
                log_data = {
                    "organization_id": org_id,
                    "user_id": user["id"],
                    "user_email": user["email"],
                    "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "event_type": event_types[event_idx],
                    "resource_type": resource_types[resource_idx],
                    "resource_id": str(uuid.uuid4()),
                    "action": actions[event_idx],
                    "description": f"Sample audit log for {user['email']}",
                    "status": "success",
                    "source": "api",
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{BASE_URL}/audit/logs",
                        json=log_data,
                        headers=headers
                    )
                    
                    if response.status_code != 201:
                        print(f"Failed to create audit log: {response.text}")


async def create_security_events(users_by_org: Dict[str, List[Dict[str, Any]]]):
    """Create sample security events."""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    event_types = ["login_failure", "suspicious_activity", "unusual_location", "brute_force_attempt"]
    severities = ["low", "medium", "high"]
    
    for org_id, users in users_by_org.items():
        # Create 2-3 security events per organization
        num_events = random.randint(2, 3)
        
        for _ in range(num_events):
            user = random.choice(users)
            event_type = random.choice(event_types)
            severity = random.choice(severities)
            
            event_data = {
                "organization_id": org_id,
                "event_type": event_type,
                "severity": severity,
                "user_id": user["id"],
                "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "description": f"Sample {event_type} security event",
                "details": {
                    "attempts": random.randint(1, 5),
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{BASE_URL}/audit/security-events",
                    json=event_data,
                    headers=headers
                )
                
                if response.status_code == 201:
                    event = response.json()
                    print(f"Created security event: {event['event_type']} (ID: {event['id']})")
                else:
                    print(f"Failed to create security event: {response.text}")


async def create_superadmin():
    """Create a superadmin user if it doesn't exist."""
    # For testing, try to login first to see if the admin exists
    login_successful = await login_admin()
    
    if login_successful:
        print("Superadmin already exists, skipping creation")
        return True
    
    # Superadmin doesn't exist, need to create it
    # This typically would be done via a special endpoint or directly in the database
    # For this seed script, we'll assume there's an endpoint to create the initial superadmin
    admin_data = {
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
        "first_name": "System",
        "last_name": "Administrator",
        "is_superadmin": True
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/auth/setup",
            json=admin_data
        )
        
        if response.status_code == 201:
            print("Created superadmin user")
            return await login_admin()
        else:
            print(f"Failed to create superadmin: {response.text}")
            return False


async def main():
    """Main function to run the seed script."""
    parser = argparse.ArgumentParser(description="Seed the AuthX database with test data")
    parser.add_argument("--base-url", help="Base URL for the API", default=BASE_URL)
    parser.add_argument("--admin-email", help="Admin email", default=ADMIN_EMAIL)
    parser.add_argument("--admin-password", help="Admin password", default=ADMIN_PASSWORD)
    args = parser.parse_args()
    
    global BASE_URL, ADMIN_EMAIL, ADMIN_PASSWORD
    BASE_URL = args.base_url
    ADMIN_EMAIL = args.admin_email
    ADMIN_PASSWORD = args.admin_password
    
    print(f"Seeding AuthX database using API at {BASE_URL}")
    
    # Create superadmin and login
    if not await create_superadmin():
        print("Failed to create or login as superadmin. Exiting.")
        return
    
    # Create test data
    organizations = await create_organizations()
    permissions = await create_permissions()
    locations_by_org = await create_locations(organizations)
    roles_by_org = await create_roles(organizations, permissions, locations_by_org)
    users_by_org = await create_users(organizations, roles_by_org, locations_by_org)
    
    # Create logs and events
    await create_audit_logs(users_by_org)
    await create_security_events(users_by_org)
    
    print("Database seeding completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())
