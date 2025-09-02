"""
User API endpoints for the AuthX service.
This module provides API endpoints for user management functionality.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
import csv
import io
import secrets
import string
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status, Body, BackgroundTasks, UploadFile, File, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.api.deps import get_current_user, get_db, get_organization_admin, get_current_superadmin
from app.models.user import User, UserRole
from app.models.user_device import UserDevice
from app.models.role import Role
from app.models.location import Location
from app.utils.security import get_password_hash, verify_password
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    UserPasswordUpdate,
    UserMFAUpdate,
    UserRoleAssignment,
    UserStatusUpdate,
    UserVerificationRequest,
    UserVerificationComplete,
    UserDeviceCreate,
    UserDeviceResponse,
    UserDeviceListResponse,
    UserImportRequest,
    UserImportResponse,
    UserExportRequest,
    UserExportResponse,
    UserImportItem
)

router = APIRouter()

# User CRUD Operations
@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_data: UserCreate,
    background_tasks: BackgroundTasks
):
    """
    Create a new user.
    Organization admins can create users within their organization.
    """
    # Set organization_id from current user if not provided or validate access
    if not user_data.organization_id:
        user_data.organization_id = current_user.organization_id
    elif current_user.organization_id != user_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users for this organization"
        )

    # Check if user with the same email already exists in the organization
    existing_user = db.query(User).filter(
        User.email == user_data.email,
        User.organization_id == user_data.organization_id
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{user_data.email}' already exists in this organization"
        )

    # Validate default location if provided
    if user_data.default_location_id:
        location = db.query(Location).filter(
            Location.id == user_data.default_location_id,
            Location.organization_id == user_data.organization_id
        ).first()

        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Default location not found or belongs to a different organization"
            )

    # Hash the password
    hashed_password = get_password_hash(user_data.password)

    # Create user without roles first
    user_dict = user_data.dict(exclude={"password", "role_ids"})
    new_user = User(**user_dict, hashed_password=hashed_password)

    # Set invitation information
    new_user.invited_by = current_user.id
    new_user.invited_at = datetime.utcnow()
    new_user.status = "pending"

    # Generate a verification token
    new_user.email_verification_token = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
    )
    new_user.email_verification_sent_at = datetime.utcnow()

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Assign roles if provided
    if user_data.role_ids:
        await assign_roles_to_user(db, new_user.id, user_data.role_ids, current_user.id)

    # Send invitation email in the background
    # background_tasks.add_task(
    #     send_invitation_email,
    #     new_user.email,
    #     new_user.email_verification_token,
    #     new_user.organization_id
    # )

    return new_user

@router.get("", response_model=UserListResponse)
async def get_users(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    organization_id: Optional[UUID] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_verified: Optional[bool] = None,
    location_id: Optional[UUID] = None,
    role_id: Optional[UUID] = None
):
    """
    Get a paginated list of users with optional filtering.
    Users can only view users within their organization unless they are superadmins.
    """
    # Determine which organization to query
    if organization_id is None:
        organization_id = current_user.organization_id
    elif current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view users for this organization"
        )

    # Build query
    query = db.query(User).filter(User.organization_id == organization_id)

    # Apply filters
    if search:
        query = query.filter(
            or_(
                User.email.ilike(f"%{search}%"),
                User.username.ilike(f"%{search}%"),
                User.first_name.ilike(f"%{search}%"),
                User.last_name.ilike(f"%{search}%")
            )
        )

    if status:
        query = query.filter(User.status == status)

    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    if is_verified is not None:
        query = query.filter(User.is_verified == is_verified)

    if location_id:
        query = query.filter(User.default_location_id == location_id)

    if role_id:
        query = query.filter(User.roles.any(UserRole.role_id == role_id))

    # Get total count
    total = query.count()

    # Apply pagination
    users = query.offset(skip).limit(limit).all()

    return {
        "items": users,
        "total": total,
        "page": skip // limit + 1,
        "size": limit
    }

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID
):
    """
    Get detailed information about a specific user by ID.
    Users can only view users within their organization unless they are superadmins.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to view this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user"
        )

    return user

@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    user_data: UserUpdate
):
    """
    Update a user's details.
    Users can update their own profile. Organization admins can update any user in their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )

    # Regular users can only update certain fields for themselves
    if is_self and not is_admin:
        allowed_fields = {"first_name", "last_name", "phone_number", "profile_picture_url", "settings"}
        for field in user_data.__dict__:
            if field not in allowed_fields and getattr(user_data, field, None) is not None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not authorized to update the '{field}' field"
                )

    # If updating email, check if it's already in use
    if user_data.email and user_data.email != user.email:
        existing_user = db.query(User).filter(
            User.email == user_data.email,
            User.organization_id == user.organization_id,
            User.id != user_id
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"User with email '{user_data.email}' already exists in this organization"
            )

    # Validate default location if provided
    if user_data.default_location_id:
        location = db.query(Location).filter(
            Location.id == user_data.default_location_id,
            Location.organization_id == user.organization_id
        ).first()

        if not location:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Default location not found or belongs to a different organization"
            )

    # Update user with provided data
    update_data = user_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)

    return user

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_id: UUID
):
    """
    Delete a user.
    Organization admins can delete users within their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to delete this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this user"
        )

    # Prevent self-deletion
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself"
        )

    # Delete the user
    db.delete(user)
    db.commit()

    return None

# User Profile and Settings Management
@router.patch("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def update_password(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    password_data: UserPasswordUpdate
):
    """
    Update a user's password.
    Users can change their own password. Admins can reset passwords for users in their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user's password"
        )

    # Verify current password if changing own password
    if is_self:
        if not verify_password(password_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password"
            )
    elif not is_admin:
        # Non-admins need to provide the current password
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user's password"
        )

    # Update password
    user.hashed_password = get_password_hash(password_data.new_password)
    user.password_last_changed = datetime.utcnow()

    db.commit()

    return None

@router.patch("/{user_id}/mfa", response_model=UserResponse)
async def update_mfa_settings(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    mfa_data: UserMFAUpdate
):
    """
    Update a user's MFA settings.
    Users can update their own MFA settings.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user's MFA settings"
        )

    # Validate MFA type if provided
    if mfa_data.mfa_type and mfa_data.mfa_type not in ["totp", "sms", "email"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA type. Must be one of: totp, sms, email"
        )

    # Update MFA settings
    user.mfa_enabled = mfa_data.mfa_enabled
    if mfa_data.mfa_type:
        user.mfa_type = mfa_data.mfa_type

    # If disabling MFA, clear the secret
    if not mfa_data.mfa_enabled:
        user.mfa_secret = None

    db.commit()
    db.refresh(user)

    return user

# User Status Management
@router.patch("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_id: UUID,
    status_data: UserStatusUpdate
):
    """
    Update a user's active status.
    Organization admins can activate or deactivate users within their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to update this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user's status"
        )

    # Prevent self-deactivation
    if current_user.id == user_id and not status_data.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate yourself"
        )

    # Update status
    user.is_active = status_data.is_active
    user.status = "active" if status_data.is_active else "inactive"
    user.status_reason = status_data.reason
    user.status_changed_at = datetime.utcnow()
    user.status_changed_by = current_user.id

    db.commit()
    db.refresh(user)

    return user

@router.post("/{user_id}/suspend", response_model=UserResponse)
async def suspend_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_id: UUID,
    reason: str = Body(..., embed=True)
):
    """
    Suspend a user.
    Organization admins can suspend users within their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to update this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to suspend this user"
        )

    # Prevent self-suspension
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend yourself"
        )

    # Update status
    user.is_active = False
    user.status = "suspended"
    user.status_reason = reason
    user.status_changed_at = datetime.utcnow()
    user.status_changed_by = current_user.id

    db.commit()
    db.refresh(user)

    return user

@router.post("/{user_id}/reinstate", response_model=UserResponse)
async def reinstate_user(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_id: UUID
):
    """
    Reinstate a suspended user.
    Organization admins can reinstate suspended users within their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to update this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to reinstate this user"
        )

    # Check if user is suspended
    if user.status != "suspended":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not suspended"
        )

    # Update status
    user.is_active = True
    user.status = "active"
    user.status_reason = None
    user.status_changed_at = datetime.utcnow()
    user.status_changed_by = current_user.id

    db.commit()
    db.refresh(user)

    return user

# User Verification
@router.post("/{user_id}/verification/request", status_code=status.HTTP_204_NO_CONTENT)
async def request_verification(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    verification_data: UserVerificationRequest,
    background_tasks: BackgroundTasks
):
    """
    Request user verification.
    Users can request verification for themselves, or admins can request it for users in their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to request verification for this user"
        )

    # Validate verification type
    valid_types = ["email", "phone", "document"]
    if verification_data.verification_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verification type. Must be one of: {', '.join(valid_types)}"
        )

    # Generate verification token
    token = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
    )

    # Update user with verification information
    if verification_data.verification_type == "email":
        user.email_verification_token = token
        user.email_verification_sent_at = datetime.utcnow()

        # Send verification email in the background
        # background_tasks.add_task(
        #     send_verification_email,
        #     user.email,
        #     token,
        #     user.organization_id
        # )

    db.commit()

    return None

@router.post("/{user_id}/verification/complete", response_model=UserResponse)
async def complete_verification(
    *,
    db: Session = Depends(get_db),
    user_id: UUID,
    verification_data: UserVerificationComplete
):
    """
    Complete user verification.
    Users verify themselves using a verification code.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check verification code
    if user.email_verification_token != verification_data.verification_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    # Check if verification token is expired (24 hours)
    if user.email_verification_sent_at:
        expiration = user.email_verification_sent_at + timedelta(hours=24)
        if datetime.utcnow() > expiration:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code has expired. Please request a new one."
            )

    # Update verification status
    user.is_verified = True
    user.email_verified = True
    user.email_verification_token = None

    # If user was in pending status, activate them
    if user.status == "pending":
        user.status = "active"
        user.invitation_accepted_at = datetime.utcnow()

    db.commit()
    db.refresh(user)

    return user

# User Roles
@router.post("/{user_id}/roles", response_model=UserResponse)
async def assign_roles(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    user_id: UUID,
    role_data: UserRoleAssignment
):
    """
    Assign roles to a user.
    Organization admins can assign roles to users within their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has permission to update this user
    if current_user.organization_id != user.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to assign roles to this user"
        )

    # Assign roles
    await assign_roles_to_user(db, user_id, role_data.role_ids, current_user.id, role_data.is_primary)

    # Refresh user to include new roles
    db.refresh(user)

    return user

async def assign_roles_to_user(
    db: Session,
    user_id: UUID,
    role_ids: List[UUID],
    assigned_by: UUID,
    is_primary: Optional[bool] = None
):
    """Helper function to assign roles to a user."""
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Validate that all roles exist and belong to the organization
    roles = db.query(Role).filter(
        Role.id.in_(role_ids),
        Role.organization_id == user.organization_id
    ).all()

    if len(roles) != len(role_ids):
        found_ids = {str(role.id) for role in roles}
        missing_ids = [str(id) for id in role_ids if str(id) not in found_ids]
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Some roles not found or belong to a different organization: {', '.join(missing_ids)}"
        )

    # Remove existing role assignments
    db.query(UserRole).filter(UserRole.user_id == user_id).delete()

    # Create new role assignments
    for role in roles:
        user_role = UserRole(
            user_id=user_id,
            role_id=role.id,
            assigned_by=assigned_by,
            is_primary=is_primary if is_primary is not None else False
        )
        db.add(user_role)

    # If any role has admin privileges, set is_org_admin to True
    has_admin_role = any(role.is_admin for role in roles)
    user.is_org_admin = has_admin_role

    db.commit()

# User Devices
@router.get("/{user_id}/devices", response_model=UserDeviceListResponse)
async def get_user_devices(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID
):
    """
    Get a list of devices for a user.
    Users can view their own devices. Admins can view devices for users in their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user's devices"
        )

    # Get devices
    devices = db.query(UserDevice).filter(UserDevice.user_id == user_id).all()

    return {
        "items": devices,
        "total": len(devices)
    }

@router.post("/{user_id}/devices", response_model=UserDeviceResponse)
async def register_device(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    device_data: UserDeviceCreate
):
    """
    Register a new device for a user.
    Users can register devices for themselves.
    """
    # Check permissions
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to register devices for this user"
        )

    # Check if device already exists
    existing_device = db.query(UserDevice).filter(
        UserDevice.user_id == user_id,
        UserDevice.device_id == device_data.device_id
    ).first()

    if existing_device:
        # Update existing device
        existing_device.device_name = device_data.device_name
        existing_device.device_type = device_data.device_type
        existing_device.operating_system = device_data.operating_system
        existing_device.browser = device_data.browser
        existing_device.ip_address = device_data.ip_address
        existing_device.location = device_data.location
        existing_device.last_used = datetime.utcnow()
        existing_device.is_current = True

        db.commit()
        db.refresh(existing_device)

        return existing_device

    # Create new device
    new_device = UserDevice(**device_data.dict())
    db.add(new_device)
    db.commit()
    db.refresh(new_device)

    return new_device

@router.delete("/{user_id}/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_device(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    device_id: UUID
):
    """
    Remove a device from a user's account.
    Users can remove their own devices. Admins can remove devices for users in their organization.
    """
    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check permissions
    is_self = current_user.id == user_id
    is_admin = current_user.is_org_admin or current_user.is_superadmin
    is_same_org = current_user.organization_id == user.organization_id

    if not (is_self or (is_admin and is_same_org) or current_user.is_superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to remove this user's devices"
        )

    # Get device
    device = db.query(UserDevice).filter(
        UserDevice.id == device_id,
        UserDevice.user_id == user_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Delete device
    db.delete(device)
    db.commit()

    return None

@router.post("/{user_id}/devices/{device_id}/trust", response_model=UserDeviceResponse)
async def trust_device(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_id: UUID,
    device_id: UUID
):
    """
    Mark a device as trusted.
    Users can trust their own devices.
    """
    # Check permissions
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to trust devices for this user"
        )

    # Get device
    device = db.query(UserDevice).filter(
        UserDevice.id == device_id,
        UserDevice.user_id == user_id
    ).first()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )

    # Update trust status
    device.is_trusted = True
    db.commit()
    db.refresh(device)

    return device

# User Import/Export
@router.post("/import", response_model=UserImportResponse)
async def import_users(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    import_data: UserImportRequest,
    background_tasks: BackgroundTasks
):
    """
    Import multiple users.
    Organization admins can import users into their organization.
    """
    # Check if user has access to the organization
    if current_user.organization_id != import_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to import users for this organization"
        )

    # Track import results
    results = {
        "total": len(import_data.users),
        "created": 0,
        "failed": 0,
        "errors": []
    }

    # Process each user
    for user_item in import_data.users:
        try:
            # Check if user already exists
            existing_user = db.query(User).filter(
                User.email == user_item.email,
                User.organization_id == import_data.organization_id
            ).first()

            if existing_user:
                results["failed"] += 1
                results["errors"].append({
                    "email": user_item.email,
                    "error": "User with this email already exists"
                })
                continue

            # Generate password if not provided
            password = user_item.password
            if not password:
                password = "".join(
                    secrets.choice(string.ascii_letters + string.digits + string.punctuation)
                    for _ in range(12)
                )

            # Create user
            hashed_password = get_password_hash(password)

            # Create user object
            new_user = User(
                email=user_item.email,
                username=user_item.username,
                first_name=user_item.first_name,
                last_name=user_item.last_name,
                phone_number=user_item.phone_number,
                hashed_password=hashed_password,
                is_active=user_item.is_active,
                status="pending" if user_item.send_invitation else "active",
                organization_id=import_data.organization_id,
                default_location_id=user_item.default_location_id,
                invited_by=current_user.id,
                invited_at=datetime.utcnow()
            )

            # Generate verification token if sending invitation
            if user_item.send_invitation:
                new_user.email_verification_token = "".join(
                    secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
                )
                new_user.email_verification_sent_at = datetime.utcnow()

            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            # Assign roles if provided
            if user_item.role_ids:
                await assign_roles_to_user(db, new_user.id, user_item.role_ids, current_user.id)

            # Send invitation email if requested
            if user_item.send_invitation:
                # background_tasks.add_task(
                #     send_invitation_email,
                #     new_user.email,
                #     new_user.email_verification_token,
                #     new_user.organization_id,
                #     password if not user_item.password else None
                # )
                pass

            results["created"] += 1

        except Exception as e:
            results["failed"] += 1
            results["errors"].append({
                "email": user_item.email,
                "error": str(e)
            })

    return results

@router.post("/import/csv", response_model=UserImportResponse)
async def import_users_csv(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    organization_id: UUID = Query(...),
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks
):
    """
    Import users from a CSV file.
    Organization admins can import users into their organization.
    """
    # Check if user has access to the organization
    if current_user.organization_id != organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to import users for this organization"
        )

    # Read CSV file
    contents = await file.read()
    csv_text = contents.decode('utf-8')
    csv_reader = csv.DictReader(io.StringIO(csv_text))

    # Convert CSV to user import items
    users = []
    for row in csv_reader:
        # Handle role IDs if provided
        role_ids = []
        if "role_ids" in row and row["role_ids"]:
            role_ids = [UUID(role_id.strip()) for role_id in row["role_ids"].split(",")]

        # Handle default location if provided
        default_location_id = None
        if "default_location_id" in row and row["default_location_id"]:
            default_location_id = UUID(row["default_location_id"])

        # Convert is_active to boolean
        is_active = True
        if "is_active" in row:
            is_active = row["is_active"].lower() in ["true", "yes", "1"]

        # Convert send_invitation to boolean
        send_invitation = True
        if "send_invitation" in row:
            send_invitation = row["send_invitation"].lower() in ["true", "yes", "1"]

        user_item = UserImportItem(
            email=row["email"],
            username=row.get("username"),
            first_name=row.get("first_name"),
            last_name=row.get("last_name"),
            phone_number=row.get("phone_number"),
            default_location_id=default_location_id,
            role_ids=role_ids,
            is_active=is_active,
            password=row.get("password"),
            send_invitation=send_invitation
        )
        users.append(user_item)

    # Create import request
    import_data = UserImportRequest(
        users=users,
        organization_id=organization_id
    )

    # Process import
    return await import_users(
        db=db,
        current_user=current_user,
        import_data=import_data,
        background_tasks=background_tasks
    )

@router.post("/export", response_model=UserExportResponse)
async def export_users(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin),
    export_data: UserExportRequest
):
    """
    Export users to a file.
    Organization admins can export users from their organization.
    """
    # Check if user has access to the organization
    if current_user.organization_id != export_data.organization_id and not current_user.is_superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export users for this organization"
        )

    # Build query
    query = db.query(User).filter(User.organization_id == export_data.organization_id)

    # Apply filters
    if not export_data.include_inactive:
        query = query.filter(User.is_active == True)

    # Get users
    users = query.all()

    # Generate file in requested format
    if export_data.format == "csv":
        output = io.StringIO()
        fieldnames = ["id", "email", "username", "first_name", "last_name", "phone_number",
                    "is_active", "is_verified", "status", "created_at", "updated_at"]

        # Add role information if requested
        if export_data.include_roles:
            fieldnames.append("roles")

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for user in users:
            user_dict = {
                "id": str(user.id),
                "email": user.email,
                "username": user.username or "",
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "phone_number": user.phone_number or "",
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "status": user.status,
                "created_at": user.created_at.isoformat() if user.created_at else "",
                "updated_at": user.updated_at.isoformat() if user.updated_at else ""
            }

            # Add role information if requested
            if export_data.include_roles and user.roles:
                role_names = [role.role.name for role in user.roles if role.role]
                user_dict["roles"] = ", ".join(role_names)

            writer.writerow(user_dict)

        # Return CSV file
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )

    elif export_data.format == "json":
        # Return JSON data
        user_data = []
        for user in users:
            user_dict = {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone_number": user.phone_number,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "status": user.status,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None
            }

            # Add role information if requested
            if export_data.include_roles and user.roles:
                user_dict["roles"] = [
                    {
                        "id": str(role.role_id),
                        "name": role.role.name if role.role else None,
                        "is_primary": role.is_primary
                    }
                    for role in user.roles
                ]

            user_data.append(user_dict)

        return {
            "download_url": "generated_on_the_fly",
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "record_count": len(users)
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format: {export_data.format}"
        )
