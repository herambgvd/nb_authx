"""
Initial database schema creation.
This migration creates all tables for the AuthX service.
Revision ID: 2023090101
Revises:
Create Date: 2023-09-01 01:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid


# revision identifiers, used by Alembic
revision = '2023090101'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Organizations table
    op.create_table(
        'organizations',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('display_name', sa.String(255), nullable=True),
        sa.Column('domain', sa.String(255), nullable=True, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('contact_email', sa.String(255), nullable=True),
        sa.Column('contact_phone', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('is_verified', sa.Boolean(), default=False, nullable=False),
        sa.Column('subscription_plan', sa.String(50), default='free', nullable=False),
        sa.Column('subscription_start_date', sa.String(10), nullable=True),
        sa.Column('subscription_end_date', sa.String(10), nullable=True),
        sa.Column('logo_url', sa.String(255), nullable=True),
        sa.Column('primary_color', sa.String(20), nullable=True),
        sa.Column('enforce_mfa', sa.Boolean(), default=False, nullable=False),
        sa.Column('password_policy', sa.String(50), default='standard', nullable=False),
        sa.Column('session_timeout_minutes', sa.Integer(), default=60, nullable=False),
        sa.Column('verification_status', sa.String(50), default='pending', nullable=False),
        sa.Column('verification_method', sa.String(50), nullable=True),
        sa.Column('verification_date', sa.String(10), nullable=True),
        sa.Column('data_isolation_level', sa.String(50), default='strict', nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Organization Settings table
    op.create_table(
        'organization_settings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False, unique=True),
        sa.Column('security_settings', JSONB, nullable=False, default=dict),
        sa.Column('branding_settings', JSONB, nullable=False, default=dict),
        sa.Column('notification_settings', JSONB, nullable=False, default=dict),
        sa.Column('integration_settings', JSONB, nullable=False, default=dict),
        sa.Column('custom_settings', JSONB, nullable=False, default=dict),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Locations table
    op.create_table(
        'locations',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('code', sa.String(50), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('parent_id', UUID(as_uuid=True), sa.ForeignKey('locations.id'), nullable=True),
        sa.Column('address_line1', sa.String(255), nullable=True),
        sa.Column('address_line2', sa.String(255), nullable=True),
        sa.Column('city', sa.String(100), nullable=True),
        sa.Column('state', sa.String(100), nullable=True),
        sa.Column('postal_code', sa.String(20), nullable=True),
        sa.Column('country', sa.String(100), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('contact_name', sa.String(255), nullable=True),
        sa.Column('contact_email', sa.String(255), nullable=True),
        sa.Column('contact_phone', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('geo_fencing_enabled', sa.Boolean(), default=False, nullable=False),
        sa.Column('geo_fencing_radius', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Location Groups table
    op.create_table(
        'location_groups',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Location Group Association table
    op.create_table(
        'location_group_locations',
        sa.Column('location_group_id', UUID(as_uuid=True), sa.ForeignKey('location_groups.id'), primary_key=True),
        sa.Column('location_id', UUID(as_uuid=True), sa.ForeignKey('locations.id'), primary_key=True)
    )

    # Users table
    op.create_table(
        'users',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('first_name', sa.String(100), nullable=True),
        sa.Column('last_name', sa.String(100), nullable=True),
        sa.Column('phone_number', sa.String(50), nullable=True),
        sa.Column('profile_picture_url', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('is_verified', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_superadmin', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_org_admin', sa.Boolean(), default=False, nullable=False),
        sa.Column('status', sa.String(50), default='active', nullable=False),
        sa.Column('status_reason', sa.Text(), nullable=True),
        sa.Column('status_changed_at', sa.DateTime(), nullable=True),
        sa.Column('status_changed_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('mfa_enabled', sa.Boolean(), default=False, nullable=False),
        sa.Column('mfa_secret', sa.String(255), nullable=True),
        sa.Column('mfa_type', sa.String(20), default='totp', nullable=True),
        sa.Column('password_last_changed', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), default=0, nullable=False),
        sa.Column('account_locked_until', sa.DateTime(), nullable=True),
        sa.Column('email_verified', sa.Boolean(), default=False, nullable=False),
        sa.Column('email_verification_token', sa.String(255), nullable=True),
        sa.Column('email_verification_sent_at', sa.DateTime(), nullable=True),
        sa.Column('invited_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('invited_at', sa.DateTime(), nullable=True),
        sa.Column('invitation_accepted_at', sa.DateTime(), nullable=True),
        sa.Column('settings', JSONB, default=dict, nullable=False),
        sa.Column('default_location_id', UUID(as_uuid=True), sa.ForeignKey('locations.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # User Devices table
    op.create_table(
        'user_devices',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=False),
        sa.Column('device_type', sa.String(50), nullable=False),
        sa.Column('device_id', sa.String(255), nullable=False),
        sa.Column('operating_system', sa.String(100), nullable=True),
        sa.Column('browser', sa.String(100), nullable=True),
        sa.Column('token_id', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('location', sa.String(255), nullable=True),
        sa.Column('last_used', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('is_trusted', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_remembered', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_current', sa.Boolean(), default=True, nullable=False),
        sa.Column('metadata', JSONB, default=dict, nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Permissions table
    op.create_table(
        'permissions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(100), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('is_system_permission', sa.Boolean(), default=False, nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Roles table
    op.create_table(
        'roles',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system_role', sa.Boolean(), default=False, nullable=False),
        sa.Column('is_location_specific', sa.Boolean(), default=False, nullable=False),
        sa.Column('location_id', UUID(as_uuid=True), sa.ForeignKey('locations.id'), nullable=True),
        sa.Column('parent_id', UUID(as_uuid=True), sa.ForeignKey('roles.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Role-Permission association table
    op.create_table(
        'role_permissions',
        sa.Column('role_id', UUID(as_uuid=True), sa.ForeignKey('roles.id'), primary_key=True),
        sa.Column('permission_id', UUID(as_uuid=True), sa.ForeignKey('permissions.id'), primary_key=True)
    )

    # User-Role association table
    op.create_table(
        'user_roles',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('role_id', UUID(as_uuid=True), sa.ForeignKey('roles.id'), nullable=False),
        sa.Column('is_primary', sa.Boolean(), default=False, nullable=False),
        sa.Column('assigned_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('assigned_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('user_email', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, default='success'),
        sa.Column('details', JSONB, nullable=True),
        sa.Column('source', sa.String(100), nullable=True),
        sa.Column('session_id', sa.String(255), nullable=True),
        sa.Column('request_id', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Security Events table
    op.create_table(
        'security_events',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('location', sa.String(255), nullable=True),
        sa.Column('device_id', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('details', JSONB, nullable=True),
        sa.Column('status', sa.String(50), nullable=False, default='new'),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('resolved_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('alert_sent', sa.Boolean(), default=False, nullable=False),
        sa.Column('alert_recipients', JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Compliance Reports table
    op.create_table(
        'compliance_reports',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('report_type', sa.String(100), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('generated_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('parameters', JSONB, nullable=True),
        sa.Column('data', JSONB, nullable=True),
        sa.Column('summary', JSONB, nullable=True),
        sa.Column('status', sa.String(50), nullable=False, default='generating'),
        sa.Column('file_path', sa.String(255), nullable=True),
        sa.Column('shared_with', JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Forensic Snapshots table
    op.create_table(
        'forensic_snapshots',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('snapshot_type', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=False),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('data', JSONB, nullable=False),
        sa.Column('status', sa.String(50), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # System Configs table
    op.create_table(
        'system_configs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('key', sa.String(255), nullable=False, unique=True),
        sa.Column('value', JSONB, nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_encrypted', sa.Boolean(), default=False, nullable=False),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('updated_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Licenses table
    op.create_table(
        'licenses',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('key', sa.String(255), nullable=False, unique=True),
        sa.Column('organization_id', UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('max_users', sa.Integer(), nullable=False),
        sa.Column('max_locations', sa.Integer(), nullable=False),
        sa.Column('features', JSONB, nullable=False, default=list),
        sa.Column('issued_date', sa.DateTime(), nullable=False),
        sa.Column('expiration_date', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('contact_name', sa.String(255), nullable=True),
        sa.Column('contact_email', sa.String(255), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # User Impersonation table
    op.create_table(
        'user_impersonations',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('impersonator_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('token', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Maintenance Windows table
    op.create_table(
        'maintenance_windows',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('start_time', sa.DateTime(), nullable=False),
        sa.Column('end_time', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('affected_services', JSONB, nullable=False, default=list),
        sa.Column('status', sa.String(50), nullable=False, default='scheduled'),
        sa.Column('notification_sent', sa.Boolean(), default=False, nullable=False),
        sa.Column('notified_organizations', JSONB, nullable=True),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Platform Metrics table
    op.create_table(
        'platform_metrics',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('metric_name', sa.String(100), nullable=False),
        sa.Column('metric_value', JSONB, nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False, default=sa.func.now()),
        sa.Column('dimension', sa.String(50), nullable=True),
        sa.Column('dimension_id', sa.String(255), nullable=True),
        sa.Column('interval', sa.String(20), nullable=False, default='day'),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now(), nullable=False)
    )

    # Create indexes for performance
    op.create_index('ix_users_email_org', 'users', ['email', 'organization_id'], unique=True)
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_org_id', 'audit_logs', ['organization_id'])
    op.create_index('ix_security_events_created_at', 'security_events', ['created_at'])
    op.create_index('ix_security_events_org_id', 'security_events', ['organization_id'])
    op.create_index('ix_locations_org_id', 'locations', ['organization_id'])
    op.create_index('ix_roles_org_id', 'roles', ['organization_id'])


def downgrade() -> None:
    # Drop tables in reverse order of creation (to handle foreign key constraints)
    op.drop_table('platform_metrics')
    op.drop_table('maintenance_windows')
    op.drop_table('user_impersonations')
    op.drop_table('licenses')
    op.drop_table('system_configs')
    op.drop_table('forensic_snapshots')
    op.drop_table('compliance_reports')
    op.drop_table('security_events')
    op.drop_table('audit_logs')
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_table('roles')
    op.drop_table('permissions')
    op.drop_table('user_devices')
    op.drop_table('users')
    op.drop_table('location_group_locations')
    op.drop_table('location_groups')
    op.drop_table('locations')
    op.drop_table('organization_settings')
    op.drop_table('organizations')
