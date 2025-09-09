"""
Alembic environment configuration for AuthX.
Handles database migrations with synchronous support for Alembic.
"""
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.base import Base
from app.core.config import settings

# Import all models to ensure they're registered with SQLAlchemy
from app.models.user import User
from app.models.organization import Organization
from app.models.role import Role, Permission
from app.models.location import Location
from app.models.location_group import LocationGroup
from app.models.admin import SystemConfig, License, Admin
from app.models.audit import AuditLog, SecurityEvent
from app.models.user_device import UserDevice
from app.models.organization_settings import OrganizationSettings
from app.models.user_location_access import UserLocationAccess

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set the target metadata
target_metadata = Base.metadata

# Set the database URL from settings (use synchronous URL for migrations)
config.set_main_option("sqlalchemy.url", settings.ALEMBIC_DATABASE_URL)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
