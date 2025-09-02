"""
Alembic configuration for database migrations.
This module is used by Alembic to handle database schema migrations.
"""
import os
import sys
from logging.config import fileConfig
from pathlib import Path

# Add the parent directory to the path so we can import the app
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Special flag for SQLAlchemy 2.0 to be more lenient with annotations
os.environ["SQLALCHEMY_WARN_20"] = "1"

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context

# Now import from the app
from app.core.config import settings
from app.models.base import BaseModel
from app.db.session import Base

# Load all models to ensure they're included in migrations
import app.models.organization
import app.models.organization_settings
import app.models.location
import app.models.location_group
import app.models.user
import app.models.user_device
import app.models.role
import app.models.audit
import app.models.admin

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override the SQLAlchemy URL with our connection string
config.set_main_option("sqlalchemy.url", settings.DATABASE_URI)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
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
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
