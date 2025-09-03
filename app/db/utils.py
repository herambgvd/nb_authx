"""
Database utilities for AuthX.
This module provides database management utilities, migration helpers, and data operations.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import async_engine, sync_engine, AsyncSessionLocal

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database management utilities for AuthX."""

    @staticmethod
    async def initialize_database():
        """Initialize database with tables and initial data."""
        try:
            # Import all models to ensure they're registered
            from app.models import (
                User, Organization, Role, Location, LocationGroup,
                AuditLog, SecurityEvent, SystemConfig, License
            )

            # Create all tables
            from app.db.session import create_database_tables
            await create_database_tables()

            # Create initial system data
            await DatabaseManager.create_initial_data()

            logger.info("Database initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False

    @staticmethod
    async def create_initial_data():
        """Create initial system data."""
        async with AsyncSessionLocal() as session:
            try:
                # Check if we already have data
                from app.models.admin import SystemConfig
                existing_config = await session.execute(
                    text("SELECT COUNT(*) FROM system_configs")
                )
                if existing_config.scalar() > 0:
                    logger.info("Initial data already exists, skipping creation")
                    return

                # Create default system configurations
                default_configs = [
                    {
                        "key": "system.version",
                        "value": {"version": settings.VERSION},
                        "description": "System version information"
                    },
                    {
                        "key": "security.password_policy",
                        "value": {
                            "min_length": settings.PASSWORD_MIN_LENGTH,
                            "require_uppercase": settings.PASSWORD_REQUIRE_UPPERCASE,
                            "require_lowercase": settings.PASSWORD_REQUIRE_LOWERCASE,
                            "require_digits": settings.PASSWORD_REQUIRE_DIGITS,
                            "require_special": settings.PASSWORD_REQUIRE_SPECIAL
                        },
                        "description": "Default password policy settings"
                    },
                    {
                        "key": "auth.session_settings",
                        "value": {
                            "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
                            "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS,
                            "session_expire_minutes": settings.SESSION_EXPIRE_MINUTES
                        },
                        "description": "Authentication session settings"
                    }
                ]

                for config_data in default_configs:
                    config = SystemConfig(**config_data)
                    session.add(config)

                await session.commit()
                logger.info("Initial system data created successfully")

            except Exception as e:
                await session.rollback()
                logger.error(f"Error creating initial data: {e}")
                raise

    @staticmethod
    async def backup_database(backup_path: str) -> bool:
        """Create a database backup."""
        try:
            import subprocess
            import os

            # Parse database URL
            db_url = settings.DATABASE_URL
            # Extract connection details from URL
            # Format: postgresql://user:password@host:port/database

            cmd = [
                "pg_dump",
                db_url,
                "-f", backup_path,
                "--verbose"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"Database backup created successfully: {backup_path}")
                return True
            else:
                logger.error(f"Database backup failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return False

    @staticmethod
    async def restore_database(backup_path: str) -> bool:
        """Restore database from backup."""
        try:
            import subprocess

            # Parse database URL
            db_url = settings.DATABASE_URL

            cmd = [
                "psql",
                db_url,
                "-f", backup_path,
                "--verbose"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"Database restored successfully from: {backup_path}")
                return True
            else:
                logger.error(f"Database restore failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error restoring database: {e}")
            return False

    @staticmethod
    async def vacuum_database():
        """Perform database maintenance (VACUUM)."""
        try:
            async with async_engine.connect() as conn:
                await conn.execute(text("VACUUM ANALYZE"))
                await conn.commit()
            logger.info("Database vacuum completed successfully")
            return True
        except Exception as e:
            logger.error(f"Database vacuum failed: {e}")
            return False

    @staticmethod
    async def get_table_sizes() -> Dict[str, Any]:
        """Get size information for all tables."""
        try:
            async with async_engine.connect() as conn:
                result = await conn.execute(text("""
                    SELECT 
                        schemaname,
                        tablename,
                        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                        pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                    FROM pg_tables 
                    WHERE schemaname = 'public'
                    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                """))

                tables = []
                for row in result:
                    tables.append({
                        "schema": row.schemaname,
                        "table": row.tablename,
                        "size": row.size,
                        "size_bytes": row.size_bytes
                    })

                return {"tables": tables}
        except Exception as e:
            logger.error(f"Error getting table sizes: {e}")
            return {"tables": []}

class DataSeeder:
    """Database data seeding utilities."""

    @staticmethod
    async def seed_development_data():
        """Seed database with development data."""
        async with AsyncSessionLocal() as session:
            try:
                from app.models import Organization, User, Role

                # Check if we already have organizations
                existing_orgs = await session.execute(
                    text("SELECT COUNT(*) FROM organizations")
                )
                if existing_orgs.scalar() > 0:
                    logger.info("Development data already exists, skipping seeding")
                    return

                # Create test organization
                test_org = Organization(
                    name="Test Organization",
                    slug="test-org",
                    description="Test organization for development",
                    email="test@example.com",
                    is_active=True
                )
                session.add(test_org)
                await session.flush()  # Get the ID

                # Create admin role
                admin_role = Role(
                    name="Administrator",
                    slug="admin",
                    description="Full system administrator",
                    organization_id=test_org.id,
                    is_default=False,
                    is_system=True,
                    permissions={
                        "users": {"create": True, "read": True, "update": True, "delete": True},
                        "organizations": {"create": True, "read": True, "update": True, "delete": True},
                        "roles": {"create": True, "read": True, "update": True, "delete": True},
                        "locations": {"create": True, "read": True, "update": True, "delete": True},
                        "audit": {"read": True},
                        "admin": {"access": True}
                    }
                )
                session.add(admin_role)

                # Create user role
                user_role = Role(
                    name="User",
                    slug="user",
                    description="Standard user",
                    organization_id=test_org.id,
                    is_default=True,
                    is_system=False,
                    permissions={
                        "users": {"read": True, "update": False},
                        "organizations": {"read": True},
                        "locations": {"read": True}
                    }
                )
                session.add(user_role)

                await session.commit()
                logger.info("Development data seeded successfully")

            except Exception as e:
                await session.rollback()
                logger.error(f"Error seeding development data: {e}")
                raise

# Global database manager instance
db_manager = DatabaseManager()
data_seeder = DataSeeder()
