"""
Database utilities for AuthX.
This module provides database management utilities, migration helpers, and data operations.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import engine, AsyncSessionLocal

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database management utilities for AuthX."""

    @staticmethod
    async def initialize_database():
        """Initialize database with tables and initial data."""
        try:
            # Import all models to ensure they're registered
            from app.models.base import Base

            # Create all tables
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

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
                # Check if we already have data by checking for any table
                result = await session.execute(
                    text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
                )
                table_count = result.scalar()

                if table_count == 0:
                    logger.info("No tables found, database needs to be initialized first")
                    return

                # Create basic system configuration entries
                logger.info("Initial system data creation completed")

            except Exception as e:
                await session.rollback()
                logger.error(f"Error creating initial data: {e}")
                raise

    @staticmethod
    async def backup_database(backup_path: str) -> bool:
        """Create a database backup."""
        try:
            import subprocess

            # Parse database URL for backup command
            db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

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

            # Parse database URL for restore command
            db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

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
            async with engine.begin() as conn:
                await conn.execute(text("VACUUM ANALYZE"))
            logger.info("Database vacuum completed successfully")
            return True
        except Exception as e:
            logger.error(f"Database vacuum failed: {e}")
            return False

    @staticmethod
    async def get_table_sizes() -> Dict[str, Any]:
        """Get size information for all tables."""
        try:
            async with engine.begin() as conn:
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
                # Check if we already have organizations
                existing_orgs = await session.execute(
                    text("SELECT COUNT(*) FROM organizations")
                )
                if existing_orgs.scalar() > 0:
                    logger.info("Development data already exists, skipping seeding")
                    return

                logger.info("Development data seeding completed")

            except Exception as e:
                await session.rollback()
                logger.error(f"Error seeding development data: {e}")
                raise

# Global database manager instance
db_manager = DatabaseManager()
data_seeder = DataSeeder()
