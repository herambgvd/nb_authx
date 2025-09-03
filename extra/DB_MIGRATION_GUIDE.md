# Database Migration Guide for AuthX

This guide explains how to set up and run database migrations for the AuthX microservice.

## Prerequisites

1. PostgreSQL server installed and running
2. Database created for nb_auth
3. Python environment with required packages installed

## Setup Database

First, create a PostgreSQL database for AuthX:

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE authx;

# Exit PostgreSQL
\q
```

## Environment Variables

Make sure your `.env` file contains the correct database connection string:

```
DATABASE_URI=postgresql://postgres:password@localhost:5432/authx
```

Replace `password` with your actual PostgreSQL password.

## Migration Commands

### Initialize Database with All Tables

To create all tables in the database:

```bash
# Run all migrations
alembic upgrade head
```

### Create a New Migration

When you make changes to the database models, create a new migration:

```bash
# Create a new migration
alembic revision --autogenerate -m "description_of_changes"
```

### Apply Pending Migrations

To apply any pending migrations:

```bash
# Apply migrations
alembic upgrade head
```

### Rollback Migrations

To roll back the most recent migration:

```bash
# Rollback one migration
alembic downgrade -1
```

To roll back to a specific migration:

```bash
# Rollback to a specific revision
alembic downgrade revision_id
```

### View Migration History

To view the migration history:

```bash
# Show migration history
alembic history
```

### Get Current Revision

To check the current migration version:

```bash
# Show current revision
alembic current
```

## Troubleshooting

If you encounter issues with migrations:

1. Check that your database connection string is correct
2. Make sure all model files are imported in `migrations/env.py`
3. Verify that the migration script contains the expected changes
4. For import errors, ensure the project root is in your Python path

For more complex issues, check the alembic logs by running commands with `--verbose` flag.
