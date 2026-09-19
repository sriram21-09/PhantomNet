import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Add backend directory and project root to sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
project_root = os.path.dirname(backend_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Interpret config file for logging
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import models to populate Base.metadata
from database.models import Base
try:
    import sentinel.models  # Ensure SentinelPlaybook is registered
except ImportError:
    pass

target_metadata = Base.metadata

# Retrieve DATABASE_URL dynamically if not explicitly specified in config
from database.database import DATABASE_URL
current_url = config.get_main_option("sqlalchemy.url")
if not current_url or "driver://user:pass" in current_url:
    target_url = os.getenv("DATABASE_URL", DATABASE_URL)
    if target_url:
        config.set_main_option("sqlalchemy.url", target_url.replace("%", "%%"))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True if url and "sqlite" in url else False,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section, {})
    effective_url = config.get_main_option("sqlalchemy.url") or os.getenv("DATABASE_URL", DATABASE_URL)
    if effective_url:
        configuration["sqlalchemy.url"] = effective_url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=is_sqlite,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
