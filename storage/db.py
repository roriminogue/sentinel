"""Database connection and session handling."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

DEFAULT_DB_PATH = "sentinel.db"


def make_engine(db_path: str = DEFAULT_DB_PATH) -> Engine:
    """Create an engine and ensure the schema is up to date."""
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    return engine


def _add_missing_columns(engine: Engine) -> None:
    """Add columns present on the models but missing from an existing database.

    As the framework grows it gains new fields, and a database written by an
    earlier version would otherwise have to be deleted — losing real results.
    SQLite cannot drop or retype a column, but ADD COLUMN is cheap and covers
    every change made so far.
    """
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                spec = f"{column.name} {column.type.compile(engine.dialect)}"
                if not column.nullable:
                    spec += f" NOT NULL DEFAULT {_default_literal(column)}"
                conn.exec_driver_sql(f"ALTER TABLE {table.name} ADD COLUMN {spec}")


def _default_literal(column) -> str:
    value = getattr(column.default, "arg", None)
    if isinstance(value, bool) or value is None:
        return "1" if value is True else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return f"'{value}'"


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope around a series of operations."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
