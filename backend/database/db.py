"""
ScamShield Database Module
SQLAlchemy database initialization and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager

from backend.config import config

# Create engine
engine = create_engine(
    config.SQLALCHEMY_DATABASE_URI,
    echo=config.FLASK_DEBUG,
    pool_pre_ping=True,
    pool_recycle=3600
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create scoped session
db_session = scoped_session(SessionLocal)

# Create base class for models
Base = declarative_base()


def init_db():
    """Initialize database tables"""
    from backend.database.models import User, Email, ScanResult, Alert, BlacklistEntry
    Base.metadata.create_all(bind=engine)


def drop_db():
    """Drop all database tables"""
    Base.metadata.drop_all(bind=engine)


@contextmanager
def get_session():
    """Get database session context manager"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db():
    """Get database session for dependency injection"""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def reset_db():
    """Reset database (drop and recreate)"""
    drop_db()
    init_db()
