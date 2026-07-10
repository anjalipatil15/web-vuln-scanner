from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite file lives at app/database/scanner.db
SQLALCHEMY_DATABASE_URL = "sqlite:///./app/database/scanner.db"

# check_same_thread=False is required for SQLite when used with FastAPI,
# since FastAPI can handle requests across multiple threads.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# All ORM models (Scan, Finding, Asset) will inherit from this Base.
Base = declarative_base()

def get_db():
    """
    FastAPI dependency that yields a database session and
    guarantees it's closed after the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

