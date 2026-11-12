"""Production WSGI entry point with first-start database initialization."""

from app import app
from run import initialize_database


initialize_database()
