"""
Database Management Module: SQLite persistent storage for TraceMail.
"""
from backend.db.database import get_db_connection, init_db, store_email_analysis, list_cases

__all__ = ["get_db_connection", "init_db", "store_email_analysis", "list_cases"]
