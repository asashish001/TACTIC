"""Custom SQLAlchemy types for UUID handling.

Provides a UUID type that stores as 16-byte binary for efficient indexing
and comparison, while presenting as a Python UUID object to application code.
"""
import uuid as _uuid

from sqlalchemy import LargeBinary, String
from sqlalchemy.types import TypeDecorator, CHAR


class UUID(TypeDecorator):
    """Platform-independent UUID type.

    Uses CHAR(36) for storage, which stores the UUID as a 36-character
    hex string. This provides:
    - Format validation (only valid UUIDs can be stored)
    - Proper indexing (string comparison is faster than text)
    - Application code works with Python UUID objects directly
    """
    impl = CHAR
    cache_ok = True

    def __init__(self):
        super().__init__(length=36)

    def process_bind_param(self, value, dialect):
        """Convert Python UUID to string for database storage."""
        if value is not None:
            if isinstance(value, _uuid.UUID):
                return str(value)
            # Accept string UUIDs and validate them
            try:
                return str(_uuid.UUID(value))
            except (ValueError, AttributeError) as exc:
                raise ValueError(f"Invalid UUID format: {value}") from exc
        return value

    def process_result_value(self, value, dialect):
        """Convert database string back to Python UUID."""
        if value is not None:
            return _uuid.UUID(value)
        return value

    @staticmethod
    def create_default():
        """Return a callable that generates a new UUID."""
        return lambda: _uuid.uuid4()
