"""Tests for UUID type validation in the database types module."""
import uuid

import pytest
from sqlalchemy import Column, String, create_engine
from sqlalchemy.orm import Session

from app.database.session import Base
from app.database.types import UUID


class MockUUIDModel(Base):
    """Test model with UUID primary key."""
    __tablename__ = "test_uuid_model"
    id = Column(UUID(), primary_key=True, default=UUID.create_default())
    name = Column(String(50))


def test_uuid_stores_and_retrieves_correctly():
    """UUID should store as string and retrieve as UUID object."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        test_uuid = uuid.uuid4()
        record = MockUUIDModel(id=test_uuid, name="test")
        session.add(record)
        session.commit()

        retrieved = session.query(MockUUIDModel).first()
        assert retrieved.id == test_uuid
        assert isinstance(retrieved.id, uuid.UUID)


def test_uuid_rejects_invalid_format():
    """UUID should reject invalid UUID strings."""
    from sqlalchemy.exc import StatementError

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        with pytest.raises(StatementError):
            record = MockUUIDModel(id="not-a-valid-uuid", name="test")
            session.add(record)
            session.commit()


def test_uuid_accepts_string_uuid():
    """UUID should accept valid UUID strings."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        test_uuid = uuid.uuid4()
        record = MockUUIDModel(id=str(test_uuid), name="test")
        session.add(record)
        session.commit()

        retrieved = session.query(MockUUIDModel).first()
        assert retrieved.id == test_uuid
        assert isinstance(retrieved.id, uuid.UUID)


def test_uuid_default_generates_unique_values():
    """UUID default should generate unique values for each record."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        record1 = MockUUIDModel(name="first")
        record2 = MockUUIDModel(name="second")
        session.add(record1)
        session.add(record2)
        session.commit()

        assert record1.id is not None
        assert record2.id is not None
        assert record1.id != record2.id
