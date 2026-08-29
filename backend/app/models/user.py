import datetime
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from app.database.session import Base, engine

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    role = Column(String(20), nullable=False, default="investigator") # admin, investigator, student, viewer
    timezone = Column(String(50), nullable=False, default="UTC")
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    token_version = Column(Integer, nullable=False, default=0)
    refresh_token_jtis = Column(String(500), nullable=True, default="[]")  # JSON array of valid JTI strings

    cases = relationship("Case", back_populates="created_by", cascade="all, delete-orphan")
