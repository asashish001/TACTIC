import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.database.session import Base


class SystemSetting(Base):
    """Stores persisted system configuration values such as anomaly detection thresholds."""
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(80), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
