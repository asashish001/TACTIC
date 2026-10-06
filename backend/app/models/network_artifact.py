import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class NetworkArtifact(Base):
    __tablename__ = "network_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    timestamp: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(30), nullable=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    extracted_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="network_artifacts")
    case: Mapped["Case"] = relationship("Case", back_populates="network_artifacts")
