from sqlalchemy import String, Integer, Column, Boolean, ForeignKey, DateTime
from database import Base
from datetime import datetime, timedelta, timezone


class Owner(Base):
    __tablename__ = "owner"
    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    code = Column(String, nullable=False, unique=True)


class Admin(Base):
    __tablename__ = "admin"
    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)


class Work_order(Base):
    __tablename__ = "work_order"
    id = Column(Integer, primary_key=True, nullable=False)
    tenant_name = Column(String, nullable=False)
    tenant_phone = Column(Integer, nullable=False)
    technician_name = Column(String, nullable=False)
    technician_phone = Column(Integer, nullable=False)
    technician_email = Column(String, nullable=True)
    location = Column(String, nullable=False)
    priority_time = Column(Integer, default=72)
    category = Column(String, nullable=False)
    details = Column(String, nullable=False)
    created_by_id = Column(Integer, nullable=False)
    created_by_role = Column(String, nullable=False)
    created_by_email = Column(String, nullable=False)
    status = Column(String, nullable=False, default="assigned")

    # For soft delete
    deleted_at = Column(DateTime, nullable=True)
    deleted_by_id = Column(Integer, nullable=True)
    deleted_by_role = Column(String, nullable=True)
    deleted_by_email = Column(String, nullable=True)


class Work_order_inspection(Base):
    __tablename__ = "work_order_inspection"

    id = Column(Integer, primary_key=True, nullable=False)
    inspection_token = Column(String, nullable=False, unique=True, index=True)
    inspection = Column(Boolean, nullable=False, default=False)
    issue = Column(Boolean, nullable=False, default=False)
    image_upload1 = Column(String, nullable=True)
    image_upload2 = Column(String, nullable=True)
    tenant_signature = Column(String, nullable=True)
    technician_signature = Column(String, nullable=True)
    work_order_id = Column(Integer, ForeignKey(
        "work_order.id", ondelete="CASCADE"), nullable=False, unique=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)

    jti = Column(String, unique=True, nullable=False, index=True)

    expires_at = Column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, nullable=False)
    user_role = Column(String, nullable=False)
    user_email = Column(String, nullable=False)

    action = Column(String, nullable=False)

    work_order_id = Column(Integer, nullable=True)

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow
    )
