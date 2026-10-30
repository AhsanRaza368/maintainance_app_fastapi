from pydantic import BaseModel, EmailStr
from pydantic import BaseModel, EmailStr, Field
from typing import Literal
from datetime import datetime


class create_Owner(BaseModel):

    name: str
    email: EmailStr
    password: str = Field(min_length=8)
    code: str


class create_admin(BaseModel):
    name: str
    email: EmailStr
    password: str


class login_owner_admin(BaseModel):
    email: EmailStr
    password: str


class Work_order(BaseModel):
    tenant_name: str
    tenant_phone: int
    technician_name: str
    technician_phone: int
    technician_email: EmailStr | None = None
    location: str
    category: str
    details: str


# =========================================================
# INSPECTION RESPONSE
# =========================================================

class Work_order_inspection_response(BaseModel):
    work_order_id: int
    inspection_id: int

    inspection: bool
    issue: bool

    image_upload1: str | None = None
    image_upload2: str | None = None

    tenant_signature: str | None = None
    technician_signature: str | None = None


class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    user_role: str
    user_email: str
    action: str
    work_order_id: int | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class DashboardWorkOrder(BaseModel):
    id: int

    tenant_name: str
    tenant_phone: int

    technician_name: str
    technician_phone: int
    technician_email: EmailStr | None = None

    location: str
    priority_time: int

    category: str
    details: str

    created_by_id: int
    created_by_role: str
    created_by_email: str

    status: str

    class Config:
        from_attributes = True


class DashboardResponse(BaseModel):
    total_work_orders: int
    assigned: int
    pending: int
    completed: int
    work_orders: list[DashboardWorkOrder]
