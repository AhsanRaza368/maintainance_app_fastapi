from sqlalchemy.orm import Session
import smtplib
from jose import jwt, JWTError
from email.message import EmailMessage
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone
from html import escape
from io import BytesIO
from PIL import Image
from fastapi import (
    HTTPException,
    status,
    APIRouter,
    Depends,
    Request,
    UploadFile,
    File,
    Form,
    BackgroundTasks
)

from fastapi.security import HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, RedirectResponse

import schemas
import database
import models

from auth_utils import (
    create_owner_token,
    create_admin_token,
    get_current_owner,
    get_current_user,
    security
)

from config import settings


route = APIRouter(tags=["Authentication"])

# =========================================================
# FILE UPLOAD SETTINGS
# =========================================================

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

ALLOWED_IMAGE_TYPES = {
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/webp": [".webp"]
}


# =========================================================
# VALIDATE IMAGE UPLOAD
# =========================================================

def validate_image_upload(upload: UploadFile):
    if upload is None:
        return

    # ---------------------------------------------
    # CHECK CONTENT TYPE
    # ---------------------------------------------

    if upload.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid file type for '{upload.filename}'. "
                f"Only JPG, JPEG, PNG and WEBP are allowed."
            )
        )

    # ---------------------------------------------
    # CHECK FILE EXTENSION
    # ---------------------------------------------

    extension = Path(
        upload.filename or ""
    ).suffix.lower()

    allowed_extensions = ALLOWED_IMAGE_TYPES[
        upload.content_type
    ]

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid file extension for "
                f"'{upload.filename}'."
            )
        )

    # ---------------------------------------------
    # READ FILE
    # ---------------------------------------------

    upload.file.seek(0)

    file_data = upload.file.read()

    # ---------------------------------------------
    # CHECK EMPTY FILE
    # ---------------------------------------------

    if len(file_data) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File '{upload.filename}' is empty."
        )

    # ---------------------------------------------
    # CHECK FILE SIZE
    # ---------------------------------------------

    if len(file_data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"File '{upload.filename}' is too large. "
                f"Maximum size is 5 MB."
            )
        )

    # ---------------------------------------------
    # CHECK FILE SIGNATURE
    # ---------------------------------------------

    valid_file = False

    if upload.content_type == "image/jpeg":

        valid_file = file_data.startswith(
            b"\xff\xd8\xff"
        )

    elif upload.content_type == "image/png":

        valid_file = file_data.startswith(
            b"\x89PNG\r\n\x1a\n"
        )

    elif upload.content_type == "image/webp":

        valid_file = (
            file_data.startswith(b"RIFF")
            and file_data[8:12] == b"WEBP"
        )

    if not valid_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid image content in "
                f"'{upload.filename}'."
            )
        )

    # ---------------------------------------------
    # VERIFY ACTUAL IMAGE WITH PILLOW
    # ---------------------------------------------

    try:
        image = Image.open(
            BytesIO(file_data)
        )

        image.verify()

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid or corrupted image: "
                f"'{upload.filename}'"
            )
        )

    # ---------------------------------------------
    # RESET FILE POSITION
    # ---------------------------------------------

    upload.file.seek(0)


# =========================================================
# CREATE AUDIT LOG
# =========================================================

def create_audit_log(
    db: Session,
    user_id: int,
    user_role: str,
    user_email: str,
    action: str,
    work_order_id: int | None = None
):
    audit = models.AuditLog(
        user_id=user_id,
        user_role=user_role,
        user_email=user_email,
        action=action,
        work_order_id=work_order_id
    )

    db.add(audit)

    return audit


UPLOAD_DIR = Path("uploads/inspections")

UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# OWNER SIGNUP
# =========================================================

@route.post(
    "/owner_signup",
    status_code=status.HTTP_201_CREATED
)
def owner_signup(
    data: schemas.create_Owner,
    db: Session = Depends(database.get_db)
):

    # Only one Owner is allowed
    owner_try = db.query(models.Owner).count()

    if owner_try >= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Owner already exists"
        )

    # Check email
    owner_exist = db.query(models.Owner).filter(
        models.Owner.email == data.email
    ).first()

    if owner_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    # Check Owner code
    if settings.owner_code != data.code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authorized Person"
        )

    # Create Owner
    create_user = models.Owner(
        name=data.name,
        email=data.email,
        password=data.password,
        code=data.code
    )

    db.add(create_user)
    db.commit()
    db.refresh(create_user)

    return {
        "message": "Owner account initialized successfully"
    }


# =========================================================
# OWNER / ADMIN LOGIN
# =========================================================

# =========================================================
# OWNER / ADMIN LOGIN
# =========================================================

@route.post("/owner_admin_login")
def owner_admin_login(
    data: schemas.login_owner_admin,
    db: Session = Depends(database.get_db)
):

    # -----------------------------------------------------
    # CHECK OWNER
    # -----------------------------------------------------

    owner = db.query(models.Owner).filter(
        models.Owner.password == data.password,
        models.Owner.email == data.email
    ).first()

    if owner:

        access_token = create_owner_token(owner.id)

        create_audit_log(
            db=db,
            user_id=owner.id,
            user_role="owner",
            user_email=owner.email,
            action="LOGIN"
        )

        # One commit for login + audit log
        db.commit()

        return {
            "message": "Owner login successfully",
            "access_token": access_token,
            "token_type": "bearer",
            "role": "owner"
        }

    # -----------------------------------------------------
    # CHECK ADMIN
    # -----------------------------------------------------

    admin = db.query(models.Admin).filter(
        models.Admin.password == data.password,
        models.Admin.email == data.email
    ).first()

    if admin:

        access_token = create_admin_token(admin.id)

        create_audit_log(
            db=db,
            user_id=admin.id,
            user_role="admin",
            user_email=admin.email,
            action="LOGIN"
        )

        # One commit for login + audit log
        db.commit()

        return {
            "message": "Admin login successfully",
            "access_token": access_token,
            "token_type": "bearer",
            "role": "admin"
        }

    # -----------------------------------------------------
    # INVALID LOGIN
    # -----------------------------------------------------

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="You are not authorized to login"
    )

# =========================================================
# CREATE ADMIN
# ONLY OWNER CAN ACCESS THIS
# =========================================================


@route.post(
    "/create_admin",
    status_code=status.HTTP_201_CREATED
)
def create_admin(
    data: schemas.create_admin,
    db: Session = Depends(database.get_db),
    owner=Depends(get_current_owner)
):

    # Check if email already exists
    admin_exist = db.query(models.Admin).filter(
        models.Admin.email == data.email
    ).first()

    if admin_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Admin with this email already exists"
        )

    # Create Admin
    admin = models.Admin(
        name=data.name,
        email=data.email,
        password=data.password
    )

    db.add(admin)
    db.commit()
    db.refresh(admin)

    return {
        "message": "Admin created successfully",
        "admin_id": admin.id,
        "email": admin.email
    }


# =========================================================
# CREATE WORK ORDER
# BOTH OWNER AND ADMIN CAN CREATE WORK ORDER
# =========================================================

# =========================================================
# CREATE WORK ORDER
# BOTH OWNER AND ADMIN CAN CREATE WORK ORDER
# =========================================================

@route.post(
    "/work_order",
    status_code=status.HTTP_201_CREATED
)
def work_order(
    request: Request,
    data: schemas.Work_order,
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
    user=Depends(get_current_user)
):

    # -----------------------------------------------------
    # DETERMINE USER ROLE
    # -----------------------------------------------------

    if isinstance(user, models.Owner):

        user_role = "owner"

    elif isinstance(user, models.Admin):

        user_role = "admin"

    else:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid user"
        )

    # -----------------------------------------------------
    # CREATE WORK ORDER
    # -----------------------------------------------------

    order = models.Work_order(
        tenant_name=data.tenant_name,
        tenant_phone=data.tenant_phone,
        technician_name=data.technician_name,
        technician_phone=data.technician_phone,
        technician_email=data.technician_email,
        location=data.location,
        category=data.category,
        details=data.details,
        created_by_id=user.id,
        created_by_email=user.email,
        created_by_role=user_role
    )

    db.add(order)

    # -----------------------------------------------------
    # GET WORK ORDER ID BEFORE COMMIT
    # -----------------------------------------------------

    db.flush()

    # -----------------------------------------------------
    # GENERATE INSPECTION TOKEN
    # -----------------------------------------------------

    inspection_token = str(uuid.uuid4())

    # -----------------------------------------------------
    # CREATE INSPECTION RECORD
    # -----------------------------------------------------

    inspection = models.Work_order_inspection(
        inspection_token=inspection_token,
        work_order_id=order.id
    )

    db.add(inspection)

    # -----------------------------------------------------
    # CREATE AUDIT LOG
    # -----------------------------------------------------

    create_audit_log(
        db=db,
        user_id=user.id,
        user_role=user_role,
        user_email=user.email,
        action="CREATE_WORK_ORDER",
        work_order_id=order.id
    )

    # -----------------------------------------------------
    # ONE DATABASE COMMIT
    # -----------------------------------------------------

    db.commit()

    db.refresh(order)
    db.refresh(inspection)

    # -----------------------------------------------------
    # CREATE INSPECTION LINK
    # -----------------------------------------------------

    inspection_link = (
        str(request.base_url).rstrip("/")
        + f"/inspection/{inspection.inspection_token}"
    )

    # -----------------------------------------------------
    # SEND INSPECTION LINK TO TECHNICIAN
    # -----------------------------------------------------

    if data.technician_email:

        background_tasks.add_task(
            send_inspection_email,
            data.technician_email,
            order.id,
            inspection_link
        )

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {
        "message": "Work order created successfully",
        "work_order_id": order.id,
        "status": order.status,
        "created_by_email": user.email,
        "created_by_role": user_role,
        "inspection_link": inspection_link
    }


# =========================================================
# SEND INSPECTION LINK TO TECHNICIAN
# =========================================================

def send_inspection_email(
    technician_email: str,
    work_order_id: int,
    inspection_link: str
):
    try:

        if not technician_email:

            print(
                f"Inspection email not sent: "
                f"technician email is empty for work order #{work_order_id}"
            )

            return

        message = EmailMessage()

        message["Subject"] = (
            f"Work Order #{work_order_id} - Inspection Required"
        )

        message["From"] = settings.smtp_email
        message["To"] = technician_email

        message.set_content(
            f"""
Hello,

A work order has been assigned to you.

Work Order: #{work_order_id}

Please open the following link to start the job and complete the inspection:

{inspection_link}

Thank you.
"""
        )

        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port
        ) as server:

            server.starttls()

            server.login(
                settings.smtp_email,
                settings.smtp_password
            )

            server.send_message(message)

        print(
            f"Inspection email sent successfully "
            f"to {technician_email}"
        )

    except Exception as e:

        print(
            f"ERROR sending inspection email "
            f"for work order #{work_order_id}: {e}"
        )
# =========================================
# START INSPECTION
# =========================================


@route.post("/inspection/{inspection_token}/start")
def start_inspection(
    inspection_token: str,
    db: Session = Depends(database.get_db)
):
    inspection = db.query(
        models.Work_order_inspection
    ).filter(
        models.Work_order_inspection.inspection_token == inspection_token
    ).first()

    if not inspection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Inspection not found"
        )

    order = db.query(
        models.Work_order
    ).filter(
        models.Work_order.id == inspection.work_order_id
    ).first()

    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Work order not found"
        )

    # Block deleted work orders
    if order.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This work order has been deleted"
        )

    # Job can only be started from assigned status
    if order.status != "assigned":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Work order cannot be started from status '{order.status}'"
        )

    order.status = "pending"

    db.commit()
    db.refresh(order)

    return RedirectResponse(
        url=f"/inspection/{inspection_token}",
        status_code=status.HTTP_303_SEE_OTHER
    )


# =========================================
# OPEN INSPECTION
# =========================================

# =========================================
# OPEN INSPECTION
# =========================================

@route.get(
    "/inspection/{inspection_token}",
    response_class=HTMLResponse
)
def open_inspection(
    inspection_token: str,
    db: Session = Depends(database.get_db)
):
    inspection = db.query(
        models.Work_order_inspection
    ).filter(
        models.Work_order_inspection.inspection_token == inspection_token
    ).first()

    if not inspection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Inspection not found"
        )

    order = db.query(
        models.Work_order
    ).filter(
        models.Work_order.id == inspection.work_order_id
    ).first()

    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Work order not found"
        )

    # =========================================
    # BLOCK DELETED WORK ORDERS
    # =========================================

    if order.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This work order has been deleted"
        )

    # =========================================
    # ESCAPE DATABASE VALUES FOR HTML
    # =========================================

    tenant_name = escape(
        str(order.tenant_name or "")
    )

    tenant_phone = escape(
        str(order.tenant_phone or "")
    )

    technician_name = escape(
        str(order.technician_name or "")
    )

    technician_phone = escape(
        str(order.technician_phone or "")
    )

    location = escape(
        str(order.location or "")
    )

    category = escape(
        str(order.category or "")
    )

    details = escape(
        str(order.details or "")
    )

    priority_time = escape(
        str(order.priority_time or "")
    )

    # =========================================
    # ASSIGNED
    # =========================================

    if order.status == "assigned":
        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Work Order #{order.id}</title>
            </head>

            <body>

                <h2>Work Order #{order.id}</h2>

                <p>
                    <strong>Tenant Name:</strong>
                    {tenant_name}
                </p>

                <p>
                    <strong>Tenant Phone:</strong>
                    {tenant_phone}
                </p>

                <p>
                    <strong>Technician Name:</strong>
                    {technician_name}
                </p>

                <p>
                    <strong>Technician Phone:</strong>
                    {technician_phone}
                </p>

                <p>
                    <strong>Location:</strong>
                    {location}
                </p>

                <p>
                    <strong>Priority Time:</strong>
                    {priority_time}
                </p>

                <p>
                    <strong>Category:</strong>
                    {category}
                </p>

                <p>
                    <strong>Details:</strong>
                    {details}
                </p>

                <p>
                    <strong>Status:</strong>
                    Assigned
                </p>

                <form
                    method="post"
                    action="/inspection/{inspection_token}/start"
                >
                    <button type="submit">
                        Start Job
                    </button>
                </form>

            </body>
            </html>
            """
        )

    # =========================================
    # PENDING
    # =========================================

    elif order.status == "pending":
        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Inspection - Work Order #{order.id}</title>
            </head>

            <body>

                <h2>Inspection - Work Order #{order.id}</h2>

                <p>
                    <strong>Tenant Name:</strong>
                    {tenant_name}
                </p>

                <p>
                    <strong>Tenant Phone:</strong>
                    {tenant_phone}
                </p>

                <p>
                    <strong>Technician Name:</strong>
                    {technician_name}
                </p>

                <p>
                    <strong>Technician Phone:</strong>
                    {technician_phone}
                </p>

                <p>
                    <strong>Location:</strong>
                    {location}
                </p>

                <p>
                    <strong>Priority Time:</strong>
                    {priority_time}
                </p>

                <p>
                    <strong>Category:</strong>
                    {category}
                </p>

                <p>
                    <strong>Details:</strong>
                    {details}
                </p>

                <p>
                    <strong>Status:</strong>
                    Pending
                </p>

                <hr>

                <form
                    method="post"
                    action="/inspection/{inspection_token}/submit"
                    enctype="multipart/form-data"
                >

                    <h3>Inspection</h3>

                    <label>
                        <input
                            type="checkbox"
                            name="inspection"
                            value="true"
                        >
                        Inspection Completed
                    </label>

                    <br><br>

                    <label>
                        <input
                            type="checkbox"
                            name="issue"
                            value="true"
                        >
                        Issue Found
                    </label>

                    <br><br>

                    <label>
                        Image Upload 1:
                    </label>

                    <input
                        type="file"
                        name="image_upload1"
                        accept="image/*"
                    >

                    <br><br>

                    <label>
                        Image Upload 2:
                    </label>

                    <input
                        type="file"
                        name="image_upload2"
                        accept="image/*"
                    >

                    <br><br>

                    <label>
                        Tenant Signature:
                    </label>

                    <input
                        type="file"
                        name="tenant_signature"
                        accept="image/*"
                        required
                    >

                    <br><br>

                    <label>
                        Technician Signature:
                    </label>

                    <input
                        type="file"
                        name="technician_signature"
                        accept="image/*"
                        required
                    >

                    <br><br>

                    <button type="submit">
                        Submit Inspection
                    </button>

                </form>

            </body>
            </html>
            """
        )

    # =========================================
    # COMPLETED
    # =========================================

    elif order.status == "completed":
        return HTMLResponse(
            f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Work Order Completed</title>
            </head>

            <body>

                <h2>Work Order #{order.id}</h2>

                <h3>Inspection Completed</h3>

                <p>
                    This work order has already been completed.
                </p>

                <p>
                    <strong>Status:</strong>
                    Completed
                </p>

            </body>
            </html>
            """
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid work order status"
        )

# =========================================
# SUBMIT INSPECTION
# =========================================


@route.post("/inspection/{inspection_token}/submit")
def submit_inspection(
    inspection_token: str,
    background_tasks: BackgroundTasks,

    inspection: bool = Form(False),
    issue: bool = Form(False),

    image_upload1: UploadFile | None = File(None),
    image_upload2: UploadFile | None = File(None),

    tenant_signature: UploadFile | None = File(None),
    technician_signature: UploadFile | None = File(None),

    db: Session = Depends(database.get_db)
):
    inspection_record = db.query(
        models.Work_order_inspection
    ).filter(
        models.Work_order_inspection.inspection_token == inspection_token
    ).first()

    if not inspection_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Inspection not found"
        )

    order = db.query(
        models.Work_order
    ).filter(
        models.Work_order.id == inspection_record.work_order_id
    ).first()

    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Work order not found"
        )

    # =========================================
    # BLOCK DELETED WORK ORDERS
    # =========================================

    if order.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This work order has been deleted"
        )

    # =========================================
    # INSPECTION CAN ONLY BE SUBMITTED
    # WHILE WORK ORDER IS PENDING
    # =========================================

    if order.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Inspection cannot be submitted "
                f"from status '{order.status}'"
            )
        )

    # =========================================
    # INSPECTION CHECKBOX IS REQUIRED
    # =========================================

    if not inspection:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inspection must be completed"
        )

    # =========================================
    # TENANT SIGNATURE IS REQUIRED
    # =========================================

    if tenant_signature is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant signature is required"
        )

    # =========================================
    # TECHNICIAN SIGNATURE IS REQUIRED
    # =========================================

    if technician_signature is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Technician signature is required"
        )

    # =========================================
    # VALIDATE UPLOADED FILES
    # =========================================

    if image_upload1 is not None:
        validate_image_upload(image_upload1)

    if image_upload2 is not None:
        validate_image_upload(image_upload2)

    validate_image_upload(tenant_signature)
    validate_image_upload(technician_signature)

    # =========================================
    # SAVE INSPECTION DATA
    # =========================================

    inspection_record.inspection = inspection
    inspection_record.issue = issue

    # =========================================
    # SAVE IMAGE 1
    # =========================================

    if image_upload1 is not None:
        image1_extension = Path(
            image_upload1.filename
        ).suffix

        image1_filename = (
            f"{uuid.uuid4()}{image1_extension}"
        )

        image1_path = UPLOAD_DIR / image1_filename

        with image1_path.open("wb") as buffer:
            shutil.copyfileobj(
                image_upload1.file,
                buffer
            )

        inspection_record.image_upload1 = str(
            image1_path
        )

    # =========================================
    # SAVE IMAGE 2
    # =========================================

    if image_upload2 is not None:
        image2_extension = Path(
            image_upload2.filename
        ).suffix

        image2_filename = (
            f"{uuid.uuid4()}{image2_extension}"
        )

        image2_path = UPLOAD_DIR / image2_filename

        with image2_path.open("wb") as buffer:
            shutil.copyfileobj(
                image_upload2.file,
                buffer
            )

        inspection_record.image_upload2 = str(
            image2_path
        )

    # =========================================
    # SAVE TENANT SIGNATURE
    # =========================================

    tenant_extension = Path(
        tenant_signature.filename
    ).suffix

    tenant_filename = (
        f"{uuid.uuid4()}{tenant_extension}"
    )

    tenant_path = UPLOAD_DIR / tenant_filename

    with tenant_path.open("wb") as buffer:
        shutil.copyfileobj(
            tenant_signature.file,
            buffer
        )

    inspection_record.tenant_signature = str(
        tenant_path
    )

    # =========================================
    # SAVE TECHNICIAN SIGNATURE
    # =========================================

    technician_extension = Path(
        technician_signature.filename
    ).suffix

    technician_filename = (
        f"{uuid.uuid4()}{technician_extension}"
    )

    technician_path = UPLOAD_DIR / technician_filename

    with technician_path.open("wb") as buffer:
        shutil.copyfileobj(
            technician_signature.file,
            buffer
        )

    inspection_record.technician_signature = str(
        technician_path
    )

    # =========================================
    # COMPLETE WORK ORDER
    # =========================================

    order.status = "completed"

    db.commit()

    db.refresh(order)
    db.refresh(inspection_record)

    # =========================================
    # SEND COMPLETION EMAIL
    # =========================================

    background_tasks.add_task(
        send_completion_email,
        order.created_by_email,
        order.id,
        order.created_by_role
    )

    # =========================================
    # RESPONSE
    # =========================================

    return {
        "message": "Inspection submitted successfully",
        "work_order_id": order.id,
        "status": order.status,
        "created_by_email": order.created_by_email,
        "created_by_role": order.created_by_role
    }
# =========================================================
# DELETE WORK ORDER
# =========================================================


# =========================================================
# DELETE WORK ORDER
# =========================================================

# =========================================================
# DELETE WORK ORDER
# =========================================================

@route.delete(
    "/work_order/{work_order_id}"
)
def delete_work_order(
    work_order_id: int,
    db: Session = Depends(database.get_db),
    user=Depends(get_current_user)
):

    # -----------------------------------------------------
    # FIND WORK ORDER
    # -----------------------------------------------------

    order = db.query(
        models.Work_order
    ).filter(
        models.Work_order.id == work_order_id
    ).first()

    if order is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Work order not found"
        )

    # =====================================================
    # CHECK IF ALREADY DELETED
    # =====================================================

    if order.deleted_at is not None:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Work order is already in recycle bin"
        )

    # =====================================================
    # OWNER CAN DELETE IN ANY STATUS
    # =====================================================

    if isinstance(user, models.Owner):

        # -------------------------------------------------
        # SOFT DELETE
        # -------------------------------------------------

        order.deleted_at = datetime.now(timezone.utc)
        order.deleted_by_id = user.id
        order.deleted_by_role = "owner"
        order.deleted_by_email = user.email

        # -------------------------------------------------
        # CREATE AUDIT LOG
        # -------------------------------------------------

        create_audit_log(
            db=db,
            user_id=user.id,
            user_role="owner",
            user_email=user.email,
            action="DELETE_WORK_ORDER",
            work_order_id=work_order_id
        )

        # -------------------------------------------------
        # ONE DATABASE COMMIT
        # -------------------------------------------------

        db.commit()

        return {
            "message": "Work order moved to recycle bin",
            "work_order_id": work_order_id,
            "deleted_by_role": "owner",
            "deleted_by_email": user.email,
            "deleted_at": order.deleted_at
        }

    # =====================================================
    # ADMIN CAN DELETE ONLY ASSIGNED WORK ORDERS
    # =====================================================

    if isinstance(user, models.Admin):

        if order.status != "assigned":

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin can delete only assigned work orders"
            )

        # -------------------------------------------------
        # SOFT DELETE
        # -------------------------------------------------

        order.deleted_at = datetime.now(timezone.utc)
        order.deleted_by_id = user.id
        order.deleted_by_role = "admin"
        order.deleted_by_email = user.email

        # -------------------------------------------------
        # CREATE AUDIT LOG
        # -------------------------------------------------

        create_audit_log(
            db=db,
            user_id=user.id,
            user_role="admin",
            user_email=user.email,
            action="DELETE_WORK_ORDER",
            work_order_id=work_order_id
        )

        # -------------------------------------------------
        # ONE DATABASE COMMIT
        # -------------------------------------------------

        db.commit()

        return {
            "message": "Work order moved to recycle bin",
            "work_order_id": work_order_id,
            "deleted_by_role": "admin",
            "deleted_by_email": user.email,
            "deleted_at": order.deleted_at
        }

    # =====================================================
    # INVALID ROLE
    # =====================================================

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You are not allowed to delete this work order"
    )


@route.get("/recycle_bin")
def recycle_bin(
    db: Session = Depends(database.get_db),
    user=Depends(get_current_user)
):
    # Only Admin can access Recycle Bin
    if not isinstance(user, models.Admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin can access recycle bin"
        )

    # Get only deleted work orders
    deleted_orders = (
        db.query(models.Work_order)
        .filter(
            models.Work_order.deleted_at.is_not(None)
        )
        .order_by(
            models.Work_order.deleted_at.desc()
        )
        .all()
    )

    return {
        "message": "Recycle bin",
        "work_orders": deleted_orders
    }


# =========================================================
# LOGOUT
# =========================================================

@route.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(database.get_db)
):

    token = credentials.credentials

    try:

        # ---------------------------------------------
        # TRY OWNER TOKEN
        # ---------------------------------------------

        try:

            payload = jwt.decode(
                token,
                settings.owner_secret_key,
                algorithms=[settings.algorithm]
            )

        except JWTError:

            # -----------------------------------------
            # TRY ADMIN TOKEN
            # -----------------------------------------

            payload = jwt.decode(
                token,
                settings.admin_secret_key,
                algorithms=[settings.algorithm]
            )

        jti = payload.get("jti")
        exp = payload.get("exp")
        user_id = payload.get("sub")
        user_role = payload.get("role")

        # ---------------------------------------------
        # CHECK REQUIRED TOKEN DATA
        # ---------------------------------------------

        if not jti or not exp or not user_id or not user_role:

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # ---------------------------------------------
        # VALIDATE USER ID
        # ---------------------------------------------

        try:

            user_id = int(user_id)

        except (ValueError, TypeError):

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user ID in token"
            )

        # ---------------------------------------------
        # CHECK IF ALREADY REVOKED
        # ---------------------------------------------

        existing_token = db.query(
            models.RevokedToken
        ).filter(
            models.RevokedToken.jti == jti
        ).first()

        if existing_token:

            return {
                "message": "Already logged out"
            }

        # ---------------------------------------------
        # GET LOGGED-IN USER
        # ---------------------------------------------

        if user_role == "owner":

            logged_in_user = db.query(
                models.Owner
            ).filter(
                models.Owner.id == user_id
            ).first()

        elif user_role == "admin":

            logged_in_user = db.query(
                models.Admin
            ).filter(
                models.Admin.id == user_id
            ).first()

        else:

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user role"
            )

        # ---------------------------------------------
        # CHECK USER EXISTS
        # ---------------------------------------------

        if logged_in_user is None:

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        # ---------------------------------------------
        # SAVE REVOKED TOKEN
        # ---------------------------------------------

        revoked_token = models.RevokedToken(
            jti=jti,
            expires_at=datetime.fromtimestamp(
                exp,
                tz=timezone.utc
            )
        )

        db.add(revoked_token)
        db.commit()

        # ---------------------------------------------
        # CREATE LOGOUT AUDIT
        # ---------------------------------------------

        create_audit_log(
            db=db,
            user_id=user_id,
            user_role=user_role,
            user_email=logged_in_user.email,
            action="LOGOUT"
        )

        return {
            "message": "Logout successful"
        }

    except JWTError:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


@route.get("/dashboard", response_model=schemas.DashboardResponse)
def dashboard(
    db: Session = Depends(database.get_db),
    user=Depends(get_current_user)
):
    # Determine logged-in user's role
    if isinstance(user, models.Owner):
        role = "Owner"

    elif isinstance(user, models.Admin):
        role = "Admin"

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid user role"
        )

    # Get only active work orders
    # Deleted work orders are excluded from dashboard
    work_orders = (
        db.query(models.Work_order)
        .filter(
            models.Work_order.deleted_at.is_(None)
        )
        .order_by(
            models.Work_order.id.desc()
        )
        .all()
    )

    # Calculate counts from active work orders only
    total = len(work_orders)

    assigned = sum(
        1
        for order in work_orders
        if order.status == "assigned"
    )

    pending = sum(
        1
        for order in work_orders
        if order.status == "pending"
    )

    completed = sum(
        1
        for order in work_orders
        if order.status == "completed"
    )

    return {
        "role": role,
        "total": total,
        "assigned": assigned,
        "pending": pending,
        "completed": completed,
        "work_orders": work_orders
    }
