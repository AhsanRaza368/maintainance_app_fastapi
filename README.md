# Role-Based Maintenance App

A FastAPI-based maintenance and inspection platform for managing work orders, technician inspections, and role-based access control.

## Overview

This application allows an owner and admins to:

- create and manage work orders
- assign inspection workflows to technicians
- send inspection links by email
- collect inspection notes and image uploads
- validate technician signatures and uploaded images
- log actions for audit tracking

The project is built with:

- FastAPI
- SQLAlchemy
- PostgreSQL
- JWT-based authentication
- Docker and Docker Compose

## Project Structure

- `main.py` – application entry point
- `database.py` – database engine and session configuration
- `models.py` – SQLAlchemy data models
- `schemas.py` – request/response validation models
- `auth_utils.py` – authentication and authorization helpers
- `routes/auth.py` – API endpoints for authentication and work order handling
- `uploads/` – uploaded inspection media and related files
- `Dockerfile` – container image definition
- `docker-compose.yml` – local orchestration for API and PostgreSQL

## Features

- Owner-only initialization and admin creation
- Role-based login for `owner` and `admin`
- Work order creation with inspection token generation
- Email delivery of inspection links to technicians
- Image validation for inspection upload files
- Signature capture support for tenant and technician
- Audit logging for key user actions
- Static file serving for uploaded assets

## Requirements

- Python 3.11+
- PostgreSQL
- Docker and Docker Compose (optional, for local development)
- A valid `.env` file with required application configuration

## Environment Configuration

Create a `.env` file in the project root with values similar to the following:

```env
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_password
DATABASE_HOSTNAME=localhost
DATABASE_PORT=5432
DATABASE_NAME=role

OWNER_CODE=your_owner_code
OWNER_SECRET_KEY=your_owner_secret_key
ADMIN_SECRET_KEY=your_admin_secret_key
ALGORITHM=HS256

SMTP_EMAIL=your_email@example.com
SMTP_PASSWORD=your_email_password
SMTP_HOST=smtp.example.com
SMTP_PORT=587
```

The application uses `pydantic-settings` to load these values from `.env`.

## Running the Application

### Option 1: Local Python environment

1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the app:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

4. Open the API docs at:

```text
http://localhost:8000/docs
```

### Option 2: Docker Compose

```bash
docker-compose up --build
```

This starts:

- the FastAPI service on port `8000`
- a PostgreSQL service on port `5432`

## Database

The project uses PostgreSQL and creates tables automatically with:

```python
Base.metadata.create_all(bind=engine)
```

in `main.py` when the app starts.

## API Notes

This project exposes authentication and maintenance endpoints through FastAPI routes, including:

- `POST /owner_signup`
- `POST /owner_admin_login`
- `POST /create_admin`
- `POST /work_order`
- inspection-related routes generated during work order creation

The exact inspection workflow is implemented in `routes/auth.py` and may be extended depending on your maintenance process.

## Security and Validation

The app includes validation for:

- JWT authorization
- file type and image integrity checks
- duplicate owner/admin account prevention
- access control for owner-only actions

## License

This project does not include a license file. If you plan to distribute or reuse it, confirm the intended licensing terms before publishing.

## Notes

If you are extending the project, keep the following in mind:

- keep `.env` values private and do not commit secrets
- ensure `uploads/inspections` is writable by the app
- regularly review audit logs and work-order inspection workflows
