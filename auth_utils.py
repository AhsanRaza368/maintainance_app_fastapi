from datetime import datetime, timedelta, timezone
import uuid

from jose import jwt, JWTError

from fastapi import (
    HTTPException,
    status,
    Depends
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

from sqlalchemy.orm import Session

from config import settings
import database
import models


OWNER_SECRET_KEY = settings.owner_secret_key
ADMIN_SECRET_KEY = settings.admin_secret_key

ALGORITHM = settings.algorithm


security = HTTPBearer()


# =========================================================
# CREATE OWNER TOKEN
# =========================================================

def create_owner_token(owner_id: int):

    jti = str(uuid.uuid4())

    payload = {
        "sub": str(owner_id),
        "role": "owner",
        "jti": jti,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }

    return jwt.encode(
        payload,
        OWNER_SECRET_KEY,
        algorithm=ALGORITHM
    )

# =========================================================
# CREATE ADMIN TOKEN
# =========================================================


def create_admin_token(admin_id: int):

    jti = str(uuid.uuid4())

    payload = {
        "sub": str(admin_id),
        "role": "admin",
        "jti": jti,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }

    return jwt.encode(
        payload,
        ADMIN_SECRET_KEY,
        algorithm=ALGORITHM
    )


# =========================================================
# CHECK TOKEN REVOCATION
# =========================================================

def is_token_revoked(
    jti: str,
    db: Session
):

    revoked_token = db.query(
        models.RevokedToken
    ).filter(
        models.RevokedToken.jti == jti
    ).first()

    return revoked_token is not None


# =========================================================
# GET CURRENT OWNER
# ONLY OWNER
# =========================================================

def get_current_owner(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(database.get_db)
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            OWNER_SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        owner_id = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")

        # ---------------------------------------------
        # CHECK REQUIRED TOKEN DATA
        # ---------------------------------------------

        if owner_id is None or jti is None:

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid owner token"
            )

        # ---------------------------------------------
        # CHECK TOKEN REVOCATION
        # ---------------------------------------------

        if is_token_revoked(jti, db):

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        # ---------------------------------------------
        # CHECK ROLE
        # ---------------------------------------------

        if role != "owner":

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Owner access required"
            )

        # ---------------------------------------------
        # VALIDATE OWNER ID
        # ---------------------------------------------

        try:

            owner_id = int(owner_id)

        except (ValueError, TypeError):

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid owner ID in token"
            )

        # ---------------------------------------------
        # FIND OWNER
        # ---------------------------------------------

        owner = db.query(
            models.Owner
        ).filter(
            models.Owner.id == owner_id
        ).first()

        if owner is None:

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Owner no longer exists"
            )

        return owner

    except JWTError:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired owner token"
        )


# =========================================================
# GET CURRENT USER
# OWNER OR ADMIN
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(database.get_db)
):

    token = credentials.credentials

    # =====================================================
    # CHECK OWNER TOKEN
    # =====================================================

    try:

        payload = jwt.decode(
            token,
            OWNER_SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")

        if user_id and role == "owner":

            # ---------------------------------------------
            # CHECK JTI
            # ---------------------------------------------

            if not jti:

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )

            # ---------------------------------------------
            # CHECK REVOCATION
            # ---------------------------------------------

            if is_token_revoked(jti, db):

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )

            # ---------------------------------------------
            # VALIDATE USER ID
            # ---------------------------------------------

            try:

                user_id = int(user_id)

            except (ValueError, TypeError):

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid owner ID in token"
                )

            # ---------------------------------------------
            # FIND OWNER
            # ---------------------------------------------

            owner = db.query(
                models.Owner
            ).filter(
                models.Owner.id == user_id
            ).first()

            if owner:

                return owner

    except JWTError:

        pass

    # =====================================================
    # CHECK ADMIN TOKEN
    # =====================================================

    try:

        payload = jwt.decode(
            token,
            ADMIN_SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")

        if user_id and role == "admin":

            # ---------------------------------------------
            # CHECK JTI
            # ---------------------------------------------

            if not jti:

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )

            # ---------------------------------------------
            # CHECK REVOCATION
            # ---------------------------------------------

            if is_token_revoked(jti, db):

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )

            # ---------------------------------------------
            # VALIDATE USER ID
            # ---------------------------------------------

            try:

                user_id = int(user_id)

            except (ValueError, TypeError):

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid admin ID in token"
                )

            # ---------------------------------------------
            # FIND ADMIN
            # ---------------------------------------------

            admin = db.query(
                models.Admin
            ).filter(
                models.Admin.id == user_id
            ).first()

            if admin:

                return admin

    except JWTError:

        pass

    # =====================================================
    # INVALID TOKEN
    # =====================================================

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token"
    )
