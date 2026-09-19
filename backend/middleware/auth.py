"""
JWT Authentication & RBAC middleware for PhantomNet.

Hardened for Production (Phase 1):
- Fail-fast when JWT_SECRET is insecure default in production
- Short-lived access tokens (default: 15 min)
- Refresh token families with cryptographic hashing (SHA-256)
- Automatic refresh token reuse / replay attack detection with immediate family revocation
- Cookie-based authentication support (HttpOnly, Secure, SameSite=Strict)
- WebSocket handshake authentication helper (rejects query param tokens)
- Step-up authentication tokens for high-risk operations (active defense)
- Bcrypt password hashing with legacy migration support
"""

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Any, Union

import bcrypt
from fastapi import Depends, HTTPException, Request, Response, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import RefreshToken, User

logger = logging.getLogger("middleware.auth")

# Insecure secret defaults that must never be used in production
_INSECURE_DEFAULTS = {
    "phantomnet-admin-secret-key-2026",
    "your-super-secret-jwt-key-change-in-production",
    "supersecret",
    "default_key",
    "secret",
}

SECRET_KEY = os.getenv("JWT_SECRET", "phantomnet-admin-secret-key-2026")
ENVIRONMENT = os.getenv("ENVIRONMENT", "local").lower()

# Fail-fast security check: In production or staging, reject insecure keys immediately
if ENVIRONMENT in ["production", "prod"] and SECRET_KEY in _INSECURE_DEFAULTS:
    raise RuntimeError(
        "FATAL: Insecure JWT_SECRET configured in production environment. "
        "You must configure a strong, unique secret key via the JWT_SECRET environment variable."
    )
elif SECRET_KEY in _INSECURE_DEFAULTS:
    logger.warning(
        "⚠️  JWT_SECRET is using an insecure default value! "
        "Set a strong JWT_SECRET environment variable for production."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # 15 minutes
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))      # 30 days

security = HTTPBearer(auto_error=False)


# ---- Password Hashing (bcrypt) ----


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


get_password_hash = hash_password


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash, with backward-compatibility for legacy SHA-256."""
    if "$" in hashed and len(hashed.split("$", 1)) == 2:
        salt, stored_hash = hashed.split("$", 1)
        if len(stored_hash) == 64 and not stored_hash.startswith("$2"):
            is_legacy_match = (
                hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == stored_hash
            )
            return is_legacy_match

    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---- JWT Access Tokens ----


def get_jwt_secret() -> str:
    """Returns active JWT secret key, supporting zero-downtime runtime rotation."""
    return os.getenv("JWT_SECRET") or SECRET_KEY


def get_previous_jwt_secret() -> Optional[str]:
    """Returns previous JWT secret key for dual-key fallback during rotation (SEC-10)."""
    return os.getenv("JWT_SECRET_PREVIOUS") or os.getenv("PREVIOUS_SECRET") or None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token using the active key."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, get_jwt_secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token with dual-key rotation support (SEC-10).
    Tries active JWT_SECRET first. If verification fails and JWT_SECRET_PREVIOUS
    is configured, attempts validation against the previous secret.
    """
    current_secret = get_jwt_secret()
    try:
        payload = jwt.decode(token, current_secret, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        # Dual-key fallback: check previous secret during key rotation window
        previous_secret = get_previous_jwt_secret()
        if previous_secret and previous_secret != current_secret:
            try:
                payload = jwt.decode(token, previous_secret, algorithms=[ALGORITHM])
                logger.info("Token validated using previous JWT secret during rotation window.")
                return payload
            except JWTError:
                pass
        return None


# ---- Refresh Token Families & Reuse Detection ----


def create_refresh_token(
    db: Session,
    user_id: int,
    family_id: Optional[str] = None,
    parent_id: Optional[int] = None,
) -> Tuple[str, RefreshToken]:
    """Generate an opaque cryptographically random refresh token and persist its SHA-256 hash."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    fam_id = family_id or str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    token_record = RefreshToken(
        user_id=user_id,
        family_id=fam_id,
        parent_id=parent_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(token_record)
    db.commit()
    db.refresh(token_record)
    return raw_token, token_record


def rotate_refresh_token(db: Session, raw_token: str) -> Tuple[str, str]:
    """Validate refresh token, detect reuse attacks, rotate token, and return (new_access_token, new_refresh_token).

    REUSE DETECTION:
    If a refresh token is presented that has already been rotated (rotated_at is set),
    an attacker is attempting a token replay! All tokens in that family are immediately
    revoked to protect the account, and an error is raised.
    """
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_record = (
        db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    )

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # 1. Check if explicitly revoked
    if token_record.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # 2. Check if expired
    if token_record.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    # 3. REUSE DETECTION: If token was already rotated, this is a token replay attack!
    if token_record.rotated_at is not None:
        logger.critical(
            "🚨 SECURITY ALERT: Refresh token reuse detected! Family: %s, User ID: %s. "
            "Revoking all tokens in family.",
            token_record.family_id,
            token_record.user_id,
        )
        db.query(RefreshToken).filter(
            RefreshToken.family_id == token_record.family_id
        ).update({"revoked_at": datetime.utcnow()})
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security violation: Refresh token reuse detected. All sessions in this family revoked. Please re-authenticate.",
        )

    # Mark existing token as rotated
    token_record.rotated_at = datetime.utcnow()

    # Issue new refresh token within the same family
    new_raw_refresh, _ = create_refresh_token(
        db=db,
        user_id=token_record.user_id,
        family_id=token_record.family_id,
        parent_id=token_record.id,
    )

    # Fetch user & issue new access token
    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user or user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    new_access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    db.commit()
    return new_access_token, new_raw_refresh


def revoke_token_family(db: Session, family_id: str):
    """Revoke all tokens in a family."""
    db.query(RefreshToken).filter(
        RefreshToken.family_id == family_id
    ).update({"revoked_at": datetime.utcnow()})
    db.commit()


def revoke_user_tokens(db: Session, user_id: int):
    """Revoke all active refresh tokens for a user."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()})
    db.commit()


# ---- Cookie Session Helpers ----


def set_auth_cookie(response: Response, token: str, max_age: Optional[int] = None):
    """Set HttpOnly, Secure, SameSite=Strict session cookie."""
    is_prod = ENVIRONMENT in ["production", "prod"]
    response.set_cookie(
        key="phantomnet_access_token",
        value=token,
        httponly=True,
        secure=is_prod,
        samesite="strict",
        max_age=max_age if max_age is not None else ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def set_refresh_cookie(response: Response, refresh_token: str):
    """Set HttpOnly, Secure, SameSite=Strict refresh token cookie."""
    is_prod = ENVIRONMENT in ["production", "prod"]
    response.set_cookie(
        key="phantomnet_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=is_prod,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/v1/admin",
    )


def clear_auth_cookie(response: Response):
    """Clear session and refresh cookies on logout."""
    is_prod = ENVIRONMENT in ["production", "prod"]
    response.delete_cookie(
        key="phantomnet_access_token",
        path="/",
        httponly=True,
        secure=is_prod,
        samesite="strict",
    )
    response.delete_cookie(
        key="phantomnet_refresh_token",
        path="/api/v1/admin",
        httponly=True,
        secure=is_prod,
        samesite="strict",
    )


# ---- Step-Up Authentication (Active Defense) ----


def create_step_up_token(user: Any) -> str:
    """Create short-lived 5-minute confirmation token for high-risk operations (blocking IP, etc.)."""
    username = user.username if hasattr(user, "username") else str(user)
    role = user.role if hasattr(user, "role") else "Admin"
    return create_access_token(
        data={"sub": username, "role": role, "type": "step_up"},
        expires_delta=timedelta(minutes=5),
    )


def verify_step_up_auth(step_up_token: Optional[str], user: User) -> bool:
    """Verify that a step-up token is valid, matches the current user, and has not expired."""
    if not step_up_token:
        return False
    payload = decode_token(step_up_token)
    if not payload:
        return False
    if payload.get("sub") != user.username or payload.get("type") != "step_up":
        return False
    return True


# ---- FastAPI Request & WebSocket Dependencies ----


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Extract and validate current authenticated user from Bearer header OR HttpOnly cookie."""
    raw_token = None
    if credentials:
        raw_token = credentials.credentials
    elif "phantomnet_access_token" in request.cookies:
        raw_token = request.cookies["phantomnet_access_token"]
    elif "access_token" in request.cookies:
        raw_token = request.cookies["access_token"]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    token_data = decode_token(raw_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    user = db.query(User).filter(User.username == token_data.get("sub")).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    if user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled"
        )
    return user


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Optionally extract authenticated user if token present; returns None otherwise."""
    raw_token = None
    if credentials:
        raw_token = credentials.credentials
    elif "phantomnet_access_token" in request.cookies:
        raw_token = request.cookies["phantomnet_access_token"]

    if not raw_token:
        return None

    token_data = decode_token(raw_token)
    if not token_data:
        return None

    user = db.query(User).filter(User.username == token_data.get("sub")).first()
    if not user or user.status != "active":
        return None
    return user


def require_role(*roles):
    """Dependency factory: require user has one of the given roles."""

    async def _check(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(roles)}",
            )
        return user

    return _check


def ws_authenticate(websocket: WebSocket, db: Session) -> Optional[User]:
    """Validate WebSocket handshake authentication via cookie or Authorization header.
    
    Rejects query parameter tokens to prevent token leakage in server logs and browser history.
    """
    raw_token = None
    # 1. Inspect HttpOnly Cookie
    if "phantomnet_access_token" in websocket.cookies:
        raw_token = websocket.cookies["phantomnet_access_token"]
    # 2. Inspect Authorization header
    elif "authorization" in websocket.headers:
        auth_hdr = websocket.headers["authorization"]
        if auth_hdr.startswith("Bearer "):
            raw_token = auth_hdr[7:]

    if not raw_token:
        return None

    token_data = decode_token(raw_token)
    if not token_data:
        return None

    username = token_data.get("sub")
    if not username:
        return None

    user = db.query(User).filter(User.username == username).first()
    if not user or user.status != "active":
        return None

    return user


# ---- Seed Default Admin ----


def seed_default_admin(db: Session):
    """Create default admin user if none exists, using a securely generated password."""
    existing = db.query(User).filter(User.role == "Admin").first()
    if not existing:
        generated_password = secrets.token_urlsafe(16)
        admin = User(
            username="admin",
            email="admin@phantomnet.local",
            hashed_password=hash_password(generated_password),
            role="Admin",
            status="active",
        )
        db.add(admin)
        db.commit()
        logger.info("✅ Default admin user created")
        print(f"{'='*60}")
        print("  DEFAULT ADMIN CREDENTIALS (save these!)")
        print("  Username: admin")
        print(f"  Password: {generated_password}")
        print(f"{'='*60}")
    else:
        logger.info("✅ Admin user already exists")
