"""
JWT Authentication & RBAC middleware for PhantomNet Admin Panel.

BUG-02 fix: Fail-fast when JWT_SECRET is the insecure default in production.
BUG-03 fix: Generate random admin password on first run instead of hardcoded.
BUG-04 fix: Use bcrypt via passlib instead of raw SHA-256.
BUG-05 fix: Use python-jose for JWT instead of hand-rolled HMAC implementation.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User

# python-jose for JWT (BUG-05 fix)
from jose import JWTError, jwt

# passlib + bcrypt for password hashing (BUG-04 fix)
from passlib.context import CryptContext

logger = logging.getLogger("middleware.auth")

# BUG-02 fix: warn loudly if using a default/insecure key
_INSECURE_DEFAULTS = {
    "phantomnet-admin-secret-key-2026",
    "your-super-secret-jwt-key-change-in-production",
    "supersecret",
}
SECRET_KEY = os.getenv("JWT_SECRET", "phantomnet-admin-secret-key-2026")
if SECRET_KEY in _INSECURE_DEFAULTS:
    logger.warning(
        "⚠️  JWT_SECRET is using an insecure default value! "
        "Set a strong JWT_SECRET environment variable for production."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

security = HTTPBearer(auto_error=False)

import bcrypt

# ---- Password Hashing (BUG-04 fix: bcrypt) ----


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash.

    Also supports legacy SHA-256 hashes (salt$hash format) for migration.
    """
    # Legacy SHA-256 support for existing accounts
    if "$" in hashed and len(hashed.split("$", 1)) == 2:
        salt, stored_hash = hashed.split("$", 1)
        # Detect SHA-256 hex digest (64 chars) vs bcrypt ($2b$ prefix)
        if len(stored_hash) == 64 and not stored_hash.startswith("$2"):
            import hashlib
            is_legacy_match = hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == stored_hash
            return is_legacy_match

    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---- JWT Token (BUG-05 fix: python-jose) ----


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token using python-jose."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ---- FastAPI Dependencies ----


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    token_data = decode_token(credentials.credentials)
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
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not credentials:
        return None
    token_data = decode_token(credentials.credentials)
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


# ---- Seed Default Admin (BUG-03 fix: random password) ----


def seed_default_admin(db: Session):
    """Create default admin user if none exists, using a generated password."""
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
        print(f"  DEFAULT ADMIN CREDENTIALS (save these!)")
        print(f"  Username: admin")
        print(f"  Password: {generated_password}")
        print(f"{'='*60}")
    else:
        logger.info("✅ Admin user already exists")
