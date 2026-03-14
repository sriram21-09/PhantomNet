"""
JWT Authentication & RBAC middleware for PhantomNet Admin Panel.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import User
import hashlib
import hmac
import base64
import json
import os

SECRET_KEY = os.getenv("JWT_SECRET", "phantomnet-admin-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

security = HTTPBearer(auto_error=False)


# ---- Password Hashing (simple SHA256 + salt, no extra deps) ----


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, stored_hash = hashed.split("$", 1)
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == stored_hash
    except Exception:
        return False


# ---- JWT Token (minimal, no extra deps) ----


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire.timestamp()

    header = _b64_encode(json.dumps({"alg": ALGORITHM, "typ": "JWT"}).encode())
    payload = _b64_encode(json.dumps(to_encode, default=str).encode())
    signature = hmac.new(
        SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    return f"{header}.{payload}.{signature}"


def decode_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, signature = parts
        expected_sig = hmac.new(
            SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return None
        data = json.loads(_b64_decode(payload))
        if data.get("exp", 0) < datetime.utcnow().timestamp():
            return None
        return data
    except Exception:
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


# ---- Seed Default Admin ----


def seed_default_admin(db: Session):
    """Create default admin user if none exists."""
    existing = db.query(User).filter(User.role == "Admin").first()
    if not existing:
        admin = User(
            username="admin",
            email="admin@phantomnet.local",
            hashed_password=hash_password("admin123"),
            role="Admin",
            status="active",
        )
        db.add(admin)
        db.commit()
        print("✅ Default admin user created (admin / admin123)")
    else:
        print("✅ Admin user already exists")
