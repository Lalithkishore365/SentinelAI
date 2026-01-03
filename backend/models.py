from datetime import datetime
from typing import Optional


# Simple dictionary-based models (no pydantic)

def UserRegister(username: str, email: str, password: str):
    return {
        "username": username,
        "email": email,
        "password": password
    }


def UserLogin(username: str, password: str):
    return {
        "username": username,
        "password": password
    }


def TokenResponse(access_token: str, refresh_token: str, user_id: int, expires_in: int):
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": user_id,
        "expires_in": expires_in
    }


def UserResponse(user_id: int, username: str, email: str, created_at: datetime, is_active: bool):
    return {
        "user_id": user_id,
        "username": username,
        "email": email,
        "created_at": created_at.isoformat(),
        "is_active": is_active
    }


def SessionResponse(session_id: str, user_id: int, ip_address: str, login_time: datetime, 
                   logout_time: Optional[datetime], is_authenticated: bool, expires_at: datetime):
    return {
        "session_id": session_id,
        "user_id": user_id,
        "ip_address": ip_address,
        "login_time": login_time.isoformat(),
        "logout_time": logout_time.isoformat() if logout_time else None,
        "is_authenticated": is_authenticated,
        "expires_at": expires_at.isoformat()
    }
