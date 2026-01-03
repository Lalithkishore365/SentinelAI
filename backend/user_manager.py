from db_connection import get_connection
from auth import hash_password, verify_password
import logging

logger = logging.getLogger(__name__)


def create_user(username: str, email: str, password: str) -> int:
    """Create a new user. Returns user_id."""
    hashed_password = hash_password(password)
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash, is_active)
            VALUES (%s, %s, %s, TRUE)
            RETURNING user_id
            """,
            (username, email, hashed_password)
        )
        
        user_id = cur.fetchone()[0]
        conn.commit()
        logger.info(f"User created: {username} (id={user_id})")
        return user_id
        
    except Exception as e:
        logger.error(f"Failed to create user: {str(e)}")
        raise Exception("Failed to create user")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def get_user_by_username(username: str) -> dict:
    """Fetch user by username."""
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT user_id, username, email, password_hash, is_active FROM users WHERE username = %s",
            (username,)
        )
        
        row = cur.fetchone()
        
        if not row:
            return None
        
        return {
            "user_id": row[0],
            "username": row[1],
            "email": row[2],
            "password_hash": row[3],
            "is_active": row[4]
        }
        
    except Exception as e:
        logger.error(f"Failed to fetch user: {str(e)}")
        raise Exception("Database error")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def authenticate_user(username: str, password: str) -> dict:
    """Authenticate user. Returns user dict if valid, None otherwise."""
    user = get_user_by_username(username)
    
    if not user or not user.get("is_active"):
        return None
    
    if not verify_password(password, user["password_hash"]):
        return None
    
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"]
    }
