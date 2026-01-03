import uuid
from datetime import datetime, timedelta
from db_connection import get_connection
from config import SESSION_TIMEOUT_MINUTES
import logging

logger = logging.getLogger(__name__)


def create_session(user_id: int, ip_address: str, user_agent: str) -> str:
    """Create a new session and store in user_sessions table."""
    session_id = str(uuid.uuid4())

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO user_sessions (
                session_id,
                user_id,
                ip_address,
                user_agent,
                login_time,
                is_authenticated
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                session_id,
                user_id,
                ip_address,
                user_agent,
                datetime.now(),
                True,
            ),
        )

        conn.commit()
        logger.info(f"Session created: {session_id} for user {user_id}")
        return session_id

    except Exception as e:
        logger.error(f"Failed to create session: {str(e)}")
        raise Exception("Failed to create session")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def session_exists(session_id: str) -> bool:
    """Check if a session exists and is still valid (not timed out)."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT login_time, logout_time FROM user_sessions 
            WHERE session_id = %s
            """,
            (session_id,)
        )
        
        row = cur.fetchone()
        
        if not row:
            return False
        
        login_time, logout_time = row
        
        # Check if session has been logged out
        if logout_time is not None:
            return False
        
        # Check if session has timed out
        timeout_threshold = datetime.now() - timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        if login_time < timeout_threshold:
            logger.warning(f"Session {session_id} has timed out")
            # Auto-logout timed out session
            logout_session(session_id)
            return False
        
        return True

    except Exception as e:
        logger.error(f"Failed to check session: {str(e)}")
        raise Exception("Database error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def logout_session(session_id: str) -> None:
    """Mark a session as logged out."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE user_sessions 
            SET logout_time = %s, is_authenticated = FALSE
            WHERE session_id = %s
            """,
            (datetime.now(), session_id)
        )

        conn.commit()
        logger.info(f"Session logged out: {session_id}")

    except Exception as e:
        logger.error(f"Failed to logout session: {str(e)}")
        raise Exception("Failed to logout")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def get_session_info(session_id: str) -> dict:
    """Get session information."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT session_id, user_id, ip_address, login_time, logout_time, is_authenticated
            FROM user_sessions 
            WHERE session_id = %s
            """,
            (session_id,)
        )
        
        row = cur.fetchone()
        
        if not row:
            return None
        
        return {
            "session_id": row[0],
            "user_id": row[1],
            "ip_address": row[2],
            "login_time": row[3],
            "logout_time": row[4],
            "is_authenticated": row[5],
            "expires_at": row[3] + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        }

    except Exception as e:
        logger.error(f"Failed to get session info: {str(e)}")
        raise Exception("Database error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
