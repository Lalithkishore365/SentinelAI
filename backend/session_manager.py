import uuid
from datetime import datetime
from db_connection import get_connection
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
    """Check if a session exists in the database."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM user_sessions WHERE session_id = %s", (session_id,))
        exists = cur.fetchone() is not None

        return exists

    except Exception as e:
        logger.error(f"Failed to check session existence: {str(e)}")
        raise Exception("Database error")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
