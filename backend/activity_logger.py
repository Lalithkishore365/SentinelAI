from datetime import datetime
from db_connection import get_connection
import logging

logger = logging.getLogger(__name__)


def log_request(
    *,
    session_id: str,
    user_id: int,
    ip_address: str,
    endpoint: str,
    http_method: str,
    response_status: int,
    bytes_sent: int,
    bytes_received: int,
    processing_time_ms: int,
) -> None:
    """Log a request to activity_logs table."""
    
    # Validate inputs
    if not session_id or not isinstance(session_id, str):
        raise ValueError("Invalid session_id")
    if not endpoint or not isinstance(endpoint, str):
        raise ValueError("Invalid endpoint")
    if http_method not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        raise ValueError("Invalid HTTP method")

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO activity_logs (
                user_id,
                session_id,
                ip_address,
                endpoint,
                http_method,
                response_status,
                bytes_sent,
                bytes_received,
                processing_time_ms,
                timestamp
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                session_id,
                ip_address,
                endpoint,
                http_method,
                response_status,
                bytes_sent,
                bytes_received,
                processing_time_ms,
                datetime.now(),
            ),
        )

        conn.commit()
        logger.debug(f"Request logged for session {session_id} to {endpoint}")

    except ValueError as e:
        logger.warning(f"Invalid input: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Failed to log request: {str(e)}")
        raise Exception("Failed to log request")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
