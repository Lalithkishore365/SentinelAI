from db_connection import get_connection
import logging

logger = logging.getLogger(__name__)


def extract_auth_features(session_id: str) -> dict:
    """Extract authentication features for a given session."""
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE response_status >= 400) AS failed_login_count,
                COUNT(*) FILTER (WHERE response_status < 400)  AS success_login_count,
                COUNT(DISTINCT ip_address)                      AS unique_ip_count,
                AVG(processing_time_ms)                            AS avg_response_time
            FROM activity_logs
            WHERE session_id = %s
              AND timestamp >= NOW() - INTERVAL '10 minutes'
            """,
            (session_id,),
        )

        row = cur.fetchone()

        if not row:
            return {
                "failed_login_count": 0,
                "success_login_count": 0,
                "unique_ip_count": 0,
                "avg_response_time": 0,
            }

        failed, success, unique_ips, avg_rt = row

        return {
            "failed_login_count": failed or 0,
            "success_login_count": success or 0,
            "unique_ip_count": unique_ips or 0,
            "avg_response_time": round(avg_rt or 0, 2),
        }

    except Exception as e:
        logger.error(f"Failed to extract features: {str(e)}")
        raise Exception("Failed to extract features")

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
