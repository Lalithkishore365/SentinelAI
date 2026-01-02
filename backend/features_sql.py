from db_connection import get_connection

def get_session_features(session_id):
    conn = get_connection()
    cur = conn.cursor()

    # Request count
    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE session_id = %s
    """, (session_id,))
    req_count = cur.fetchone()[0]

    # Session duration
    cur.execute("""
        SELECT
            EXTRACT(EPOCH FROM (MAX(request_time) - MIN(request_time)))
        FROM activity_logs
        WHERE session_id = %s
    """, (session_id,))
    duration = cur.fetchone()[0] or 0

    # Failed logins
    cur.execute("""
        SELECT COUNT(*)
        FROM auth_logs
        WHERE session_id = %s
        AND event_type = 'LOGIN_FAIL'
    """, (session_id,))
    failed = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "request_count": req_count,
        "session_duration": duration,
        "failed_logins": failed
    }


SESSION_FEATURES_QUERY = """
SELECT
    session_id,
    COUNT(*) AS total_requests,
    SUM(CASE WHEN response_status >= 400 THEN 1 ELSE 0 END) AS failed_requests,
    COUNT(DISTINCT endpoint) AS unique_endpoints,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen,
    EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) AS session_duration_seconds,
    AVG(processing_time_ms) AS avg_processing_time_ms
FROM activity_logs
GROUP BY session_id
ORDER BY last_seen DESC;
"""

