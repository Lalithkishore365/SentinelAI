from db_connection import get_connection

conn = get_connection()
cur = conn.cursor()

cur.execute("""
    SELECT COUNT(*)
    FROM auth_logs
    WHERE event_type = 'LOGIN_FAIL'
    AND timestamp >= NOW() - INTERVAL '5 minutes'
""")

print("Failed logins (5 min):", cur.fetchone()[0])

cur.close()
conn.close()
