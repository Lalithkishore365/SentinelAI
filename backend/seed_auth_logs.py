from db_connection import get_connection
import random
import time

conn = get_connection()
cur = conn.cursor()

for i in range(10):
    cur.execute("""
        INSERT INTO auth_logs (
            user_id, ip_address, user_agent, event_type, response_time_ms
        )
        VALUES (%s, %s, %s, %s, %s)
    """, (
        1,
        "192.168.1.50",
        "Chrome",
        "LOGIN_FAIL",
        random.randint(100, 300)
    ))
    time.sleep(0.3)

conn.commit()
cur.close()
conn.close()

print("Inserted brute-force simulation logs")
