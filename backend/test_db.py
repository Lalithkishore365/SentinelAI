from db_connection import get_connection

conn = get_connection()
cur = conn.cursor()

cur.execute("SELECT NOW();")
print(cur.fetchone())

cur.close()
conn.close()
