# add_user.py
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "database.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
    INSERT INTO users (username, password)
    VALUES ('admin1', 'admin123')
""")

conn.commit()
conn.close()

print("✅ User created: admin / admin123")