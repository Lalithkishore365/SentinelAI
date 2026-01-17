# add_user.py
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "database.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
);

""")

cur.execute("""
    INSERT INTO admin_users (username, password)
    VALUES ('admin', 'admin123');
""")

conn.commit()
conn.close()

print("✅ User created: admin / admin123")