import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from db_connection import DB_CONFIG

DB_NAME = DB_CONFIG["dbname"]

def create_database_if_not_exists():
    """Create database if it does not exist."""
    temp_config = DB_CONFIG.copy()
    temp_config["dbname"] = "postgres"  # connect to default DB

    conn = psycopg2.connect(**temp_config)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s",
        (DB_NAME,)
    )

    exists = cur.fetchone()
    if not exists:
        print(f"📦 Creating database: {DB_NAME}")
        cur.execute(f"CREATE DATABASE {DB_NAME}")
    else:
        print(f"✅ Database already exists: {DB_NAME}")

    cur.close()
    conn.close()


def create_tables():
    """Create required tables if they don't exist."""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        session_id UUID PRIMARY KEY,
        user_id INT REFERENCES users(user_id),
        ip_address TEXT,
        user_agent TEXT,
        login_time TIMESTAMP,
        logout_time TIMESTAMP,
        is_authenticated BOOLEAN
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        log_id SERIAL PRIMARY KEY,
        user_id INT,
        session_id UUID,
        ip_address TEXT,
        endpoint TEXT,
        http_method TEXT,
        response_status INT,
        bytes_sent INT,
        bytes_received INT,
        processing_time_ms INT,
        timestamp TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs (
        log_id SERIAL PRIMARY KEY,
        user_id INT,
        ip_address TEXT,
        user_agent TEXT,
        event_type TEXT,
        response_time_ms INT,
        timestamp TIMESTAMP DEFAULT NOW()
    );
    """)

    conn.commit()
    cur.close()
    conn.close()

    print("✅ All tables ensured")


def init_db():
    create_database_if_not_exists()
    create_tables()
