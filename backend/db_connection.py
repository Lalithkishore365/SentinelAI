import psycopg2
from psycopg2 import OperationalError
import time

DB_CONFIG = {
    "dbname": "sentinel_ai",
    "user": "postgres",
    "password": "Alpha_Spectram@123",
    "host": "localhost",
    "port": "5432",
}

MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds


def get_connection(retry=True):
    """Get a PostgreSQL connection with optional retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            return conn
        except OperationalError as e:
            if attempt < MAX_RETRIES - 1 and retry:
                print(f"DB connection failed (attempt {attempt + 1}). Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                raise Exception(f"Database connection failed after {MAX_RETRIES} attempts: {str(e)}")
