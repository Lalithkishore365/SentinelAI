from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

# JWT Settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Session timeout (in minutes)
SESSION_TIMEOUT_MINUTES = 30

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:Alpha_Spectram@123@localhost:5432/sentinel_ai")