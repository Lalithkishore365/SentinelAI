from time import perf_counter
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Query, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
from db_init import init_db

from session_manager import create_session, session_exists, logout_session, get_session_info
from activity_logger import log_request
from features_auth import extract_auth_features
from user_manager import authenticate_user, create_user, get_user_by_username
from auth import create_access_token, create_refresh_token, decode_token
from models import UserRegister, UserLogin, TokenResponse, UserResponse, SessionResponse

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel AI", version="2.0.0")
# Initialize database & tables at startup
from db_init import init_db

@app.on_event("startup")
def startup_event():
    init_db()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


def verify_token(authorization: str = Header(None)) -> dict:
    """Verify JWT token from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    
    token = parts[1]
    
    try:
        payload = decode_token(token)
        
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return payload
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ============ USER AUTHENTICATION ENDPOINTS ============

@app.post("/register")
async def register(request: Request):
    """Register a new user.
    
    Request body:
    {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    }
    """
    try:
        data = await request.json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        
        if not all([username, email, password]):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        # Check if user already exists
        if get_user_by_username(username):
            raise HTTPException(status_code=409, detail="Username already exists")
        
        user_id = create_user(username, email, password)
        
        return UserResponse(user_id, username, email, datetime.now(), True)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")



@app.post("/login")
async def login(request: Request):
    """Authenticate user and create session with JWT tokens."""
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Missing username or password")
        
        # Authenticate user
        user = authenticate_user(username, password)
        if not user:
            logger.warning(f"Login failed for user: {username}")
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create JWT tokens
        access_token, expires_at = create_access_token(user["user_id"], user["username"])
        refresh_token = create_refresh_token(user["user_id"], user["username"])
        
        # Create session
        ip = request.client.host or "unknown"
        ua = request.headers.get("user-agent", "unknown")
        session_id = create_session(user["user_id"], ip, ua)
        
        logger.info(f"Login successful: user_id={user['user_id']}, username={user['username']}")
        
        # Calculate expires_in (seconds)
        expires_in = int((expires_at - datetime.utcnow()).total_seconds())
        
        return {
    "access_token": access_token,
    "refresh_token": refresh_token,
    "token_type": "bearer",
    "user_id": user["user_id"],
    "expires_in": expires_in,
    "session_id": session_id  # ADD THIS LINE
}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@app.post("/refresh")
async def refresh(refresh_token: str = Query(...)):
    """Refresh access token using refresh token."""
    try:
        payload = decode_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("user_id")
        username = payload.get("username")
        
        # Create new access token
        access_token, expires_at = create_access_token(user_id, username)
        expires_in = int((expires_at - datetime.utcnow()).total_seconds())
        
        logger.info(f"Token refreshed for user_id={user_id}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in
        }
    
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


@app.post("/logout")
async def logout(
    token_payload: dict = Depends(verify_token),
    session_id: str = Query(..., description="Session ID to logout")
):
    """Logout user and invalidate session."""
    try:
        user_id = token_payload.get("user_id")
        
        # Verify session exists and belongs to user
        session_info = get_session_info(session_id)
        if not session_info or session_info["user_id"] != user_id:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Logout the session
        logout_session(session_id)
        
        logger.info(f"User logged out: user_id={user_id}, session_id={session_id}")
        
        return {
            "status": "logged_out",
            "message": "Session terminated successfully"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Logout failed")


# ============ ACTIVITY TRACKING ENDPOINTS ============

@app.get("/track")
async def track(
    request: Request,
    session_id: str = Query(..., description="Session ID from /login"),
    token_payload: dict = Depends(verify_token)
):
    """Log request activity and extract features for the session."""
    
    if not session_id or len(session_id) != 36:
        logger.warning(f"Invalid session_id format: {session_id}")
        raise HTTPException(status_code=400, detail="Invalid session_id format")

    try:
        if not session_exists(session_id):
            logger.warning(f"Session not found or timed out: {session_id}")
            raise HTTPException(status_code=404, detail="Session not found or expired")
    except Exception as e:
        logger.error(f"Session lookup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error")

    try:
        user_id = token_payload.get("user_id")
        ip = request.client.host or "unknown"
        
        bytes_received = int(request.headers.get("content-length", 0))
        
        start = perf_counter()
        
        response_status = 200
        bytes_sent = 256
        
        processing_time_ms = int((perf_counter() - start) * 1000)

        log_request(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip,
            endpoint=request.url.path,
            http_method=request.method,
            response_status=response_status,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            processing_time_ms=processing_time_ms,
        )

        features = extract_auth_features(session_id)

        logger.info(f"Track logged: session_id={session_id}, user_id={user_id}, status={response_status}")

        return {
            "status": "logged",
            "session_id": session_id,
            "user_id": user_id,
            "features": features,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Track failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to log request")


# ============ SESSION MANAGEMENT ENDPOINTS ============

@app.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    token_payload: dict = Depends(verify_token)
):
    """Get session information."""
    try:
        user_id = token_payload.get("user_id")
        
        session_info = get_session_info(session_id)
        if not session_info:
            raise HTTPException(status_code=404, detail="Session not found")
        
        if session_info["user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Unauthorized")
        
        return SessionResponse(
            session_info["session_id"],
            session_info["user_id"],
            session_info["ip_address"],
            session_info["login_time"],
            session_info["logout_time"],
            session_info["is_authenticated"],
            session_info["expires_at"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get session: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/me")
async def get_current_user(token_payload: dict = Depends(verify_token)):
    """Get current authenticated user info."""
    try:
        user_id = token_payload.get("user_id")
        username = token_payload.get("username")
        
        return {
            "user_id": user_id,
            "username": username,
            "authenticated": True
        }
    
    except Exception as e:
        logger.error(f"Failed to get user info: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving user info")


# ============ HEALTH CHECK ============

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0"
    }


# ============ ROOT ENDPOINT ============

@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "Sentinel AI",
        "version": "2.0.0",
        "description": "Security telemetry and anomaly detection system",
        "docs": "/docs",
        "endpoints": {
            "auth": ["/register", "/login", "/refresh", "/logout"],
            "tracking": ["/track"],
            "session": ["/sessions/{session_id}", "/me"],
            "health": ["/health"]
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
