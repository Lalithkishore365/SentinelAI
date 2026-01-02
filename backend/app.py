from time import perf_counter
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse
import logging

from session_manager import create_session, session_exists
from activity_logger import log_request
from features_auth import extract_auth_features

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel AI", version="1.0.0")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.post("/login")
async def login(request: Request):
    """Create a new session for a user."""
    try:
        user_id = 1  # Demo only — in production, extract from auth token
        ip = request.client.host or "unknown"
        ua = request.headers.get("user-agent", "unknown")

        session_id = create_session(user_id, ip, ua)
        logger.info(f"Login successful: session_id={session_id}, user_id={user_id}, ip={ip}")

        return {
            "status": "success",
            "session_id": session_id,
            "user_id": user_id
        }

    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create session")


@app.get("/track")
async def track(
    request: Request,
    session_id: str = Query(..., description="Session ID from /login"),
):
    """Log a request and extract features for the session."""
    
    # Validate session_id format
    if not session_id or len(session_id) != 36:  # UUID format
        logger.warning(f"Invalid session_id format: {session_id}")
        raise HTTPException(status_code=400, detail="Invalid session_id format")

    # Check if session exists
    try:
        if not session_exists(session_id):
            logger.warning(f"Session not found: {session_id}")
            raise HTTPException(status_code=404, detail="Session not found")
    except Exception as e:
        logger.error(f"Session lookup failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error")

    try:
        user_id = 1  # Demo only
        ip = request.client.host or "unknown"
        
        # Capture request metadata
        bytes_received = int(request.headers.get("content-length", 0))
        
        # Measure processing time
        start = perf_counter()
        
        # Simulate business logic
        response_status = 200
        bytes_sent = 128  # Approximate response size
        
        processing_time_ms = int((perf_counter() - start) * 1000)

        # Log the request
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

        # Extract features
        features = extract_auth_features(session_id)

        logger.info(f"Track logged: session_id={session_id}, status={response_status}")

        return {
            "status": "logged",
            "session_id": session_id,
            "features": features,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Track failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to log request")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
