from flask import Flask, render_template, request, redirect, url_for, session, abort
import sqlite3
import uuid
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "sentinel-secret-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "database.db")

def get_db_connection():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=10,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_blocked INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            login_time TEXT,
            logout_time TEXT,
            session_duration INTEGER,
            total_requests INTEGER DEFAULT 0,
            failed_logins INTEGER DEFAULT 0,
            avg_request_interval REAL,
            max_request_rate REAL,
            is_authenticated INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            endpoint TEXT,
            request_time TEXT,
            method TEXT,
            response_code INTEGER
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            username TEXT,
            risk_score REAL,
            ml_score REAL,
            triggered_rules TEXT,
            action_taken TEXT,
            event_time TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_users (
            username TEXT PRIMARY KEY,
            block_reason TEXT,
            block_time TEXT,
            session_id TEXT
        )
    """)

    conn.commit()
    conn.close()


# 🔥 CHECK 1: Block users who are in blocked_users table
@app.before_request
def check_blocked_user():
    """Prevent blocked users from even attempting login"""
    if request.endpoint == "login" and request.method == "POST":
        username = request.form.get("username")
        if username:
            conn = get_db_connection()
            cur = conn.cursor()
            
            blocked = cur.execute("""
                SELECT block_reason, block_time 
                FROM blocked_users 
                WHERE username = ?
            """, (username,)).fetchone()
            
            conn.close()
            
            if blocked:
                print(f"🚫 BLOCKED USER LOGIN ATTEMPT: {username}")
                return render_template(
                    "blocked.html",
                    message=f"Account '{username}' has been permanently blocked due to suspicious activity."
                ), 403


# 🔥 CHECK 2: Block active sessions that are flagged
@app.before_request
def enforce_session_block():
    """Block any session that's marked as blocked"""
    # Skip login and static files
    if request.endpoint in ("login", "static"):
        return

    if "session_id" not in session:
        return

    conn = get_db_connection()
    cur = conn.cursor()

    row = cur.execute("""
        SELECT is_blocked, username
        FROM user_sessions
        WHERE session_id = ?
    """, (session["session_id"],)).fetchone()

    conn.close()

    if row and row["is_blocked"] == 1:
        print(f"🚫 BLOCKED SESSION ACCESS DENIED: {row['username']}")
        session.clear()
        abort(403)  # Use abort instead of return


# 🔥 CHECK 3: Log every request FIRST
@app.before_request
def log_and_count_request():
    """Log request and increment counter BEFORE detection"""
    if request.endpoint in ("logout", "static", "login"):
        return

    if "session_id" not in session:
        return

    conn = get_db_connection()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat()

    # Log the request
    cur.execute("""
        INSERT INTO request_logs (
            session_id, endpoint, request_time, method, response_code
        )
        VALUES (?, ?, ?, ?, ?)
    """, (session["session_id"], request.path, now, request.method, 200))
    
    # Increment counter
    cur.execute("""
        UPDATE user_sessions
        SET total_requests = total_requests + 1
        WHERE session_id = ?
    """, (session["session_id"],))
    
    conn.commit()
    conn.close()


# 🔥 CHECK 4: DETECT ATTACK - This runs AFTER logging
@app.before_request
def detect_attack_realtime():
    """
    Check EVERY 5 REQUESTS for attack patterns
    Use abort(403) to STOP request immediately
    """
    if request.endpoint in ("login", "static", "logout"):
        return

    if "session_id" not in session:
        return

    session_id = session["session_id"]
    
    conn = get_db_connection()
    cur = conn.cursor()

    # Get current state
    session_data = cur.execute("""
        SELECT total_requests, is_blocked, username
        FROM user_sessions
        WHERE session_id = ?
    """, (session_id,)).fetchone()

    if not session_data:
        conn.close()
        return

    # Already blocked? Deny immediately with abort
    if session_data["is_blocked"] == 1:
        conn.close()
        print(f"🚫 Session already blocked: {session_data['username']}")
        session.clear()
        abort(403)  # Use abort to STOP request

    total_requests = session_data["total_requests"]
    username = session_data["username"]

    # 🔥 CHECK EVERY 5 REQUESTS
    if total_requests >= 5 and total_requests % 5 == 0:
        print(f"\n{'='*60}")
        print(f"🔍 ATTACK CHECK #{total_requests} - User: {username}")
        print(f"{'='*60}")
        
        # Get last 10 requests for analysis
        rows = cur.execute("""
            SELECT request_time
            FROM request_logs
            WHERE session_id = ?
            ORDER BY request_time DESC
            LIMIT 10
        """, (session_id,)).fetchall()

        if len(rows) >= 5:
            timestamps = [datetime.fromisoformat(r["request_time"]) for r in rows]
            timestamps.reverse()  # Oldest to newest
            
            # Calculate time span and rate
            time_span = (timestamps[-1] - timestamps[0]).total_seconds()
            rate = len(timestamps) / time_span if time_span > 0 else 999
            
            # Calculate average interval
            intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                        for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            
            print(f"📊 Analyzed {len(timestamps)} requests")
            print(f"📊 Time span: {time_span:.2f}s")
            print(f"📊 Rate: {rate:.2f} req/s")
            print(f"📊 Avg interval: {avg_interval:.3f}s")
            
            # 🚨 ATTACK DETECTION LOGIC
            is_attack = False
            reason = []
            
            # CRITICAL: Very fast rate
            if rate > 3:
                is_attack = True
                reason.append(f"Excessive rate: {rate:.1f} req/s")
                print(f"🚨 ATTACK: Rate = {rate:.2f} req/s (threshold: 3)")
            
            # CRITICAL: Bot-like intervals
            if avg_interval < 0.5:
                is_attack = True
                reason.append(f"Bot intervals: {avg_interval:.3f}s")
                print(f"🚨 ATTACK: Interval = {avg_interval:.3f}s (threshold: 0.5)")
            
            # HIGH: Burst pattern
            if total_requests > 15 and avg_interval < 1.0:
                is_attack = True
                reason.append(f"Burst traffic: {total_requests} requests")
                print(f"🚨 ATTACK: Burst pattern detected")
            
            if is_attack:
                print(f"\n🔴🔴🔴 ATTACK CONFIRMED 🔴🔴🔴")
                print(f"Reasons: {', '.join(reason)}")
                
                # Update metrics
                cur.execute("""
                    UPDATE user_sessions
                    SET avg_request_interval = ?,
                        max_request_rate = ?
                    WHERE session_id = ?
                """, (avg_interval, rate, session_id))
                conn.commit()
                
                # 🤖 Call agent for evaluation
                from agent.agent import evaluate_session
                from agent.memory import store_event, permanently_block_user
                
                print("🤖 Calling agent for evaluation...")
                result = evaluate_session(session_id)
                
                if result:
                    print(f"🤖 Agent decision: {result['action']}")
                    store_event(result)
                    
                    # 🔴 IMMEDIATE BLOCK
                    if result["action"] == "BLOCK":
                        print(f"\n🚫🚫🚫 BLOCKING USER: {username} 🚫🚫🚫\n")
                        
                        cur.execute("""
                            UPDATE user_sessions
                            SET is_blocked = 1
                            WHERE session_id = ?
                        """, (session_id,))
                        conn.commit()

                        # 2️⃣ Permanently block user (login-level)
                        permanently_block_user(username, session_id, reason)

                        # 3️⃣ Clear flask session
                        session.clear()

                        # 4️⃣ 💣 HARD STOP REQUEST (THIS IS THE ACTUAL BLOCK)
                        abort(403)
                        conn.close()
                        
                        # Permanently block the user
                        permanently_block_user(username, session_id, reason)
                        
                        # Clear session
                        session.clear()
                        
                        # 🔥 USE ABORT TO STOP REQUEST IMMEDIATELY
                        print(f"🚫 Aborting request with 403\n")
                        abort(403)  # This STOPS the request!
                    
                    elif result["action"] == "WARN":
                        print("⚠️ WARNING - Monitoring continues...")
            else:
                print(f"✅ Normal traffic - Rate: {rate:.2f} req/s, Interval: {avg_interval:.3f}s")
        
        print(f"{'='*60}\n")
    
    conn.close()


@app.route("/", methods=["GET", "POST"])
def login():
    if "temp_session_id" not in session:
        session["temp_session_id"] = str(uuid.uuid4())

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent")
        now = datetime.utcnow().isoformat()

        user = cur.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        
        if user is None:
            cur.execute("""
                INSERT INTO user_sessions (
                    session_id, username, ip_address, user_agent,
                    login_time, failed_logins, is_authenticated
                )
                VALUES (?, ?, ?, ?, ?, 1, 0)
                ON CONFLICT(session_id)
                DO UPDATE SET failed_logins = failed_logins + 1
            """, (session["temp_session_id"], username, ip_address, user_agent, now))
            conn.commit()
            conn.close()
            return render_template("login.html", error="Invalid credentials")

        # Successful login
        session_id = session.pop("temp_session_id", str(uuid.uuid4()))

        existing = cur.execute("""
            SELECT session_id FROM user_sessions WHERE session_id = ?
        """, (session_id,)).fetchone()

        if existing:
            cur.execute("""
                UPDATE user_sessions
                SET user_id = ?, username = ?, ip_address = ?,
                    user_agent = ?, login_time = ?, is_authenticated = 1
                WHERE session_id = ?
            """, (user["id"], username, ip_address, user_agent, now, session_id))
        else:
            cur.execute("""
                INSERT INTO user_sessions (
                    session_id, user_id, username, ip_address, user_agent,
                    login_time, is_authenticated
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (session_id, user["id"], username, ip_address, user_agent, now))

        conn.commit()
        conn.close()

        session["session_id"] = session_id
        session["user_id"] = user["id"]

        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/home")
def home():
    if "session_id" not in session:
        return redirect(url_for("login"))
    return render_template("home.html")


@app.route("/view-profile")
def view_profile():
    if "session_id" not in session:
        return redirect(url_for("login"))
    return render_template("view_profile.html")


@app.route("/update-profile", methods=["POST"])
def update_profile():
    if "session_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("home"))


@app.route("/submit-form", methods=["POST"])
def submit_form():
    if "session_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("home"))


@app.route("/download-doc")
def download_doc():
    if "session_id" not in session:
        return redirect(url_for("login"))
    return render_template("download_doc.html")


@app.route("/logout")
def logout():
    session_id = session.get("session_id")

    if session_id:
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            rows = cur.execute("""
                SELECT request_time
                FROM request_logs
                WHERE session_id = ?
                ORDER BY request_time
            """, (session_id,)).fetchall()

            timestamps = [datetime.fromisoformat(r["request_time"]) for r in rows]
            total_requests = len(timestamps)

            if total_requests > 1:
                intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                            for i in range(1, total_requests)]
                avg_request_interval = sum(intervals) / len(intervals)
                max_request_rate = 1 / min(intervals) if min(intervals) > 0 else total_requests
            else:
                avg_request_interval = None
                max_request_rate = None

            logout_time = datetime.utcnow()
            
            row = cur.execute("""
                SELECT login_time, username
                FROM user_sessions
                WHERE session_id = ?
            """, (session_id,)).fetchone()

            if row and row["login_time"]:
                login_time = row["login_time"]
                username = row["username"]
                session_duration = (logout_time - datetime.fromisoformat(login_time)).total_seconds()

                cur.execute("""
                    UPDATE user_sessions
                    SET logout_time = ?, session_duration = ?,
                        total_requests = ?, avg_request_interval = ?,
                        max_request_rate = ?
                    WHERE session_id = ?
                """, (logout_time.isoformat(), session_duration, total_requests,
                     avg_request_interval, max_request_rate, session_id))

                conn.commit()
                conn.close()

                from agent.agent import evaluate_session
                from agent.memory import store_event, permanently_block_user

                result = evaluate_session(session_id)

                if result:
                    store_event(result)
                    
                    if result["action"] == "BLOCK":
                        permanently_block_user(username, session_id, result["rules_triggered"])
                        print(f"🚫 User {username} blocked at logout")

        except Exception as e:
            print(f"❌ ERROR IN LOGOUT: {e}")
            import traceback
            traceback.print_exc()

    session.clear()
    return redirect(url_for("login"))


# 🔥 CUSTOM ERROR HANDLER FOR 403
@app.errorhandler(403)
def forbidden(e):
    """Show blocked page for all 403 errors"""
    return render_template("blocked.html", 
        message="Attack detected! Your account has been blocked."), 403


if __name__ == "__main__":
    init_db()
    app.run(debug=True, use_reloader=False)