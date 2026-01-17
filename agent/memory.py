import sqlite3
from datetime import datetime

DB_PATH = "db/database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_session_state(session_id):
    conn = get_db()
    cur = conn.cursor()

    row = cur.execute("""
        SELECT *
        FROM user_sessions
        WHERE session_id = ?
    """, (session_id,)).fetchone()

    conn.close()

    if row is None:
        return None

    return dict(row)


def store_event(result):
    """Store security event in database"""
    try:
        conn = get_db()
        cur = conn.cursor()

        # Get username from session
        username = cur.execute("""
            SELECT username FROM user_sessions WHERE session_id = ?
        """, (result["session_id"],)).fetchone()
        
        username = username["username"] if username else "unknown"

        cur.execute("""
            INSERT INTO security_events (
                session_id,
                username,
                risk_score,
                ml_score,
                triggered_rules,
                action_taken,
                event_time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["session_id"],
            username,
            float(result["risk_score"]),
            float(result["ml_score"]),
            ", ".join(result["rules_triggered"]),
            result["action"],
            datetime.utcnow().isoformat()
        ))

        # 🔥 ENFORCEMENT: Mark session as blocked
        if result["action"] == "BLOCK":
            print(f"🚨 MARKING SESSION AS BLOCKED: {result['session_id']}")
            cur.execute("""
                UPDATE user_sessions
                SET is_blocked = 1
                WHERE session_id = ?
            """, (result["session_id"],))

        conn.commit()
        conn.close()

        print("✅ SECURITY EVENT STORED")

    except Exception as e:
        print(f"❌ ERROR IN store_event: {e}")


def permanently_block_user(username, session_id, rules_triggered):
    """
    🔥 PERMANENTLY BLOCK USER ACCOUNT
    User cannot log in again even with correct credentials
    """
    try:
        conn = get_db()
        cur = conn.cursor()

        print(f"\n{'='*60}")
        print(f"🚫 PERMANENTLY BLOCKING USER: {username}")
        print(f"{'='*60}")

        # Add to blocked_users table
        cur.execute("""
            INSERT OR REPLACE INTO blocked_users (
                username,
                block_reason,
                block_time,
                session_id
            )
            VALUES (?, ?, ?, ?)
        """, (
            username,
            ", ".join(rules_triggered) if rules_triggered else "Attack pattern detected",
            datetime.utcnow().isoformat(),
            session_id
        ))

        # Also mark user as blocked in users table
        cur.execute("""
            UPDATE users
            SET is_blocked = 1
            WHERE username = ?
        """, (username,))

        conn.commit()
        conn.close()

        print(f"✅ USER '{username}' PERMANENTLY BLOCKED")
        print(f"   - Reason: {', '.join(rules_triggered) if rules_triggered else 'Attack detected'}")
        print(f"   - Session: {session_id}")
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"❌ ERROR IN permanently_block_user: {e}")
        import traceback
        traceback.print_exc()


def is_user_blocked(username):
    """Check if a username is permanently blocked"""
    try:
        conn = get_db()
        cur = conn.cursor()

        result = cur.execute("""
            SELECT username FROM blocked_users WHERE username = ?
        """, (username,)).fetchone()

        conn.close()
        return result is not None

    except Exception as e:
        print(f"❌ ERROR IN is_user_blocked: {e}")
        return False