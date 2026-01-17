from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "sentinel-admin-secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "db", "database.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- ADMIN LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        admin = cur.execute("""
            SELECT * FROM admin_users
            WHERE username = ? AND password = ?
        """, (username, password)).fetchone()

        conn.close()

        if admin:
            session["admin"] = username
            return redirect(url_for("dashboard"))
        return render_template("admin/admin_login.html", error="Invalid credentials")

    return render_template("admin/admin_login.html")

def admin_required():
    if "admin" not in session:
        return redirect(url_for("admin_login"))

# ---------------- DASHBOARD ----------------
@app.route("/admin/dashboard")
def dashboard():
    admin_required()
    conn = get_db()
    cur = conn.cursor()

    stats = {
        "total_sessions": cur.execute("SELECT COUNT(*) FROM user_sessions").fetchone()[0],
        "total_attacks": cur.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
        "blocked_users": cur.execute("SELECT COUNT(*) FROM blocked_users").fetchone()[0],
        "active_sessions": cur.execute("""
            SELECT COUNT(*) FROM user_sessions
            WHERE logout_time IS NULL
        """).fetchone()[0]
    }

    # 📊 Attacks per day
    attack_trend = cur.execute("""
        SELECT substr(event_time,1,10) as day, COUNT(*) as count
        FROM security_events
        GROUP BY day
        ORDER BY day
    """).fetchall()

    # 📊 Action distribution
    action_dist = cur.execute("""
        SELECT action_taken, COUNT(*) as count
        FROM security_events
        GROUP BY action_taken
    """).fetchall()

    conn.close()

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        attack_trend=attack_trend,
        action_dist=action_dist
    )


# ---------------- ATTACK LOGS ----------------
@app.route("/admin/attacks")
def attacks():
    admin_required()
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM security_events
        ORDER BY event_time DESC
    """).fetchall()
    conn.close()
    return render_template("admin/attacks.html", rows=rows)

# ---------------- BLOCKED USERS ----------------
@app.route("/admin/blocked-users")
def blocked_users():
    admin_required()
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM blocked_users
        ORDER BY block_time DESC
    """).fetchall()
    conn.close()
    return render_template("admin/blocked_users.html", rows=rows)

@app.route("/admin/rules-heatmap")
def rules_heatmap():
    admin_required()
    conn = get_db()
    cur = conn.cursor()

    rows = cur.execute("""
        SELECT triggered_rules, COUNT(*) as count
        FROM security_events
        WHERE triggered_rules IS NOT NULL
    """).fetchall()

    rule_counts = {}

    for r in rows:
        rules = r["triggered_rules"].split(",")
        for rule in rules:
            rule = rule.strip()
            rule_counts[rule] = rule_counts.get(rule, 0) + r["count"]

    conn.close()

    return render_template(
        "admin/rules_heatmap.html",
        rules=list(rule_counts.keys()),
        counts=list(rule_counts.values())
    )

@app.route("/admin/session-replay", methods=["GET", "POST"])
def session_replay():
    admin_required()
    conn = get_db()
    cur = conn.cursor()

    sessions = cur.execute("""
        SELECT DISTINCT session_id
        FROM request_logs
        ORDER BY session_id DESC
    """).fetchall()

    selected_session = request.form.get("session_id")
    logs = []

    if selected_session:
        logs = cur.execute("""
            SELECT request_time, method, endpoint
            FROM request_logs
            WHERE session_id = ?
            ORDER BY request_time
        """, (selected_session,)).fetchall()

    conn.close()

    return render_template(
        "admin/session_replay.html",
        sessions=sessions,
        logs=logs,
        selected_session=selected_session
    )

@app.route("/admin/export/security-events")
def export_security_events():
    admin_required()
    conn = get_db()
    cur = conn.cursor()

    rows = cur.execute("SELECT * FROM security_events").fetchall()
    conn.close()

    def generate():
        yield "session_id,risk_score,ml_score,action,event_time\n"
        for r in rows:
            yield f"{r['session_id']},{r['risk_score']},{r['ml_score']},{r['action_taken']},{r['event_time']}\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=security_events.csv"}
    )

# ---------------- LOGOUT ----------------
@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

if __name__ == "__main__":
    app.run(port=5001, debug=True)
