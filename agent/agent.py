from agent.memory import get_session_state
from agent.ml_tool import ml_predict
from agent.actions import decide_action

def evaluate_session(session_id):
    """
    🔥 AGGRESSIVE ATTACK DETECTION ENGINE
    Detects and blocks attacks early (before 200 requests)
    """
    session = get_session_state(session_id)
    if session is None:
        print("❌ No session found!")
        return None

    print(f"\n{'='*60}")
    print(f"🔍 EVALUATING SESSION: {session_id}")
    print(f"{'='*60}")
    print(f"📊 Session Data:")
    print(f"   - Username: {session.get('username', 'N/A')}")
    print(f"   - Total Requests: {session.get('total_requests', 0)}")
    print(f"   - Failed Logins: {session.get('failed_logins', 0)}")
    print(f"   - Avg Request Interval: {session.get('avg_request_interval')}")
    print(f"   - Max Request Rate: {session.get('max_request_rate')}")
    print(f"   - Session Duration: {session.get('session_duration')}")

    rule_risk = 0
    rules_triggered = []

    # ---------- AGGRESSIVE RULE ENGINE ----------
    
    # 🚨 CRITICAL: Extremely fast request rate (clear bot attack)
    if session["max_request_rate"] and session["max_request_rate"] > 10:
        rule_risk += 50
        rules_triggered.append(f"Extremely fast request rate ({session['max_request_rate']:.1f} req/s)")
        print(f"🚨 CRITICAL: Bot-like request rate ({session['max_request_rate']:.2f} req/s)")
    
    # 🚨 HIGH: Fast request rate (likely automated)
    elif session["max_request_rate"] and session["max_request_rate"] > 5:
        rule_risk += 35
        rules_triggered.append(f"Fast request rate ({session['max_request_rate']:.1f} req/s)")
        print(f"🚨 HIGH: Fast request rate ({session['max_request_rate']:.2f} req/s)")

    # 🚨 CRITICAL: Bot-like intervals (automated script)
    if session["avg_request_interval"] and session["avg_request_interval"] < 0.1:
        rule_risk += 45
        rules_triggered.append(f"Bot-like intervals ({session['avg_request_interval']:.3f}s)")
        print(f"🚨 CRITICAL: Bot intervals ({session['avg_request_interval']:.3f}s avg)")
    
    # 🚨 HIGH: Very short intervals
    elif session["avg_request_interval"] and session["avg_request_interval"] < 0.3:
        rule_risk += 30
        rules_triggered.append(f"Very short intervals ({session['avg_request_interval']:.3f}s)")
        print(f"🚨 HIGH: Short intervals ({session['avg_request_interval']:.3f}s avg)")

    # 🚨 MEDIUM: Rapid fire pattern
    if session["avg_request_interval"] and session["avg_request_interval"] < 0.5:
        if session["total_requests"] and session["total_requests"] > 20:
            rule_risk += 25
            rules_triggered.append(f"Rapid-fire pattern ({session['total_requests']} requests)")
            print(f"🚨 MEDIUM: Rapid-fire ({session['total_requests']} requests)")

    # 🚨 HIGH: Multiple failed login attempts
    if session["failed_logins"] >= 3:
        rule_risk += 40
        rules_triggered.append(f"Multiple failed logins ({session['failed_logins']})")
        print(f"🚨 HIGH: Failed logins ({session['failed_logins']})")

    # 🚨 MEDIUM: Excessive request volume
    if session["total_requests"] and session["total_requests"] > 50:
        rule_risk += 20
        rules_triggered.append(f"Excessive requests ({session['total_requests']})")
        print(f"🚨 MEDIUM: Too many requests ({session['total_requests']})")
    
    # 🚨 HIGH: Way too many requests
    if session["total_requests"] and session["total_requests"] > 100:
        rule_risk += 30
        rules_triggered.append(f"Attack-level volume ({session['total_requests']})")
        print(f"🚨 HIGH: Attack volume ({session['total_requests']})")

    print(f"\n⚖️ Rule Risk Score: {rule_risk}")
    print(f"🚨 Triggered Rules: {rules_triggered}")

    # ---------- ML ENGINE ----------
    ml_score = 0.0
    if session["total_requests"] and session["total_requests"] >= 10:
        try:
            ml_score = ml_predict(session)
            print(f"🤖 ML Score: {ml_score:.3f}")
        except Exception as e:
            print(f"⚠️ ML prediction failed: {e}")
            ml_score = 0.0
    else:
        print(f"⚠️ Not enough requests ({session.get('total_requests', 0)}) for ML")

    # ---------- AGGRESSIVE DECISION ENGINE ----------
    
    # 🔴 IMMEDIATE BLOCK CONDITIONS
    if rule_risk >= 70:
        action = "BLOCK"
        print(f"🔴 BLOCKING: Critical rule risk ({rule_risk})")
    
    elif ml_score >= 0.85:
        action = "BLOCK"
        print(f"🔴 BLOCKING: Very high ML confidence ({ml_score:.2f})")
    
    elif ml_score >= 0.7 and rule_risk >= 40:
        action = "BLOCK"
        print(f"🔴 BLOCKING: High ML ({ml_score:.2f}) + Moderate rules ({rule_risk})")
    
    elif rule_risk >= 50 and ml_score >= 0.5:
        action = "BLOCK"
        print(f"🔴 BLOCKING: High rules ({rule_risk}) + ML confirmation ({ml_score:.2f})")
    
    # 🟡 WARNING CONDITIONS
    elif rule_risk >= 40 or ml_score >= 0.6:
        action = "WARN"
        print(f"🟡 WARNING: Moderate risk (rules: {rule_risk}, ML: {ml_score:.2f})")
    
    # 🟢 ALLOW
    else:
        action = "ALLOW"
        print(f"🟢 ALLOWING: Low risk (rules: {rule_risk}, ML: {ml_score:.2f})")

    print(f"\n✅ Final Decision: {action}")
    print(f"{'='*60}\n")

    return {
        "session_id": session_id,
        "risk_score": rule_risk,
        "ml_score": ml_score,
        "rules_triggered": rules_triggered,
        "action": action
    }