def evaluate_rules(state):
    risk = 0
    triggered_rules = []

    if state["failed_logins"] >= 3:
        risk += 30
        triggered_rules.append("Multiple failed logins")

    if state["avg_request_interval"] is not None and state["avg_request_interval"] < 0.5:
        risk += 25
        triggered_rules.append("Very fast request rate")

    if state["max_request_rate"] is not None and state["max_request_rate"] > 5:
        risk += 25
        triggered_rules.append("Burst traffic detected")

    if state["session_duration"] is not None and state["session_duration"] > 3600:
        risk += 10
        triggered_rules.append("Abnormally long session")

    return risk, triggered_rules