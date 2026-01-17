import joblib
import numpy as np
import pandas as pd
import os

MODEL_PATH = "models/sentinel_rf_model.pkl"

model = joblib.load(MODEL_PATH)
FEATURE_COLUMNS = model.feature_names_in_

def ml_predict(session):
    """
    Build a 15-feature vector from session-level behavior.
    Missing packet-level features are safely approximated or zero-filled.
    """

    feature_map = {
        "Bwd Header Length": session["total_requests"] * 20,
        "Fwd Packet Length Mean": session["total_requests"] * 30,
        "Fwd Packet Length Max": session["total_requests"] * 50,
        "Packet Length Max": session["total_requests"] * 50,
        "Fwd Packets Length Total": session["total_requests"] * 100,
        "Flow IAT Min": session["avg_request_interval"] or 0,
        "Packet Length Mean": session["total_requests"] * 25,
        "Fwd Packet Length Std": session["max_request_rate"] or 0,
        "Bwd Packet Length Mean": session["total_requests"] * 15,
        "Fwd Header Length": session["total_requests"] * 10,
        "Packet Length Variance": (session["max_request_rate"] or 0) ** 2,
        "Init Bwd Win Bytes": 0,
        "Init Fwd Win Bytes": 0,
        "Bwd Packet Length Max": session["total_requests"] * 40,
        "Fwd PSH Flags": 0,
    }
    X = pd.DataFrame([[feature_map[f] for f in FEATURE_COLUMNS]],
                     columns=FEATURE_COLUMNS)

    prob = model.predict_proba(X)[0][1]
    return prob