import pickle
import os
from model.feature_encoder import encode_permissions

# Load model
model_path = os.path.join("model", "model.pkl")
with open(model_path, "rb") as f:
    model = pickle.load(f)

# Load all permission names
with open(os.path.join("model", "drebin_features.pkl"), "rb") as f:
    all_permissions = pickle.load(f)

def predict_misuse_from_permissions(permissions, threshold=0.3):
    features = encode_permissions(permissions)
    probs = model.predict_proba([features])[0]
    print("Prediction probabilities:", probs)
    prediction = 1 if probs[1] >= threshold else 0

    # Identify suspicious permissions from feature importances
    suspicious_permissions = []
    if hasattr(model, "feature_importances_"):
        importance_threshold = sorted(model.feature_importances_)[-20]  # top 20 features
        suspicious_permissions = [
            name for name, val, present in zip(all_permissions, model.feature_importances_, features)
            if val >= importance_threshold and present == 1
        ]

    return prediction, suspicious_permissions
