import os
import pickle

# Load the original column set (feature names) used during training
with open(os.path.join("model", "drebin_features.pkl"), "rb") as f:
    all_permissions = pickle.load(f)

def encode_permissions(permission_list):
    """
    Returns a feature vector (list of 0/1s) representing the presence of each permission.
    Converts 'perm' to 'permission::perm' format to match training.
    """
    features = [1 if perm in permission_list else 0 for perm in all_permissions]
    return features
