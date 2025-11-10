def extract_features(static_permissions, dynamic_flags):
    """
    Extract features from the static and dynamic analysis results.
    Return a set of features for further analysis or reporting.
    """
    dangerous_permissions = ["CAMERA", "LOCATION", "MICROPHONE", "CONTACTS", "STORAGE"]
    dangerous_count = len([perm for perm in static_permissions if perm in dangerous_permissions])
    flagged_count = len(dynamic_flags)
    
    return dangerous_count, flagged_count