import os

def generate_report(apk_name, permissions, flagged_suspicious_permissions, dangerous_count, flagged_count, misuse_detected):
    """
    Generate a report summarizing static and dynamic analysis results.
    """
    report = f"""
    --- App Permission Misuse Report ---
    APK File: {apk_name}

    Static Analysis:
    Extracted Permissions: {permissions}
    Flagged Permissions: {flagged_suspicious_permissions}

    Feature Extraction:
    Dangerous Permissions Count: {dangerous_count}
    Flagged Permissions Count: {flagged_count}

    Conclusion:
    """
    
    if misuse_detected:
        report += f"\nMisuse Detected: Yes\n"
        report += f"Suspicious Permissions Involved: {flagged_suspicious_permissions}\n"
    else:
        report += f"\nMisuse Detected: No\n"
    
    report_path = os.path.join("reports", f"{apk_name}_report.txt")  # ← changed
    with open(report_path, "w") as file:
        file.write(report)
    print(f"Report saved as 'reports/{apk_name}_report.txt'.")  # ← changed

    return report_path