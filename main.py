import os
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from static_analysis.static_analysis import extract_permissions
from dynamic_analysis.dynamic_analysis import (
    simulate_dynamic_analysis,
    calculate_dynamic_risk,
)
from feature_extraction.feature_extraction import extract_features
from reports.report_generator import generate_report
from severity_identifier.severity_identifier import plot_severity_graph
from model.predictor import predict_misuse_from_permissions


# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

APP_TITLE = "PermissionShield"
WINDOW_SIZE = "980x720"

latest_report = None
scan_in_progress = False


# -------------------------------------------------
# THREAD-SAFE UI HELPERS
# -------------------------------------------------
def ui(callable_obj):
    root.after(0, callable_obj)


def append_log(msg):
    def _update():
        console_box.insert("end", msg + "\n")
        console_box.see("end")
    ui(_update)


def set_progress(v):
    ui(lambda: progress.set(v))


def set_status(msg):
    ui(lambda: status_label.configure(text=msg))


# -------------------------------------------------
# UI RESET
# -------------------------------------------------
def reset_scan_view():
    risk_value.configure(text="--", text_color="white")
    summary_label.configure(text="No scan performed yet")
    perm_label.configure(text="Permissions: --")
    suspicious_label.configure(text="Suspicious: --")
    dynamic_label.configure(text="Dynamic Flags: --")
    insight_label.configure(text="")
    progress.set(0)
    # ── NEW: clear the report tab when a new scan starts ──────────────────
    report_box.delete("1.0", tk.END)
    report_status_label.configure(text="No report generated yet.")


# -------------------------------------------------
# MAIN ANALYSIS PIPELINE
# -------------------------------------------------
def analyze_apk(apk_path):
    global latest_report, scan_in_progress

    try:
        apk_name = os.path.basename(apk_path)

        append_log(f"Analyzing APK: {apk_name}")
        set_status("Running Static Analysis...")
        set_progress(0.15)

        # -----------------------------------------
        # STATIC ANALYSIS
        # -----------------------------------------
        permissions = extract_permissions(apk_path)

        if not permissions:
            raise Exception("No permissions extracted from APK")

        permissions = [p.upper() for p in permissions]
        append_log(f"Extracted Permissions: {permissions}")

        # -----------------------------------------
        # MACHINE LEARNING
        # -----------------------------------------
        set_status("Running ML Prediction...")
        set_progress(0.35)

        prediction, suspicious_permissions = predict_misuse_from_permissions(
            permissions,
            threshold=0.30
        )

        misuse_detected = prediction == 1

        append_log(
            f"Misuse Prediction: {'Detected' if misuse_detected else 'Not Detected'}"
        )

        if suspicious_permissions:
            append_log(f"Flagged By Model: {suspicious_permissions}")

        # -----------------------------------------
        # DYNAMIC ANALYSIS
        # -----------------------------------------
        set_status("Running Dynamic Analysis...")
        set_progress(0.60)

        dynamic_flags = simulate_dynamic_analysis(permissions)
        dyn_score, dyn_level = calculate_dynamic_risk(dynamic_flags)

        append_log(f"Dynamic Flags: {dynamic_flags}")
        append_log(f"Dynamic Risk: {dyn_level} ({dyn_score})")

        # -----------------------------------------
        # FEATURE EXTRACTION
        # -----------------------------------------
        set_status("Extracting Features...")
        set_progress(0.75)

        dangerous_count, flagged_count = extract_features(
            permissions,
            dynamic_flags
        )

        append_log(f"Dangerous Permissions Count: {dangerous_count}")
        append_log(f"Behavior Flags Count: {flagged_count}")

        # -----------------------------------------
        # REPORT GENERATION  ← core feature added
        # -----------------------------------------
        set_status("Generating Report...")
        set_progress(0.90)

        latest_report = generate_report(
            apk_name,
            permissions,
            suspicious_permissions,
            dangerous_count,
            flagged_count,
            misuse_detected
        )

        append_log(f"Report saved to: {latest_report}")

        # -----------------------------------------
        # FINAL RISK SCORING
        # -----------------------------------------
        combined_risk = (
            dangerous_count * 10 +
            flagged_count * 15 +
            dyn_score
        )

        if combined_risk >= 80:
            overall_risk = "HIGH"
            risk_color = "red"
        elif combined_risk >= 40:
            overall_risk = "MEDIUM"
            risk_color = "orange"
        else:
            overall_risk = "LOW"
            risk_color = "green"

        # -----------------------------------------
        # UPDATE GUI
        # -----------------------------------------
        def update_ui():

            # ── Dashboard widgets ──────────────────────────────────────────
            risk_value.configure(text=overall_risk, text_color=risk_color)

            summary_label.configure(
                text=(
                    f"Permissions: {len(permissions)}   |   "
                    f"Combined Risk: {combined_risk}"
                )
            )

            perm_label.configure(text=f"Permissions: {permissions}")
            suspicious_label.configure(text=f"ML Flags: {suspicious_permissions}")
            dynamic_label.configure(text=f"Dynamic Flags: {dynamic_flags}")

            if "CAMERA" in permissions and "INTERNET" in permissions:
                insight = "Camera + Internet may indicate privacy exfiltration risk."
            elif "READ_CONTACTS" in permissions or "CONTACTS" in permissions:
                insight = "Contact harvesting indicators detected."
            elif misuse_detected:
                insight = "ML model detected suspicious permission pattern."
            else:
                insight = "No critical threat indicators observed."

            insight_label.configure(text=f"Insight: {insight}")

            # ── NEW: populate the Report tab ──────────────────────────────
            _load_report_into_viewer()

            # ── Severity Graph ────────────────────────────────────────────
            plot_severity_graph(graph_frame, permissions)

            progress.set(1)
            status_label.configure(text="Analysis Completed")

        ui(update_ui)

    except Exception as e:
        traceback.print_exc()
        ui(lambda: messagebox.showerror("Analysis Error", str(e)))
        set_status("Failed")
        set_progress(0)

    finally:
        scan_in_progress = False
        ui(lambda: scan_button.configure(state="normal"))


# -------------------------------------------------
# REPORT VIEWER HELPER  ← NEW
# -------------------------------------------------
def _load_report_into_viewer():
    """
    Read the latest generated report file and display it in the
    Report tab textbox.  Also updates the small status label so the
    user knows where the file lives.
    """
    global latest_report

    # Clear previous content
    report_box.delete("1.0", tk.END)

    if not latest_report or not os.path.exists(latest_report):
        report_box.insert(tk.END, "Report file not found.")
        report_status_label.configure(text="Report file not found.")
        return

    try:
        with open(latest_report, encoding="utf-8") as f:
            content = f.read()

        report_box.insert(tk.END, content)

        # Show path in the small status label beneath the textbox
        report_status_label.configure(
            text=f"Report saved at: {os.path.abspath(latest_report)}"
        )

    except Exception as exc:
        report_box.insert(tk.END, f"Could not read report:\n{exc}")
        report_status_label.configure(text="Error reading report file.")


# -------------------------------------------------
# FILE BROWSE + THREADING
# -------------------------------------------------
def start_scan():
    global scan_in_progress

    if scan_in_progress:
        return

    path = filedialog.askopenfilename(
        filetypes=[("APK Files", "*.apk")]
    )

    if not path:
        return

    scan_in_progress = True
    scan_button.configure(state="disabled")
    console_box.delete("1.0", tk.END)
    reset_scan_view()

    threading.Thread(
        target=analyze_apk,
        args=(path,),
        daemon=True
    ).start()


# -------------------------------------------------
# DOWNLOAD / EXPORT REPORT  ← enhanced
# -------------------------------------------------
def save_report():
    global latest_report

    if not latest_report or not os.path.exists(latest_report):
        messagebox.showwarning("No Report", "Generate a report first.")
        return

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        initialfile=os.path.basename(latest_report)   # pre-fill filename
    )

    if save_path:
        with open(latest_report, "r", encoding="utf-8") as src, \
             open(save_path,    "w", encoding="utf-8") as dst:
            dst.write(src.read())

        messagebox.showinfo("Saved", f"Report exported to:\n{save_path}")


# =================================================================
# GUI LAYOUT
# =================================================================
root = ctk.CTk()
root.geometry(WINDOW_SIZE)
root.title(APP_TITLE)


# ── HEADER ────────────────────────────────────────────────────────
header = ctk.CTkFrame(root, corner_radius=18)
header.pack(fill="x", padx=15, pady=12)

ctk.CTkLabel(
    header,
    text="PermissionShield",
    font=("Arial", 30, "bold")
).pack(pady=5)

ctk.CTkLabel(
    header,
    text="Hybrid Android Permission Misuse Detection Framework"
).pack(pady=(0, 8))


# ── TABS ──────────────────────────────────────────────────────────
tabs = ctk.CTkTabview(root)
tabs.pack(fill="both", expand=True, padx=15, pady=10)


# =================================================================
# TAB 1 – DASHBOARD
# =================================================================
tab1 = tabs.add("Dashboard")

scan_button = ctk.CTkButton(
    tab1, text="Scan APK", height=42, command=start_scan
)
scan_button.pack(pady=10)

status_label = ctk.CTkLabel(tab1, text="Ready")
status_label.pack()

progress = ctk.CTkProgressBar(tab1)
progress.pack(fill="x", padx=20, pady=10)
progress.set(0)

risk_frame = ctk.CTkFrame(tab1, corner_radius=18)
risk_frame.pack(fill="x", padx=20, pady=8)

ctk.CTkLabel(risk_frame, text="OVERALL RISK").pack(pady=(8, 0))

risk_value = ctk.CTkLabel(
    risk_frame, text="--", font=("Arial", 28, "bold")
)
risk_value.pack(pady=8)

summary_label = ctk.CTkLabel(tab1, text="No scan performed yet")
summary_label.pack(pady=8)

info_frame = ctk.CTkFrame(tab1)
info_frame.pack(fill="x", padx=20, pady=10)

perm_label = ctk.CTkLabel(info_frame, text="Permissions: --")
perm_label.pack(anchor="w", padx=10, pady=4)

suspicious_label = ctk.CTkLabel(info_frame, text="ML Flags: --")
suspicious_label.pack(anchor="w", padx=10, pady=4)

dynamic_label = ctk.CTkLabel(info_frame, text="Dynamic Flags: --")
dynamic_label.pack(anchor="w", padx=10, pady=4)

insight_label = ctk.CTkLabel(tab1, text="")
insight_label.pack(pady=10)

ctk.CTkLabel(tab1, text="Analysis Console").pack()

console_box = ctk.CTkTextbox(tab1, height=180)
console_box.pack(fill="both", expand=True, padx=20, pady=10)

save_button = ctk.CTkButton(
    tab1, text="Export Report", command=save_report
)
save_button.pack(pady=8)


# =================================================================
# TAB 2 – REPORT  ← enhanced with status label + download button
# =================================================================
tab2 = tabs.add("Report")

# Top bar: heading + download button side-by-side
report_top_bar = ctk.CTkFrame(tab2, fg_color="transparent")
report_top_bar.pack(fill="x", padx=12, pady=(10, 0))

ctk.CTkLabel(
    report_top_bar,
    text="Generated Report",
    font=("Arial", 16, "bold")
).pack(side="left")

# ── NEW: Download button inside the Report tab ─────────────────
ctk.CTkButton(
    report_top_bar,
    text="Download Report",
    width=150,
    command=save_report          # reuses the same save_report function
).pack(side="right")

# Scrollable report viewer
report_box = ctk.CTkTextbox(tab2)
report_box.pack(fill="both", expand=True, padx=12, pady=8)

# ── NEW: small path label at the bottom of the Report tab ─────
report_status_label = ctk.CTkLabel(
    tab2,
    text="No report generated yet.",
    font=("Arial", 11),
    text_color="gray"
)
report_status_label.pack(pady=(0, 6))


# =================================================================
# TAB 3 – SEVERITY GRAPH
# =================================================================
tab3 = tabs.add("Severity Graph")

graph_frame = ctk.CTkFrame(tab3, corner_radius=20)
graph_frame.pack(fill="both", expand=True, padx=20, pady=20)


root.mainloop()