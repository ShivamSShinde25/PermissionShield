from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


# -------------------------------------------------
# Permission Severity Classification
# -------------------------------------------------

def classify_permissions(permissions):

    low = {
        "ACCESS_WIFI_STATE",
        "ACCESS_NETWORK_STATE",
        "VIBRATE",
        "INTERNET",
        "BLUETOOTH",
        "STORAGE"
    }

    medium = {
        "CAMERA",
        "RECORD_AUDIO",
        "MICROPHONE",
        "LOCATION"
    }

    high = {
        "READ_SMS",
        "SEND_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_CALL_LOG",
        "CONTACTS"
    }


    severity_count = {
        "Low":0,
        "Medium":0,
        "High":0
    }


    for perm in permissions:

        p = perm.upper().strip()

        if p in high:
            severity_count["High"] += 1

        elif p in medium:
            severity_count["Medium"] += 1

        else:
            severity_count["Low"] += 1


    return severity_count



# -------------------------------------------------
# Severity Graph
# -------------------------------------------------

def plot_severity_graph(frame, permissions):

    # Clear previous graph
    for widget in frame.winfo_children():
        widget.destroy()


    severity = classify_permissions(permissions)

    levels = [
        "Low",
        "Medium",
        "High"
    ]

    counts = [
        severity["Low"],
        severity["Medium"],
        severity["High"]
    ]


    # Larger figure like expected output
    fig = plt.Figure(
        figsize=(10,7),
        dpi=100
    )

    ax = fig.add_subplot(111)


    colors = [
        "green",
        "orange",
        "red"
    ]


    bars = ax.bar(
        levels,
        counts,
        color=colors
    )


    # Graph title
    ax.set_title(
        "Permission Risk Distribution",
        fontsize=16,
        pad=15
    )


    # Clean Y range
    ymax = max(counts) + 1
    ax.set_ylim(0, ymax)


    # Add count labels above bars
    for bar in bars:

        height = bar.get_height()

        ax.text(
            bar.get_x() + bar.get_width()/2,
            height + 0.08,
            str(int(height)),
            ha='center',
            fontsize=12
        )


    # Clean appearance
    ax.grid(False)


    # Embed into GUI
    canvas = FigureCanvasTkAgg(
        fig,
        master=frame
    )

    canvas.draw()

    canvas.get_tk_widget().pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )