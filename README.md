# PermissionShield

## About
PermissionShield is a Hybrid Android
Permission Misuse Detection Framework
that combines Static Analysis, Dynamic
Analysis and Machine Learning to detect
suspicious permission patterns in
Android APK files.

Built as a final year BE project and
published as a research paper in
IJSART Journal.

## Features
- APK file upload and scanning
- Static permission extraction using APKTool
- ML based misuse prediction
- Dynamic behavior pattern analysis
- Feature extraction and risk scoring
- Interactive CustomTkinter GUI
- Multi tab dashboard interface
- Severity graph visualization
- Detailed text report generation
- Export report functionality

## How It Works

### Step 1: Static Analysis
User uploads an APK file. APKTool
extracts the APK and parses
AndroidManifest.xml to get all
declared permissions.

### Step 2: ML Prediction
Extracted permissions are encoded
using feature encoder. Pre trained
model (model.pkl) predicts if the
APK shows misuse patterns using
0.3 confidence threshold.

### Step 3: Dynamic Analysis
Checks permission combinations for
suspicious runtime behaviors like:
- Camera + Internet (data exfiltration)
- Location + Internet (tracking)
- Contacts + Internet (harvesting)
- Microphone + Internet (surveillance)
  
*Note: The dynamic analysis
module performs simulation-based
analysis by evaluating suspicious
permission combinations rather
than actual runtime execution.
For full dynamic analysis, 
integration with Android emulators
would be required (future work).

### Step 4: Feature Extraction
Counts dangerous permissions and
behavior flags to calculate risk.

### Step 5: Risk Scoring
Calculates combined risk score:
- Dangerous count x 10
- Flagged count x 15
- Dynamic score

Categorizes as LOW / MEDIUM / HIGH

### Step 6: Severity Graph
Classifies permissions into three
severity levels:
- Low: Internet, Bluetooth etc
- Medium: Camera, Microphone, Location
- High: SMS, Contacts, Call Log

### Step 7: Report Generation
Detailed text report with all
findings saved to reports folder.

## Dataset
- Drebin Dataset
- Well known Android malware dataset
- Used for training ML classifier

## Tech Stack
- **Language:** Python
- **GUI:** Tkinter, CustomTkinter
- **ML:** Scikit-learn
- **APK Analysis:** APKTool
- **Data Handling:** Pandas, NumPy
- **Visualization:** Matplotlib
- **Threading:** Python threading module

## Project Structure

```
PermissionShield/
├── main.py
├── static_analysis/
│   └── static_analysis.py
├── dynamic_analysis/
│   └── dynamic_analysis.py
├── feature_extraction/
│   └── feature_extraction.py
├── model/
│   ├── predictor.py
│   ├── feature_encoder.py
│   ├── model.pkl
│   ├── drebin_features.pkl
│   └── drebin.csv
├── severity_identifier/
│   └── severity_identifier.py
├── reports/
│   └── report_generator.py
├── app_permission_misuse/
├── input/
└── logs/
```

## Requirements
- Python 3.8 or higher
- Java (for APKTool)
- APKTool installed

### Python Packages
- customtkinter
- scikit-learn
- pandas
- numpy
- matplotlib

## How To Run

### Setup
1. Clone this repository
2. Install required packages:
   ```
   pip install customtkinter scikit-learn pandas numpy matplotlib
   ```
4. Install APKTool
5. Update APKTool path in
   static_analysis.py

### Run Application
```
python main.py
```


### Usage
1. Click Scan APK button
2. Select APK file to analyze
3. Wait for analysis to complete
4. View results on dashboard
5. Check detailed report
6. See severity graph
7. Export report if needed

## Application Interface

### Tab 1: Dashboard
- Scan button
- Progress bar
- Overall risk display
- Permission list
- ML flags
- Dynamic flags
- Analysis console

### Tab 2: Report
- Full generated report
- Download report button

### Tab 3: Severity Graph
- Visual bar chart
- Low/Medium/High classification

## Research Publication

**Title:** PermissionShield: A Hybrid
Static and Dynamic Analysis Approach
for Android Permission Misuse Detection

**Journal:** IJSART

**Type:** Peer reviewed research paper

## Team
Final Year BE Project
Sinhgad Institute of Technology,
Lonavala

Co-authored by 4 team members

## License
This project is for academic purposes.
