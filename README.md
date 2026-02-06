
Shift-Left Sentinel: Automated DevSecOps Gate
Shift-Left Sentinel is a proactive security framework that integrates automated vulnerability scanning directly into the developer workflow. By analyzing code and dependencies during the Pull Request stage, it prevents high-risk vulnerabilities from ever reaching the main branch.

System Architecture
The system is organized into four modular layers that work in sequence:

1. Ingestion & Orchestration (Module 1)
Trigger: Automates security checks on every push and pull_request to the main branch.
Environment: Provisions an ephemeral Ubuntu container to ensure a clean, isolated scan environment for every run.

2. Detection & Analysis (Module 2)
SAST (Semgrep): Scans the src/ directory for logic flaws, such as hardcoded credentials or insecure API usage.
SCA (Trivy): Analyzes requirements.txt to identify known vulnerabilities (CVEs) in third-party libraries.
Telemetry: Both tools export results into raw JSON files for processing.

3. Intelligence & Risk Core (Module 3)
RWCS Algorithm: A Python-based engine (risk_engine.py) that parses the JSON telemetry.
Scoring: It calculates a weighted Risk Score (0-100) based on the severity and quantity of findings.

4. Enforcement Gate (Module 4)
Proactive Blocking: If the calculated Risk Score exceeds the threshold (80), the script exits with a failure code.
Gatekeeping: GitHub Actions interprets the exit code to physically block the merge, forcing developers to remediate risks before proceeding.
