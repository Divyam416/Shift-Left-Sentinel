import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

# Configuration: We will tweak these later in Phase 2
RISK_THRESHOLD = 80

# Mapping severity labels to risk points
SEVERITY_WEIGHTS = {
    'CRITICAL': 40,
    'HIGH': 25,
    'ERROR': 25,    # Semgrep uses "ERROR" for high severity
    'MEDIUM': 10,
    'WARNING': 10,  # Semgrep uses "WARNING"
    'LOW': 5,
    'INFO': 1,
    'UNKNOWN': 0
}

# Context Multipliers (The "Intelligence" Layer)
CONTEXT_MULTIPLIERS = {
    'production': 1.0,  # Standard code
    'test': 0.1,        # Test files (Low risk)
    'docs': 0.0,        # Documentation (Zero risk)
    'config': 1.5,      # Config files (High risk for secrets!)
    'ci_cd': 2.0        # Pipeline files (Extreme risk!)
}


def get_context_multiplier(filepath):
    """Analyzes the file path to determine its risk context."""
    filepath = str(filepath).lower()

    if any(x in filepath for x in ['test/', 'tests/', '_test.py', '.spec.js']):
        return CONTEXT_MULTIPLIERS['test']

    if any(x in filepath for x in ['.md', '.txt', 'docs/']):
        return CONTEXT_MULTIPLIERS['docs']

    if any(x in filepath for x in ['dockerfile', 'docker-compose', '.github/', 'jenkinsfile']):
        return CONTEXT_MULTIPLIERS['ci_cd']

    if any(x in filepath for x in ['config', '.env', 'settings.py']):
        return CONTEXT_MULTIPLIERS['config']

    return CONTEXT_MULTIPLIERS['production']


def run_semgrep_scan(target_path, output_file):
    """Run Semgrep internally and write telemetry to output_file."""
    command = [
        'semgrep', 'scan', '--config', 'auto', '--json', '--output', str(output_file), str(target_path)
    ]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        print("Warning: semgrep CLI not found. Skipping Semgrep scan.")
        return False

    if result.returncode not in (0, 1):
        print(f"Warning: Semgrep scan failed (exit {result.returncode}). Skipping Semgrep findings.")
        return False

    return True


def run_trivy_scan(target_path, output_file):
    """Run Trivy internally and write telemetry to output_file."""
    command = [
        'trivy', 'fs', str(target_path), '--format', 'json', '--output', str(output_file), '--quiet'
    ]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        print("Warning: trivy CLI not found. Skipping Trivy scan.")
        return False

    if result.returncode != 0:
        print(f"Warning: Trivy scan failed (exit {result.returncode}). Skipping Trivy findings.")
        return False

    return True


def parse_semgrep(filename):
    """Reads Semgrep JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for result in data.get('results', []):
            issue = {
                'tool': 'Semgrep',
                'rule_id': result.get('check_id'),
                'file': result.get('path'),
                'severity': result.get('extra', {}).get('severity', 'UNKNOWN'),
                'message': result.get('extra', {}).get('message')
            }
            issues.append(issue)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping Semgrep scan.")
    except json.JSONDecodeError:
        print(f"Error: {filename} is empty or invalid JSON. Skipping.")
    return issues


def parse_trivy(filename):
    """Reads Trivy JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if 'Results' in data:
            for target in data['Results']:
                for vuln in target.get('Vulnerabilities', []):
                    issue = {
                        'tool': 'Trivy',
                        'rule_id': vuln.get('VulnerabilityID'),
                        'file': target.get('Target'),
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'message': vuln.get('Description')
                    }
                    issues.append(issue)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping Trivy scan.")
    except json.JSONDecodeError:
        print(f"Error: {filename} is empty or invalid JSON. Skipping.")
    return issues


def calculate_shannon_entropy(data):
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def is_high_entropy(secret_string, threshold=4.5):
    """Returns True if the string looks random (high entropy)."""
    return calculate_shannon_entropy(secret_string) > threshold


def calculate_risk_score(issues):
    total_score = 0
    print("\n--- Risk Calculation Details (Context-Aware) ---")

    for issue in issues:
        severity = issue.get('severity', 'UNKNOWN').upper()
        base_weight = SEVERITY_WEIGHTS.get(severity, 0)

        file_path = issue.get('file', 'unknown')
        multiplier = get_context_multiplier(file_path)

        final_weight = int(base_weight * multiplier)

        print(f"[{severity}] in '{file_path}'")
        print(f"   ↳ Base: {base_weight} x Context: {multiplier} = {final_weight} pts")

        total_score += final_weight

    return total_score


def main(argv=None):
    argv = argv or sys.argv
    print("--- Shift-Left Sentinel: Risk Calculator ---")

    if len(argv) != 2:
        print("Usage: python scripts/risk_engine.py <target_file_or_directory>")
        return 2

    target_path = Path(argv[1])
    if not target_path.exists():
        print(f"Error: target '{target_path}' does not exist.")
        return 2

    with tempfile.TemporaryDirectory(prefix='risk_engine_') as temp_dir:
        semgrep_output = Path(temp_dir) / 'semgrep_output.json'
        trivy_output = Path(temp_dir) / 'trivy_output.json'

        print(f"Running Semgrep on: {target_path}")
        run_semgrep_scan(target_path, semgrep_output)
        print(f"Running Trivy on: {target_path}")
        run_trivy_scan(target_path, trivy_output)

        semgrep_issues = parse_semgrep(semgrep_output)
        trivy_issues = parse_trivy(trivy_output)

    all_issues = semgrep_issues + trivy_issues
    print(f"\nSuccessfully loaded {len(all_issues)} issues.")

    total_risk_score = calculate_risk_score(all_issues)

    print("\n------------------------------------------------")
    print(f"TOTAL RISK SCORE: {total_risk_score} / 100 (Scale)")
    print(f"RISK THRESHOLD:   {RISK_THRESHOLD}")
    print("------------------------------------------------")

    if total_risk_score > RISK_THRESHOLD:
        print(" DECISION: BLOCK MERGE (Risk too high)")
        return 1

    print(" DECISION: ALLOW MERGE (Risk within limits)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
