#!/usr/bin/env python3
# === IMPORTS ===
# These are required to handle JSON, run shell commands, parse arguments, and manage paths
import json
import argparse
import subprocess
import os
import sys
from pathlib import Path

# === PATH CONFIGURATION ===
# These variables define where the report and output files will be saved,
# and where the Python virtual environment will be stored
REPORT_PATH = str(Path.home() / "Desktop" / "trivy_auto_report.json")       # Final Trivy report file
FIX_SCRIPT_PATH = str(Path.home() / "Desktop" / "fix_trivy_issues.sh")     # Bash fix script output
VENV_DIR = Path.home() / "trivy_env"                                       # Python virtual environment folder
VENV_PYTHON = VENV_DIR / "bin" / "python"                                  # Python executable inside venv
VENV_PIP = VENV_DIR / "bin" / "pip"                                        # Pip executable inside venv

# === ARGUMENT PARSING ===
# Allow user to optionally do a light scan (partial scan) or dry-run (ask before fixing)
parser = argparse.ArgumentParser(description="Trivy scan and auto-fix tool")
parser.add_argument("--dry-run", action="store_true", help="Wrap each fix command with [y/N] confirmation")
parser.add_argument("--light-scan", action="store_true", help="Scan only common system paths (faster)")
args = parser.parse_args()

# === FUNCTION TO SETUP PYTHON VIRTUAL ENVIRONMENT ===
def prepare_virtualenv():
    # If the virtual environment doesn't exist, create it
    if not VENV_DIR.exists():
        print("[*] Not in virtual environment. Preparing venv at ~/trivy_env...")
        try:
            subprocess.run(["python3", "-m", "venv", str(VENV_DIR)], check=True)
        except subprocess.CalledProcessError:
            print("[!] Failed to create virtual environment. Is 'python3-venv' installed?")
            sys.exit(1)

    # Install pip (ensure it's available), and upgrade it
    try:
        subprocess.run([str(VENV_PYTHON), "-m", "ensurepip", "--upgrade"], check=True)
        subprocess.run([str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip"], check=True)

        # Install required Python packages inside the virtual environment
        subprocess.run([str(VENV_PIP), "install", "openai", "tiktoken"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Failed to install packages in virtualenv.")
        sys.exit(1)

    # Modify the environment so subsequent code uses the venv properly
    os.environ["PATH"] = str(VENV_DIR / "bin") + os.pathsep + os.environ["PATH"]
    os.environ["VIRTUAL_ENV"] = str(VENV_DIR)

# Only set up virtual environment if we're not already inside it
if not sys.prefix or "trivy_env" not in sys.prefix:
    prepare_virtualenv()

# Now that virtualenv is ready, import packages safely
import openai
import tiktoken

# === OPENAI CLIENT SETUP ===
client = openai.OpenAI()
MODEL = "gpt-4-1106-preview"  # Use GPT-4 mini for balance between cost and intelligence

# === BUILD TRIVY SCAN COMMAND ===
# Full scan = scan entire system
# Light scan = scan system folders (faster and safer)
scan_cmd = ["sudo", "trivy", "fs"]
if args.light_scan:
    print("[+] Running light scan...")
    scan_cmd += ["/etc", "/usr/bin", "/usr/lib", "/usr/local/bin"]
    scan_cmd += ["--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go"]
else:
    print("[+] Running full scan...")
    scan_cmd += ["/"]

# Add options to format output and save to JSON
scan_cmd += ["--scanners", "vuln", "--format", "json", "--output", REPORT_PATH]

# === RUN THE TRIVY SCAN ===
subprocess.run(scan_cmd, check=True)
print(f"[+] Scan complete. Report saved to {REPORT_PATH}")

# === LOAD AND PARSE THE REPORT TO COUNT VULNERABILITIES ===
with open(REPORT_PATH) as f:
    report = json.load(f)

# Count all CVEs and those with HIGH or CRITICAL severity
total_cves = 0
high_or_critical = 0
for result in report.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        total_cves += 1
        severity = vuln.get("Severity", "").upper()
        if severity in ["HIGH", "CRITICAL"]:
            high_or_critical += 1

print(f"[+] CVEs found in this scan: {total_cves} total, {high_or_critical} HIGH or CRITICAL")

# === ESTIMATE OPENAI API TOKEN USAGE AND COST ===
encoding = tiktoken.encoding_for_model(MODEL)
token_count = len(encoding.encode(json.dumps(report))) + 500  # Buffer to account for prompt/context
cost_per_million = 0.4  # GPT-4 mini input pricing
estimated_cost = (token_count / 1_000_000) * cost_per_million

# Show estimated token usage and ask user for confirmation
print(f"[+] Estimated input tokens: {token_count}")
print(f"[+] Estimated cost for this request: ${estimated_cost:.4f} USD")
proceed = input("[?] Do you want to proceed with the OpenAI request? [y/N]: ")
if proceed.lower() != "y":
    print("[*] Aborted by user.")
    sys.exit(0)

# === REQUEST A FIX SCRIPT FROM OPENAI BASED ON THE SCAN REPORT ===
response = client.chat.completions.create(
    model=MODEL,
    messages=[
        {"role": "system", "content": "You are a cybersecurity assistant. Write a bash script to remediate the vulnerabilities in a Trivy scan report."},
        {"role": "user", "content": f"This is the Trivy scan report: ```json\n{json.dumps(report)}```\nWrite a bash script that updates or remediates each CVE where possible. Only include real commands."}
    ],
    temperature=0.2,  # Keep output deterministic
)

# Extract the script content
fix_script = response.choices[0].message.content.strip()

# === REMOVE MARKDOWN FENCING IF GPT WRAPPED THE SCRIPT IN TRIPLE BACKTICKS ===
if fix_script.startswith("```"):
    fix_script = "\n".join(fix_script.splitlines()[1:-1])

# === IF --dry-run: ASK USER BEFORE EACH FIX COMMAND ===
if args.dry_run:
    wrapped_lines = []
    for line in fix_script.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            wrapped_lines.append(f'read -p "[?] Run: {stripped} ? [y/N]: " answer')
            wrapped_lines.append('if [[ $answer == "y" || $answer == "Y" ]]; then')
            wrapped_lines.append(f'  {stripped}')
            wrapped_lines.append('fi')
        else:
            wrapped_lines.append(line)
    fix_script = "\n".join(wrapped_lines)

# === SAVE THE FIX SCRIPT TO DESKTOP AND MAKE IT EXECUTABLE ===
with open(FIX_SCRIPT_PATH, "w") as f:
    f.write("#!/bin/bash\n")
    f.write("echo \"Starting vulnerability remediation process...\"\n")
    f.write(fix_script + "\n")

os.chmod(FIX_SCRIPT_PATH, 0o755)  # Give execution permissions
print(f"[+] Fix script written to {FIX_SCRIPT_PATH}")
