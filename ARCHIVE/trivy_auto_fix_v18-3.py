#!/usr/bin/env python3
"""
TKT CHANGELOG - v18.3

- Added automatic timestamp to `fix_trivy_issues_<datetime>.sh` and `trivy_auto_report_<datetime>.json`
- Added `--break-system-packages` to all pip commands in fix script (PEP 668 workaround for Debian 13)
- Retains v18.2 logic: `--top-cves N` support to filter highest-severity vulnerabilities
"""

import os
import subprocess
import sys
import json
import tempfile
import shutil
from datetime import datetime

# --- ENV SETUP ---

VENV_DIR = os.path.expanduser("~/trivy_env")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
THIS_FILE = os.path.abspath(__file__)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
desktop_path = os.path.expanduser("~/Desktop")

if not os.path.exists(desktop_path):
    os.makedirs(desktop_path)

OUTPUT_PATH = os.path.join(desktop_path, f"trivy_auto_report_{timestamp}.json")
FIX_SCRIPT_PATH = os.path.join(desktop_path, f"fix_trivy_issues_{timestamp}.sh")

if sys.executable != VENV_PYTHON:
    print("[*] Relaunching script using virtual environment...")
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# --- Check and activate venv ---
if sys.prefix == VENV_DIR or sys.prefix.startswith(VENV_DIR):
    import openai
    import tiktoken
else:
    print("[*] Not in virtual environment. Preparing venv at ~/trivy_env...")
    if not os.path.exists(VENV_DIR):
        subprocess.run(["python3", "-m", "venv", VENV_DIR], check=True)

    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "openai", "tiktoken"], check=True)

    os.execv(VENV_PYTHON, [VENV_PYTHON, THIS_FILE] + sys.argv[1:])

# --- TRIVY SCAN LOGIC ---

API_KEY = "XXX"
MODEL_NAME = "gpt-4.1-nano"
LIGHT_SCAN_DIRS = ["/etc", "/usr/bin", "/usr/lib", "/usr/local/bin"]
FULL_SCAN_DIRS = ["/"]

light_scan = "--light-scan" in sys.argv
dry_run = "--dry-run" in sys.argv

# Ask severity preference
while True:
    fix_level = input("[?] Fix all vulnerabilities or only HIGH/CRITICAL? [all/high]: ").strip().lower()
    if fix_level in ["all", "high"]:
        break
    print("[!] Invalid input. Please type 'all' or 'high'.")

scan_dirs = LIGHT_SCAN_DIRS if light_scan else FULL_SCAN_DIRS
print(f"[+] Running {'light' if light_scan else 'full'} scan...")

merged_results = {"Results": []}

if light_scan:
    for path in scan_dirs:
        print(f"[>] Scanning {path}...")
        with tempfile.NamedTemporaryFile(delete=False, dir="/home/user") as tmp:
            scan_cmd = [
                "sudo", "trivy", "fs", path,
                "--scanners", "vuln",
                "--format", "json",
                "--output", tmp.name,
                "--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go",
                "--severity", "HIGH,CRITICAL" if fix_level == "high" else "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
            ]
            subprocess.run(scan_cmd, check=True)
            with open(tmp.name, "r") as f:
                try:
                    data = json.load(f)
                    if "Results" in data:
                        merged_results["Results"].extend(data["Results"])
                except Exception as e:
                    print(f"[!] Failed to parse scan result from {path}: {e}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(merged_results, f)
    print(f"[+] Light scan complete. Merged report saved to {OUTPUT_PATH}")
else:
    scan_cmd = [
        "sudo", "trivy", "fs", *scan_dirs,
        "--scanners", "vuln",
        "--format", "json",
        "--output", OUTPUT_PATH,
        "--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go",
        "--severity", "HIGH,CRITICAL" if fix_level == "high" else "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    ]
    subprocess.run(scan_cmd, check=True)
    print(f"[+] Full scan complete. Report saved to {OUTPUT_PATH}")

# --- PROCESS SCAN RESULTS ---

with open(OUTPUT_PATH, "r") as f:
    report_data = json.load(f)

all_vulns = []
for result in report_data.get("Results", []):
    for v in result.get("Vulnerabilities", []):
        all_vulns.append({
            "Target": result.get("Target"),
            "Vulnerability": v,
            "CVSS": max([v.get("CVSS", {}).get(source, {}).get("V3Score", 0) for source in v.get("CVSS", {})] + [0])
        })

# Sort and trim if requested
top_n = None
for arg in sys.argv:
    if arg.startswith("--top-cves="):
        try:
            top_n = int(arg.split("=")[1])
        except ValueError:
            pass

if top_n:
    all_vulns.sort(key=lambda x: x["CVSS"], reverse=True)
    all_vulns = all_vulns[:top_n]

# Rebuild filtered report
filtered_results = {}
for item in all_vulns:
    target = item["Target"]
    vuln = item["Vulnerability"]
    filtered_results.setdefault(target, []).append(vuln)

filtered_report = {"Results": [{"Target": t, "Vulnerabilities": v} for t, v in filtered_results.items()]}

# Count CVEs
all_cves = len(all_vulns)
high_cves = sum(1 for item in all_vulns if item["Vulnerability"].get("Severity") in ["HIGH", "CRITICAL"])

print(f"[+] CVEs included in fix script: {all_cves} total, {high_cves} HIGH or CRITICAL")

# --- TOKEN ESTIMATE ---

enc = tiktoken.encoding_for_model("gpt-4")
report = json.dumps(filtered_report)
tokens_input = len(enc.encode(report))
tokens_prompt = len(enc.encode("You are a Linux vulnerability assistant. Based on the following Trivy scan report (in JSON format), generate a safe and practical shell script to fix the vulnerabilities. Use apt, pip, or gem as needed. Only output the shell script content."))
tokens_total = tokens_input + tokens_prompt
cost_estimate = (tokens_input * 0.10 + 500 * 0.40) / 1_000_000

print(f"[+] Estimated input tokens: {tokens_total}")
print(f"[+] Estimated cost for this request: ${cost_estimate:.4f} USD")

MAX_INPUT_TOKENS = 28000
if tokens_total > MAX_INPUT_TOKENS:
    print(f"[!] Input too large ({tokens_total} tokens). Try --top-cves=N or --light-scan.")
    sys.exit(1)

# --- GPT CALL ---

confirm = input("[?] Do you want to proceed with the OpenAI request? [y/N]: ").strip().lower()
if confirm != 'y':
    print("[*] Aborted by user.")
    sys.exit(0)

client = openai.OpenAI(api_key=API_KEY)

prompt = f"""You are a Linux vulnerability assistant. Based on the following Trivy scan report (in JSON format), generate a safe and practical shell script to fix the vulnerabilities. Use apt, pip, or gem as needed. If you include pip commands, add --break-system-packages to each one to ensure compatibility with Debian 13. If you include npm commands, wrap them in a conditional check. Only output the shell script content.

Trivy JSON report:
{report}
"""

response = client.chat.completions.create(
    model=MODEL_NAME,
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2,
    max_tokens=1500
)

fix_script = response.choices[0].message.content.strip()
if fix_script.startswith("```"):
    fix_script = "\n".join(fix_script.splitlines()[1:-1])

# --- DRY-RUN WRAPPING ---

if dry_run:
    wrapped = []
    for line in fix_script.splitlines():
        cmd = line.strip()
        if (
            cmd
            and not cmd.startswith("#")
            and not cmd.startswith("echo")
            and not any(k in cmd for k in ["{", "}", ";;", ")", "case", "esac", "function"])
            and not any(w in cmd for w in ["do", "while", "for", "if", "done", "then"])
            and not cmd.endswith(("do", "then"))
        ):
            wrapped.append(f"read -p '[?] Run: {cmd} ? [y/N]: ' answer")
            wrapped.append('if [[ $answer == "y" || $answer == "Y" ]]; then')
            wrapped.append(f'  {cmd}')
            wrapped.append('else')
            wrapped.append('  echo "Skipped."')
            wrapped.append('fi')
        else:
            wrapped.append(cmd)
    fix_script = "\n".join(wrapped)

with open(FIX_SCRIPT_PATH, "w") as f:
    f.write(fix_script)

os.chmod(FIX_SCRIPT_PATH, 0o755)
print(f"[+] Fix script written to {FIX_SCRIPT_PATH}")
