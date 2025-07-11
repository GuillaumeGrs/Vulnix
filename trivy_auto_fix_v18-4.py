# trivy_auto_fix_v18-4.py
# Changes since v18.3:
# - Invalid pip install for "python3" is now skipped entirely (system-level).
# - Output files (report + fix script) now include date/time suffixes.
# - A companion symlink "fix_trivy_issues_latest.sh" is created or updated to point to the most recent script.
# - Includes requirements.txt for simplified installation.

#!/usr/bin/env python3
import os
import subprocess
import sys
import json
import tempfile
import shutil
from datetime import datetime

VENV_DIR = os.path.expanduser("~/trivy_env")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
THIS_FILE = os.path.abspath(__file__)
VENV_PATH = os.path.expanduser("~/trivy_env")

if sys.executable != VENV_PYTHON:
    print("[*] Relaunching script using virtual environment...")
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

if sys.prefix == VENV_DIR or sys.prefix.startswith(VENV_DIR):
    import openai
    import tiktoken
else:
    print("[*] Not in virtual environment. Preparing venv at ~/trivy_env...")
    if not os.path.exists(VENV_DIR):
        print("[*] Creating virtual environment...")
        subprocess.run(["python3", "-m", "venv", VENV_DIR], check=True)
    print("[*] Installing required packages into venv...")
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "openai", "tiktoken"], check=True)
    print("[*] Re-launching script inside virtual environment...")
    os.execv(VENV_PYTHON, [VENV_PYTHON, THIS_FILE] + sys.argv[1:])

import tiktoken
import openai

desktop_path = os.path.expanduser("~/Desktop")
os.makedirs(desktop_path, exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_filename = f"trivy_auto_report_{timestamp}.json"
script_filename = f"fix_trivy_issues_{timestamp}.sh"
symlink_path = os.path.join(desktop_path, "fix_trivy_issues_latest.sh")

OUTPUT_PATH = os.path.join(desktop_path, report_filename)
FIX_SCRIPT_PATH = os.path.join(desktop_path, script_filename)

API_KEY = "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"
MODEL_NAME = "gpt-4.1-nano"

LIGHT_SCAN_DIRS = ["/etc", "/usr/bin", "/usr/lib", "/usr/local/bin"]
FULL_SCAN_DIRS = ["/"]

light_scan = "--light-scan" in sys.argv
dry_run = "--dry-run" in sys.argv

top_cves = None
for arg in sys.argv:
    if arg.startswith("--top-CVES="):
        try:
            top_cves = int(arg.split("=")[1])
        except ValueError:
            pass

while True:
    fix_level = input("[?] Fix all vulnerabilities or only HIGH/CRITICAL? [all/high]: ").strip().lower()
    if fix_level in ["all", "high"]:
        break
    print("[!] Invalid input. Please type 'all' or 'high'.")

scan_dirs = LIGHT_SCAN_DIRS if light_scan else FULL_SCAN_DIRS
print(f"[+] Running {'light' if light_scan else 'full'} scan...")

if light_scan:
    merged_results = {"Results": []}
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
        "--severity", "HIGH,CRITICAL" if fix_level == "high" else "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        "--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go"
    ]
    subprocess.run(scan_cmd, check=True)
    print(f"[+] Full scan complete. Report saved to {OUTPUT_PATH}")

with open(OUTPUT_PATH, "r") as f:
    report_data = json.load(f)

filtered_results = []
for result in report_data.get("Results", []):
    vulns = result.get("Vulnerabilities", [])
    if fix_level == "high":
        vulns = [v for v in vulns if v.get("Severity") in ["HIGH", "CRITICAL"]]
    if top_cves:
        vulns = sorted(vulns, key=lambda v: v.get("CVSS", {}).get("nvd", {}).get("V3Score", 0), reverse=True)[:top_cves]
    if vulns:
        filtered_results.append({"Target": result.get("Target"), "Vulnerabilities": vulns})

filtered_report = {"Results": filtered_results}
report = json.dumps(filtered_report)

all_cves = sum(len(r.get("Vulnerabilities", [])) for r in report_data.get("Results", []))
high_cves = sum(
    1 for r in report_data.get("Results", [])
    for v in r.get("Vulnerabilities", []) if v.get("Severity") in ["HIGH", "CRITICAL"]
)
included_cves = sum(len(r["Vulnerabilities"]) for r in filtered_results)

print(f"[+] CVEs included in fix script: {included_cves} total, {high_cves} HIGH or CRITICAL")

enc = tiktoken.encoding_for_model("gpt-4")
tokens_input = len(enc.encode(report))
tokens_prompt = len(enc.encode("You are a Linux vulnerability assistant. Based on the following Trivy scan report (in JSON format), generate a safe and practical shell script to fix the vulnerabilities. Use apt, pip, or gem as needed. Only output the shell script content."))
tokens_total = tokens_input + tokens_prompt
cost_estimate = (tokens_input * 0.10 + 500 * 0.40) / 1_000_000
print(f"[+] Estimated input tokens: {tokens_total}")
print(f"[+] Estimated cost for this request: ${cost_estimate:.4f} USD")

MAX_INPUT_TOKENS = 28000
if tokens_total > MAX_INPUT_TOKENS:
    print(f"[!] Input too large ({tokens_total} tokens). Try --top-CVES=N or --light-scan.")
    sys.exit(1)

confirm = input("[?] Do you want to proceed with the OpenAI request? [y/N]: ").strip().lower()
if confirm != 'y':
    print("[*] Aborted by user.")
    sys.exit(0)

client = openai.OpenAI(api_key=API_KEY)

prompt = f"""You are a Linux vulnerability assistant. Based on the following Trivy scan report (in JSON format), generate a safe and practical shell script to fix the vulnerabilities. Use apt, pip, or gem as needed. If you include npm commands, wrap them in a conditional check that skips them if npm is not installed. Only output the shell script content.

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
    fix_script = "".join(fix_script.splitlines()[1:-1])

if dry_run:
    wrapped_lines = []
    for line in fix_script.splitlines():
        cmd = line.strip()
        if (
            cmd and not cmd.startswith("#") and not cmd.startswith("echo") and
            not any(x in cmd for x in ["{", "}", ";;", ")", "case", "esac", "function"]) and
            not any(w in cmd for w in ["do", "while", "for", "if", "done", "then"]) and
            not cmd.endswith("do") and not cmd.endswith("then") and
            "pip install python3" not in cmd
        ):
            wrapped_lines.append(f"read -p '[?] Run: {cmd} ? [y/N]: ' answer")
            wrapped_lines.append('if [[ $answer == "y" || $answer == "Y" ]]; then')
            wrapped_lines.append(f'  {cmd}')
            wrapped_lines.append('else')
            wrapped_lines.append('  echo "Skipped."')
            wrapped_lines.append('fi')
        else:
            wrapped_lines.append(cmd)
    fix_script = "".join(wrapped_lines)

with open(FIX_SCRIPT_PATH, "w") as f:
    f.write(fix_script)
os.chmod(FIX_SCRIPT_PATH, 0o755)
print(f"[+] Fix script written to {FIX_SCRIPT_PATH}")

try:
    if os.path.islink(symlink_path) or os.path.exists(symlink_path):
        os.remove(symlink_path)
    os.symlink(FIX_SCRIPT_PATH, symlink_path)
    print(f"[+] Symlink created at {symlink_path}")
except Exception as e:
    print(f"[!] Failed to create symlink: {e}")
