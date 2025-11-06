#!/usr/bin/env python3
import os
import subprocess
import sys
import json
import tempfile
import shutil


VENV_DIR = os.path.expanduser("~/trivy_env")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
THIS_FILE = os.path.abspath(__file__)
VENV_PATH = os.path.expanduser("~/trivy_env")

if sys.executable != VENV_PYTHON:
    print("[*] Relaunching script using virtual environment...")
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# --- Step 1: Check if already inside venv ---
if sys.prefix == VENV_DIR or sys.prefix.startswith(VENV_DIR):
    # Already in venv — import dependencies and continue
    import openai
    import tiktoken

else:
    # Not in venv yet
    print("[*] Not in virtual environment. Preparing venv at ~/trivy_env...")

    if not os.path.exists(VENV_DIR):
        print("[*] Creating virtual environment...")
        subprocess.run(["python3", "-m", "venv", VENV_DIR], check=True)

    print("[*] Installing required packages into venv...")
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "openai", "tiktoken"], check=True)

    print("[*] Re-launching script inside virtual environment...")
    os.execv(VENV_PYTHON, [VENV_PYTHON, THIS_FILE] + sys.argv[1:])

# --- MAIN LOGIC (same as v0.15 from here) ---import openai
import tiktoken
import os

desktop_path = os.path.expanduser("~/Desktop")
if not os.path.exists(desktop_path):
    os.makedirs(desktop_path)

API_KEY = "XXX"
MODEL_NAME = "gpt-4.1-nano"
OUTPUT_PATH = os.path.join(desktop_path, "trivy_auto_report.json")
FIX_SCRIPT_PATH = os.path.join(desktop_path, "fix_trivy_issues.sh")
LIGHT_SCAN_DIRS = ["/etc", "/usr/bin", "/usr/lib", "/usr/local/bin"]
FULL_SCAN_DIRS = ["/"]

light_scan = "--light-scan" in sys.argv
dry_run = "--dry-run" in sys.argv

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
                "--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go"
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
        "--skip-dirs", "/var/lib/gvm,/home/kali/.local/share/torbrowser,/home/kali/go"
    ]
    subprocess.run(scan_cmd, check=True)
    print(f"[+] Full scan complete. Report saved to {OUTPUT_PATH}")

with open(OUTPUT_PATH, "r") as f:
    report_data = json.load(f)
report = json.dumps(report_data)

all_cves = 0
high_cves = 0
for result in report_data.get("Results", []):
    vulns = result.get("Vulnerabilities", [])
    all_cves += len(vulns)
    high_cves += sum(1 for v in vulns if v.get("Severity") in ["HIGH", "CRITICAL"])
print(f"[+] CVEs found in this scan: {all_cves} total, {high_cves} HIGH or CRITICAL")

enc = tiktoken.encoding_for_model("gpt-4")
tokens_input = len(enc.encode(report))
tokens_prompt = len(enc.encode("You are a Linux vulnerability assistant. Based on the following Trivy scan report (in JSON format), generate a safe and practical shell script to fix the vulnerabilities. Use apt, pip, or gem as needed. Only output the shell script content."))
tokens_total = tokens_input + tokens_prompt
cost_estimate = (tokens_input * 0.10 + 500 * 0.40) / 1_000_000
print(f"[+] Estimated input tokens: {tokens_total}")
print(f"[+] Estimated cost for this request: ${cost_estimate:.4f} USD")

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
            cmd
            and not cmd.startswith("#")
            and not cmd.startswith("echo")
            and not any(x in cmd for x in ["{", "}", ";;", ")", "case", "esac", "function"])
            and not any(w in cmd for w in ["do", "while", "for", "if", "done", "then"])
            and not cmd.endswith("do")
            and not cmd.endswith("then")
        ):
            wrapped_lines.append(f"read -p '[?] Run: {cmd} ? [y/N]: ' answer")
            wrapped_lines.append('if [[ $answer == "y" || $answer == "Y" ]]; then')
            wrapped_lines.append(f'  {cmd}')
            wrapped_lines.append('else')
            wrapped_lines.append('  echo "Skipped."')
            wrapped_lines.append('fi')
        else:
            wrapped_lines.append(cmd)
    fix_script = "\n".join(wrapped_lines)

with open(FIX_SCRIPT_PATH, "w") as f:
    f.write(fix_script)

os.chmod(FIX_SCRIPT_PATH, 0o755)
print(f"[+] Fix script written to {FIX_SCRIPT_PATH}")
