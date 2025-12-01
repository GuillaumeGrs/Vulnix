#!/usr/bin/env python3

# === IMPORTS ===
# These are required to handle JSON, run shell commands, parse arguments, and manage paths
import json
import argparse
import subprocess
import os
import sys
import shutil
import platform
from pathlib import Path

# === PATH CONFIGURATION ===
# These variables define where the report and output files will be saved,
# and where the Python virtual environment will be stored

def get_desktop_path():
    """
    Attempts to find the Windows Desktop path if running in WSL.
    Fallbacks to Linux Desktop or Home directory.
    """
    # Check if we are in WSL by looking for the interop file or specific environment variables
    if "WSL_DISTRO_NAME" in os.environ or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        try:
            # Try to get Windows username to construct path
            # A common pattern is /mnt/c/Users/<Username>/Desktop
            # We can try to invoke cmd.exe to get the username or just search common paths
            
            # Method 1: Use wslpath if available to convert Windows Desktop path
            # This is robust but requires 'wslpath' tool
            result = subprocess.run(["wslpath", "$(cmd.exe /c 'echo %USERPROFILE%')"], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                win_home = result.stdout.strip()
                win_desktop = Path(win_home) / "Desktop"
                if win_desktop.exists():
                    return win_desktop
            
            # Method 2: Heuristic search in /mnt/c/Users
            # This is a fallback
            c_users = Path("/mnt/c/Users")
            if c_users.exists():
                for user_dir in c_users.iterdir():
                    desktop = user_dir / "Desktop"
                    if desktop.exists() and user_dir.name not in ["Public", "Default", "All Users"]:
                        return desktop
        except Exception:
            pass
            
    # Fallback to standard Linux Desktop or Home
    linux_desktop = Path.home() / "Desktop"
    if linux_desktop.exists():
        return linux_desktop
    
    return Path.home()

OUTPUT_DIR = get_desktop_path()
REPORT_PATH = str(OUTPUT_DIR / "trivy_auto_report.json")       # Final Trivy report file
FIX_SCRIPT_PATH = str(OUTPUT_DIR / "fix_trivy_issues.sh")     # Bash fix script output
VENV_DIR = Path.home() / "trivy_env"                                       # Python virtual environment folder
if platform.system() == "Windows":
    VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
    VENV_PIP = VENV_DIR / "Scripts" / "pip.exe"
else:
    VENV_PYTHON = VENV_DIR / "bin" / "python"
    VENV_PIP = VENV_DIR / "bin" / "pip"

# === ARGUMENT PARSING ===
# Allow user to optionally do a light scan (partial scan) or dry-run (ask before fixing)
parser = argparse.ArgumentParser(description="Trivy scan and auto-fix tool")
parser.add_argument("--dry-run", action="store_true", help="Wrap each fix command with [y/N] confirmation")
parser.add_argument("--light-scan", action="store_true", help="Scan only common system paths (faster)")
parser.add_argument("--path", type=str, help="Specify a specific directory to scan (overrides --light-scan)")
args = parser.parse_args()

# === CHECK DEPENDENCIES ===
def check_trivy_installed():
    if not shutil.which("trivy"):
        print("[!] Error: 'trivy' is not installed or not in PATH.")
        print("    Please install it using the instructions at: https://aquasecurity.github.io/trivy/v0.18.3/installation/")
        print("    Debian/Ubuntu example: sudo apt-get install trivy")
        print("    Windows example: choco install trivy")
        sys.exit(1)

check_trivy_installed()

# === FUNCTION TO SETUP PYTHON VIRTUAL ENVIRONMENT ===
def prepare_virtualenv():
    # If the virtual environment doesn't exist, create it
    if not VENV_DIR.exists():
        print("[*] Not in virtual environment. Preparing venv at ~/trivy_env...")
        try:
            subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        except subprocess.CalledProcessError:
            print("[!] Failed to create virtual environment. Is 'python3-venv' installed?")
            sys.exit(1)

    # Install pip (ensure it's available), and upgrade it
    try:
        subprocess.run([str(VENV_PYTHON), "-m", "ensurepip", "--upgrade"], check=True)
        subprocess.run([str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip"], check=True)

        # Install required Python packages inside the virtual environment
        subprocess.run([str(VENV_PIP), "install", "google-generativeai"], check=True)
    except subprocess.CalledProcessError:
        print("[!] Failed to install packages in virtualenv.")
        sys.exit(1)

    # Modify the environment so subsequent code uses the venv properly
    os.environ["PATH"] = str(VENV_DIR / "bin") + os.pathsep + os.environ["PATH"]
    os.environ["VIRTUAL_ENV"] = str(VENV_DIR)

# Only set up virtual environment if we're not already inside it
# Only set up virtual environment if we're not already inside it
# We check if sys.prefix matches our VENV_DIR. 
# We avoid .resolve() on the executable because venv often symlinks to system python.
if sys.prefix != str(VENV_DIR):
    prepare_virtualenv()
    
    # Re-execute the script with the venv python
    print(f"[*] Switching to virtual environment: {VENV_PYTHON}")
    try:
        # Pass all original arguments to the new process
        subprocess.run([str(VENV_PYTHON), __file__] + sys.argv[1:], check=True)
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to re-execute script: {e}")
        sys.exit(e.returncode)

# Now that virtualenv is ready, import packages safely
import google.generativeai as genai

# === GEMINI API SETUP ===
# Try to load API key from API.txt or environment variable
API_KEY_FILE = Path(__file__).parent.parent / "API.txt"
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key and API_KEY_FILE.exists():
    try:
        with open(API_KEY_FILE, "r") as f:
            api_key = f.read().strip()
    except Exception:
        pass

if not api_key:
    print("[!] Error: No Gemini API Key found. Please set GEMINI_API_KEY env var or put it in API.txt")
    sys.exit(1)

genai.configure(api_key=api_key)
MODEL_NAME = "gemini-1.5-flash"
model = genai.GenerativeModel(MODEL_NAME)

# === BUILD TRIVY SCAN COMMAND ===
# Full scan = scan entire system
# Light scan = scan system folders (faster and safer)
# === BUILD TRIVY SCAN COMMAND ===
# Full scan = scan entire system
# Light scan = scan system folders (faster and safer)
# Custom path = scan user provided path
scan_cmd = ["trivy", "fs"]
if platform.system() != "Windows":
    scan_cmd.insert(0, "sudo")

if args.path:
    print(f"[+] Running scan on custom path: {args.path}")
    scan_cmd += [args.path]
elif args.light_scan:
    print("[+] Running light scan...")
    # Trivy fs only accepts ONE target. We scan root but skip heavy dirs.
    if platform.system() == "Windows":
        scan_cmd += ["C:\\"]
        scan_cmd += ["--skip-dirs", "C:\\Windows\\Installer,C:\\Windows\\WinSxS"]
    else:
        scan_cmd += ["/"]
        # Skip heavy/irrelevant directories to make it "light"
        # CRITICAL: Exclude /mnt to avoid scanning Windows drives from WSL (extremely slow)
        scan_cmd += ["--skip-dirs", "/proc,/sys,/dev,/run,/var/lib,/var/log,/home/kali/.local,/home/kali/go,/snap,/mnt"]
else:
    print("[+] Running full scan...")
    scan_cmd += ["/"] if platform.system() != "Windows" else ["C:\\"]

# Add options to format output and save to JSON
# Increase timeout to 20m for large filesystems (especially /mnt/c in WSL)
scan_cmd += ["--scanners", "vuln", "--format", "json", "--output", REPORT_PATH, "--timeout", "20m"]

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

if total_cves == 0:
    print("[+] No vulnerabilities found. Exiting.")
    sys.exit(0)

# === ESTIMATE TOKEN USAGE ===
# Gemini 1.5 Flash is extremely cheap (often free for low volume), but we'll show token count.
prompt_text = f"This is the Trivy scan report: ```json\n{json.dumps(report)}```\nWrite a bash script that updates or remediates each CVE where possible. Only include real commands."

try:
    token_count = model.count_tokens(prompt_text).total_tokens
    print(f"[+] Estimated input tokens: {token_count}")
except Exception as e:
    print(f"[!] Warning: Could not estimate token count ({e}). Proceeding anyway.")
    token_count = "Unknown"
print(f"[+] Using model: {MODEL_NAME}")
proceed = input("[?] Do you want to proceed with the Gemini request? [y/N]: ")
if proceed.lower() != "y":
    print("[*] Aborted by user.")
    sys.exit(0)

# === REQUEST A FIX SCRIPT FROM GEMINI BASED ON THE SCAN REPORT ===
# Set system instruction via the model generation call or system_instruction if supported, 
# but for simple script generation, a direct prompt works well.
response = model.generate_content(
    f"You are a cybersecurity assistant. Write a bash script to remediate the vulnerabilities in a Trivy scan report.\n\n{prompt_text}"
)

# Extract the script content
fix_script = response.text.strip()

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
