#!/usr/bin/env python3

"""
VULNIX v2.2 - AI-Powered Vulnerability Scanner & Auto-Remediator
Author: You
Description: Combines Trivy, Gemini AI, and a Hacker-style TUI for vulnerability management.
"""

import sys
import os
import json
import argparse
import subprocess
import shutil
import platform
import datetime
import time
from pathlib import Path
from dataclasses import dataclass

# === CONFIGURATION CONSTANTS ===
TOOL_NAME = "VULNIX"
VERSION = "2.2.0"
DEFAULT_MODEL = "gemini-1.5-flash"
VENV_NAME = "trivy_env"
REQUIRED_PACKAGES = ["google-generativeai", "rich", "pyfiglet", "questionary"]

# === BOOTSTRAP: VIRTUAL ENVIRONMENT HANDLING ===
# This function runs first to ensure all libraries are installed
def bootstrap_venv():
    venv_dir = Path.home() / VENV_NAME
    
    # Determine paths
    if platform.system() == "Windows":
        venv_python = venv_dir / "Scripts" / "python.exe"
        venv_pip = venv_dir / "Scripts" / "pip.exe"
    else:
        venv_python = venv_dir / "bin" / "python"
        venv_pip = venv_dir / "bin" / "pip"

    # Check if we are running inside the correct venv
    if sys.prefix != str(venv_dir):
        # Create venv if it doesn't exist
        if not venv_dir.exists():
            print(f"[*] Initializing virtual environment at {venv_dir}...")
            try:
                subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            except subprocess.CalledProcessError:
                print("[!] Critical: Failed to create venv. Install 'python3-venv'.")
                sys.exit(1)

        # Check and install dependencies
        try:
            # Try importing a TUI lib to see if we need install
            subprocess.run([str(venv_python), "-c", "import rich; import questionary; import google.generativeai"], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print("[*] Installing dependencies (This may take a minute)...")
            subprocess.run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], check=True)
            subprocess.run([str(venv_pip), "install"] + REQUIRED_PACKAGES, check=True)

        print("[*] Loading VULNIX Engine...")
        try:
            # Re-launch script inside the venv
            os.environ["VIRTUAL_ENV"] = str(venv_dir)
            os.environ["PATH"] = str(venv_dir / "bin") + os.pathsep + os.environ["PATH"]
            subprocess.run([str(venv_python), __file__] + sys.argv[1:], check=True)
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            sys.exit(e.returncode)

# Run bootstrap immediately
bootstrap_venv()

# === IMPORTS (Available only after bootstrap) ===
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import pyfiglet
import questionary

# === DATA CLASS FOR ARGS ===
@dataclass
class ScanConfig:
    path: str = None
    light_scan: bool = False
    dry_run: bool = False

class VulnixAutomator:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.console = Console()
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = self._get_desktop_path()
        self.report_path = self.output_dir / f"VULNIX_report_{self.timestamp}.json"
        self.fix_script_path = self.output_dir / f"VULNIX_fix_{self.timestamp}.sh"
        self.api_key = self._load_api_key()
        
        # Configure Gemini
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model_name = self._get_best_model()
            self.model = genai.GenerativeModel(self.model_name)

    def _get_best_model(self):
        """Dynamically select the best available Gemini model."""
        preferred_order = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]
        try:
            available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
            clean_models = [m.replace("models/", "") for m in available_models]
            
            for preferred in preferred_order:
                if preferred in clean_models:
                    return preferred
            
            # Fallback: finding anything with "gemini"
            for m in clean_models:
                if "gemini" in m:
                    self.console.print(f"[bold yellow]⚠ Fallback Model:[/bold yellow] {m}")
                    return m
                    
            return "gemini-pro"
        except Exception as e:
            self.console.print(f"[bold red]⚠ Model list failed ({e}). Defaulting to {DEFAULT_MODEL}[/bold red]")
            return DEFAULT_MODEL

    def _get_desktop_path(self):
        """Finds Desktop path on Windows/WSL/Linux."""
        if "WSL_DISTRO_NAME" in os.environ:
            try:
                cmd = "wslpath $(cmd.exe /c 'echo %USERPROFILE%')"
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                if result.returncode == 0:
                    win_desktop = Path(result.stdout.strip()) / "Desktop"
                    if win_desktop.exists(): return win_desktop
            except: pass
        linux_desktop = Path.home() / "Desktop"
        return linux_desktop if linux_desktop.exists() else Path.home()

    def _load_api_key(self):
        """Loads API Key safely."""
        key = os.environ.get("GEMINI_API_KEY")
        key_file = Path(__file__).parent.parent / "API.txt"
        if not key and key_file.exists():
            try: key = key_file.read_text().strip()
            except: pass
        return key

    def check_dependencies(self):
        """Checks if Trivy is installed."""
        if not shutil.which("trivy"):
            self.console.print(Panel("[bold red]ERROR: 'trivy' is not installed.[/bold red]\nPlease install it via apt or choco.", title="Dependency Check", border_style="red"))
            sys.exit(1)

    def _ensure_sudo(self):
        """
        Refresh sudo credentials explicitly before hiding output.
        Prevents the script from hanging on invisible password prompts.
        """
        if platform.system() != "Windows":
            try:
                # sudo -v updates the user's cached credentials
                subprocess.run(["sudo", "-v"], check=True)
            except subprocess.CalledProcessError:
                self.console.print("[bold red]❌ Sudo authentication failed. Exiting.[/bold red]")
                sys.exit(1)

    def run_scan(self):
        """Executes the Trivy scan."""
        # 1. Ensure sudo access NOW (ask password if needed)
        self._ensure_sudo()

        cmd = ["trivy", "fs"]
        if platform.system() != "Windows": cmd.insert(0, "sudo")

        target_desc = "Full System"
        if self.config.path:
            cmd.append(self.config.path)
            target_desc = f"Custom: {self.config.path}"
        elif self.config.light_scan:
            target_desc = "Light Scan (System Dirs)"
            if platform.system() == "Windows":
                cmd += ["C:\\", "--skip-dirs", "C:\\Windows\\Installer,C:\\Windows\\WinSxS"]
            else:
                cmd += ["/", "--skip-dirs", "/proc,/sys,/dev,/run,/var/lib,/var/log,/mnt,/snap"]
        else:
            cmd.append("/") if platform.system() != "Windows" else cmd.append("C:\\")

        cmd += ["--scanners", "vuln", "--format", "json", "--output", str(self.report_path), "--timeout", "20m"]

        self.console.print(f"\n[bold cyan]Target:[/bold cyan] {target_desc}")
        
        # 2. Run scan with spinner (safe now that sudo is cached)
        with self.console.status("[bold green]Running Trivy Scan (This may take a while)...[/bold green]", spinner="dots"):
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.console.print("[bold red]Scan Failed![/bold red]")
                sys.exit(1)
        
        self.console.print(f"[bold green]✔ Scan Complete![/bold green] Report saved to: [underline]{self.report_path}[/underline]")

    def analyze_report(self):
        """Parses the JSON report and displays a summary table."""
        with open(self.report_path) as f:
            report = json.load(f)
        
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for res in report.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                stats["total"] += 1
                sev = vuln.get("Severity", "UNKNOWN").lower()
                if sev in stats: stats[sev] += 1

        # Pretty Table Output
        table = Table(title="Vulnerability Summary", border_style="blue")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        table.add_row("[bold red]CRITICAL[/bold red]", str(stats["critical"]))
        table.add_row("[red]HIGH[/red]", str(stats["high"]))
        table.add_row("[yellow]MEDIUM[/yellow]", str(stats["medium"]))
        table.add_row("[green]LOW[/green]", str(stats["low"]))
        table.add_row("[bold white]TOTAL[/bold white]", str(stats["total"]))
        
        self.console.print(table)
        
        if stats["total"] == 0:
            self.console.print(Panel("[bold green]System is CLEAN! No vulnerabilities found.[/bold green]", border_style="green"))
            sys.exit(0)
            
        return report

    def generate_fix(self, report_data):
        """Sends report to Gemini to generate a Bash fix script."""
        if not self.api_key:
            self.console.print("[bold yellow]⚠ No Gemini API Key found. Skipping auto-fix generation.[/bold yellow]")
            return None

        # Robust System Prompt (No JQ, Python Parser, Safety Checks)
        system_instruction = """
        You are an expert Senior Linux System Administrator.
        Your task is to generate a ROBUST Bash script to remediate vulnerabilities found in a Trivy JSON scan.

        ### INPUT CONTEXT
        The script will receive the path to the Trivy JSON report as the first argument ($1).

        ### NEGATIVE CONSTRAINTS (DO NOT DO THIS):
        1. **DO NOT EMBED THE JSON**: Never hardcode the JSON report inside the script. Read it from the file provided in argument $1.
        2. **DO NOT USE 'jq'**: Assume 'jq' is NOT installed.
        3. **DO NOT USE REGEX FOR JSON**: Do not try to parse JSON with grep/sed (it is fragile).

        ### POSITIVE REQUIREMENTS (DO THIS):
        1. **USE PYTHON FOR PARSING**: Since 'jq' is missing, use the system's python (python2 or python3) with the 'json' module to extract data. Use a heredoc or `python -c` one-liner to parse the input file ($1).
        2. **SAFETY CHECK**: Check if the current running OS (/etc/os-release) matches the OS detected in the JSON report. If mismatch, EXIT.
        3. **EOL HANDLING**:
        - If the detected OS is Debian Jessie (8) or Stretch (9):
            - Update /etc/apt/sources.list to use 'archive.debian.org'.
            - Set `Acquire::Check-Valid-Until "false";`.
            - Run `apt-get update` and `apt-get dist-upgrade` with `--force-yes` or `--allow-unauthenticated`.
        4. **OUTPUT**:
        - Return ONLY the raw Bash script.
        - Start immediately with `#!/bin/bash`.
        """
        
        full_prompt = f"{system_instruction}\n\nHere is the Trivy Scan Report content to analyze (but do not embed it):\n{json.dumps(report_data)}"
        
        self.console.print(f"\n[bold purple]AI Analysis[/bold purple]: Using model [cyan]{self.model_name}[/cyan]")
        
        # Interactive confirmation if in TUI mode
        if not self.config.dry_run and not questionary.confirm("Do you want Gemini to generate a fix script?").ask():
            self.console.print("[yellow]Skipping AI generation.[/yellow]")
            return None

        with self.console.status("[bold purple]Gemini is thinking (Analyzing CVEs)...[/bold purple]", spinner="earth"):
            try:
                response = self.model.generate_content(full_prompt)
                script_content = response.text.strip()
                # Clean Markdown backticks if present
                if script_content.startswith("```"):
                    lines = script_content.splitlines()
                    if lines[0].startswith("```"): lines = lines[1:]
                    if lines and lines[-1].startswith("```"): lines = lines[:-1]
                    script_content = "\n".join(lines)
                return script_content
            except Exception as e:
                self.console.print(f"[bold red]API Error: {e}[/bold red]")
                return None

    def save_script(self, content):
        """Saves the generated script to disk with optional Dry-Run wrappers."""
        if not content: return

        if self.config.dry_run:
            self.console.print("[italic]Adding Dry-Run safeguards...[/italic]")
            lines = content.splitlines()
            new_lines = []
            for line in lines:
                l = line.strip()
                # Heuristic: Wrap actionable commands only (apt, yum, rm, etc)
                if l and not l.startswith("#") and not any(x in l for x in ["if ", "fi", "then", "else", "do", "done", "read", "echo", "python", "exit"]):
                    new_lines.append(f'read -p "[DRY-RUN] Execute: {l}? [y/N] " confirm')
                    new_lines.append('if [[ $confirm == [yY] ]]; then')
                    new_lines.append(f'    {line}')
                    new_lines.append('fi')
                else:
                    new_lines.append(line)
            content = "\n".join(new_lines)

        with open(self.fix_script_path, "w") as f:
            if not content.startswith("#!"): f.write("#!/bin/bash\n")
            f.write(content)
        
        os.chmod(self.fix_script_path, 0o755)
        
        self.console.print(Panel(
            f"[bold green]Remediation Script Generated Successfully![/bold green]\n\n"
            f"Location: [underline]{self.fix_script_path}[/underline]\n"
            f"Command:  sudo {self.fix_script_path} {self.report_path}",
            title="Success", border_style="green"
        ))

# === TUI FUNCTIONS ===

def show_banner():
    console = Console()
    console.clear()
    
    # ASCII Art Title
    font = pyfiglet.figlet_format(TOOL_NAME, font="slant")
    
    # Styled Panel
    panel = Panel(
        Text(font, justify="left", style="bold cyan") + 
        Text(f"\nv{VERSION} - AI Powered Security\n", justify="right", style="italic white"),
        border_style="cyan",
        subtitle="[bold red]System Secured[/bold red]"
    )
    console.print(panel)

def interactive_menu():
    style = questionary.Style([
        ('qmark', 'fg:#673ab7 bold'),
        ('question', 'bold'),
        ('answer', 'fg:#f44336 bold'),
        ('pointer', 'fg:#673ab7 bold'),
        ('highlighted', 'fg:#673ab7 bold'),
    ])

    action = questionary.select(
        "Select Operation Mode:",
        choices=[
            "🚀 Full System Scan",
            "⚡ Light Scan (Critical System Dirs)",
            "🎯 Custom Directory Scan",
            "❌ Exit"
        ],
        style=style
    ).ask()

    dry_run = False
    if action and "Exit" not in action:
        dry_run = questionary.confirm("Enable Dry-Run mode for fix script? (Ask before executing commands)", default=True).ask()

    return action, dry_run

# === MAIN ===

def main():
    # Check if arguments provided via CLI (Automation Mode)
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--light-scan", action="store_true")
        parser.add_argument("--path", type=str)
        args = parser.parse_args()
        
        config = ScanConfig(path=args.path, light_scan=args.light_scan, dry_run=args.dry_run)
        app = VulnixAutomator(config)
        
    else:
        # TUI Mode (Interactive)
        show_banner()
        action, dry_run = interactive_menu()
        
        if not action or "Exit" in action:
            sys.exit(0)
            
        path = None
        light = False
        
        if "Custom" in action:
            path = questionary.path("Enter target directory path:").ask()
            if not path: sys.exit(0)
        elif "Light" in action:
            light = True
            
        config = ScanConfig(path=path, light_scan=light, dry_run=dry_run)
        app = VulnixAutomator(config)

    # Execution Flow
    app.check_dependencies()
    app.run_scan()
    report_data = app.analyze_report()
    fix_script = app.generate_fix(report_data)
    app.save_script(fix_script)

if __name__ == "__main__":
    main()