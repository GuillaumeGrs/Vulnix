#!/usr/bin/env python3

"""
VULNIX TEST VERSION
"""
"""
Merci de vous intéresser à Vulnix :)
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
VERSION = "2.3.0-STABLE"
DEFAULT_MODEL = "gemini-1.5-flash"
VENV_NAME = "trivy_env"
REQUIRED_PACKAGES = ["google-generativeai", "rich", "pyfiglet", "questionary", "jinja2"]

# === BOOTSTRAP: VIRTUAL ENVIRONMENT HANDLING ===
def bootstrap_venv():
    # --- FIX CRITIQUE POUR PYINSTALLER ---
    # Si on tourne en tant qu'exécutable (frozen), on a déjà tout !
    # On ne crée pas de venv et on n'installe rien.
    if getattr(sys, 'frozen', False):
        return

    # --- LOGIQUE NORMALE (SCRIPT PYTHON) ---
    # RECURSION GUARD: Prevent infinite loops if venv detection fails
    if os.environ.get("VULNIX_BOOTSTRAPPED") == "1":
        return

    venv_dir = Path.home() / VENV_NAME
    
    # Determine paths
    if platform.system() == "Windows":
        venv_python = venv_dir / "Scripts" / "python.exe"
        venv_pip = venv_dir / "Scripts" / "pip.exe"
    else:
        venv_python = venv_dir / "bin" / "python"
        venv_pip = venv_dir / "bin" / "pip"

    # Check if we are running inside the correct venv
    # We use sys.prefix match OR explicit environment variable check
    is_in_venv = sys.prefix == str(venv_dir)
    
    if not is_in_venv:
        if not venv_dir.exists():
            print(f"[*] Initializing virtual environment at {venv_dir}...")
            try:
                subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            except subprocess.CalledProcessError:
                print("[!] Critical: Failed to create venv. Install 'python3-venv'.")
                sys.exit(1)

        # Check and install dependencies
        try:
            subprocess.run([str(venv_python), "-c", "import rich; import questionary; import google.generativeai; import jinja2"], 
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print("[*] Installing dependencies (This may take a minute)...")
            subprocess.run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], check=True)
            subprocess.run([str(venv_pip), "install"] + REQUIRED_PACKAGES, check=True)

        print("[*] Loading VULNIX Engine...")
        try:
            # Re-launch script inside the venv
            # We explicitly set Bootstrapped flag to prevent loop
            env = os.environ.copy()
            env["VIRTUAL_ENV"] = str(venv_dir)
            env["PATH"] = str(venv_dir / "bin") + os.pathsep + env["PATH"]
            env["VULNIX_BOOTSTRAPPED"] = "1"
            
            subprocess.run([str(venv_python), __file__] + sys.argv[1:], check=True, env=env)
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
from jinja2 import Template

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
        self.html_report_path = self.output_dir / f"VULNIX_Dashboard_{self.timestamp}.html"
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

    def generate_html_report(self, report_data):
        """Generates a self-contained HTML Executive Dashboard."""
        
        # Calculate stats for the chart
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        vulnerabilities = []
        
        for res in report_data.get("Results", []):
            target = res.get("Target", "Unknown Target")
            for vuln in res.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN").upper()
                if sev in stats: stats[sev] += 1
                else: stats["UNKNOWN"] += 1
                
                vulnerabilities.append({
                    "id": vuln.get("VulnerabilityID", "N/A"),
                    "pkg": vuln.get("PkgName", "N/A"),
                    "severity": sev,
                    "title": vuln.get("Title", "No Description"),
                    "version": vuln.get("InstalledVersion", "N/A"),
                    "fixed_in": vuln.get("FixedVersion", "N/A"),
                    "target": target
                })

        HTML_TEMPLATE = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VULNIX Executive Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                :root { --bg: #0f172a; --card-bg: #1e293b; --text: #f8fafc; --accent: #3b82f6; --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e; }
                body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 2px solid var(--accent); padding-bottom: 10px; }
                .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin-bottom: 30px; }
                .card { background: var(--card-bg); padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5); }
                .stat-card { text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 8px; margin-bottom: 10px; }
                .stat-num { font-size: 2em; font-weight: bold; }
                .vuln-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .vuln-table th, .vuln-table td { text-align: left; padding: 12px; border-bottom: 1px solid #334155; }
                .vuln-table th { background: #334155; color: white; cursor: pointer; }
                .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: #000; }
                .bg-CRITICAL { background: var(--critical); } .bg-HIGH { background: var(--high); }
                .bg-MEDIUM { background: var(--medium); } .bg-LOW { background: var(--low); }
                input#search { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: white; margin-bottom: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡 VULNIX Executive Report</h1>
                    <p>{{ timestamp }}</p>
                </div>

                <div class="grid">
                    <div class="card">
                        <h3>Vulnerability Overview</h3>
                        <canvas id="vulnChart"></canvas>
                    </div>
                    <div class="card">
                        <h3>Summary</h3>
                        <div class="stat-card">
                            <div class="stat-num" style="color: var(--critical)">{{ stats.CRITICAL }}</div>
                            <div>Critical Issues</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-num" style="color: var(--high)">{{ stats.HIGH }}</div>
                            <div>High Priority</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-num">{{ stats.MEDIUM + stats.LOW }}</div>
                            <div>Other Risks</div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h3>Detailed Findings</h3>
                    <input type="text" id="search" placeholder="Search vulnerabilities..." onkeyup="searchTable()">
                    <table class="vuln-table" id="vulnTable">
                        <thead>
                            <tr onclick="sortTable(0)"><th>ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Title</th></tr>
                        </thead>
                        <tbody>
                            {% for v in vulnerabilities %}
                            <tr>
                                <td>{{ v.id }}</td>
                                <td><span class="badge bg-{{ v.severity }}">{{ v.severity }}</span></td>
                                <td>{{ v.pkg }}</td>
                                <td>{{ v.version }}</td>
                                <td>{{ v.title }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                // Pie Chart
                const ctx = document.getElementById('vulnChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{
                            data: [{{ stats.CRITICAL }}, {{ stats.HIGH }}, {{ stats.MEDIUM }}, {{ stats.LOW }}],
                            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                            borderWidth: 0
                        }]
                    },
                    options: { plugins: { legend: { position: 'bottom', labels: { color: 'white' } } } }
                });

                // Search Function
                function searchTable() {
                    const input = document.getElementById("search");
                    const filter = input.value.toUpperCase();
                    const table = document.getElementById("vulnTable");
                    const tr = table.getElementsByTagName("tr");
                    for (let i = 1; i < tr.length; i++) {
                        tr[i].style.display = tr[i].textContent.toUpperCase().includes(filter) ? "" : "none";
                    }
                }
            </script>
        </body>
        </html>
        """
        
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            timestamp=self.timestamp,
            stats=stats,
            vulnerabilities=vulnerabilities
        )
        
        with open(self.html_report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        self.console.print(Panel(f"[bold green]HTML Dashboard Generated![/bold green]\n[underline]{self.html_report_path}[/underline]", border_style="cyan"))

    def generate_fix(self, report_data):
        if not self.api_key:
            self.console.print("[bold yellow]⚠ No Gemini API Key found. Skipping auto-fix generation.[/bold yellow]")
            return None

        # --- INTELLIGENCE V3 : DÉDOUBLONNAGE + RECHERCHE DE FICHIER ---
        system_instruction = """
        You are an expert Senior Linux System Administrator.
        Your task is to generate a ROBUST Bash script to remediate vulnerabilities found in a Trivy JSON scan.

        ### INPUT CONTEXT
        The script will receive the path to the Trivy JSON report as the first argument ($1).

        ### REQUIREMENTS:
        1. **SCRIPT HEADER**:
           - Start with `#!/bin/bash`.
           - Use `set -eo pipefail` (NO `set -u`).
           - Wrap logic in `main()`.

        2. **PYTHON PARSING (THE BRAIN)**: 
           - Use `python3 - "$1" <<EOF` to pass the filename.
           - **LOGIC CHANGE - DEDUPLICATION**: 
             - You must parse ALL vulnerabilities.
             - Store them in a dictionary: `updates[package_name] = (max_fixed_version, target_file)`.
             - Only keep the HIGHEST version required for each package to avoid multiple useless updates.
             - Print the unique list: `pkg|ver|file`.
           - **Syntax**: Use `f"{chr(44).join(list)}"` for output.

        3. **REMEDIATION LOOP**:
           - Loop through the **unique** list.
           - `python3 -m pip install --upgrade --break-system-packages --ignore-installed "${pkg}==${ver}"`.
           - Track success (`UPDATED_PACKAGES`) and failure (`MANUAL_ACTION_REQUIRED`).

        4. **SMART FILE FINDER (The Limier)**:
           - After update, verify persistence in `$target_file`.
           - **CRITICAL LOGIC**: 
             - If `[ ! -f "$target_file" ]`, try to find it!
             - Run: `found_file=$(find . -type f -name "$(basename "$target_file")" -print -quit)`
             - If found, use `$found_file` as the new target.
             - If still not found, try searching inside `/home/$USER/`.
           - Once file is located, `grep` for the old version.
           - If old version exists in file -> Add to `MANUAL_ACTION_REQUIRED`.

        5. **FINAL REPORT**:
           - Print "REMEDIATION SUMMARY".
           - List runtime successes.
           - List persistence mismatches explicitly: "⚠️  File [path] still contains [pkg] [old_ver]".

        6. **OUTPUT**:
           - Return ONLY the raw Bash script.
        """
        
        full_prompt = f"{system_instruction}\n\nHere is the Trivy Scan Report content to analyze (but do not embed it):\n{json.dumps(report_data)}"
        
        self.console.print(f"\n[bold purple]AI Analysis[/bold purple]: Using model [cyan]{self.model_name}[/cyan]")
        
        if not self.config.dry_run and not questionary.confirm("Do you want Gemini to generate a fix script?").ask():
            self.console.print("[yellow]Skipping AI generation.[/yellow]")
            return None

        with self.console.status("[bold purple]Gemini is thinking (Optimizing & Deduplicating)...[/bold purple]", spinner="earth"):
            try:
                response = self.model.generate_content(full_prompt)
                script_content = response.text.strip()
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
            self.console.print("[italic]Adding Dry-Run safeguards (Paranoid Mode)...[/italic]")
            lines = content.splitlines()
            new_lines = []
            
            # 1. Liste des commandes à surveiller
            DANGEROUS_COMMANDS = [
                "apt-get", "apt", "yum", "dnf", "apk", "pacman", "zypper",
                "rm ", "mv ", "cp ", "sed ", "chmod ", "chown ", "dd ",
                "systemctl", "service", "pip ", "npm ", "yarn ", "poetry ",
                "wget", "curl", "dpkg", "rpm"
            ]

            # 2. Liste des caractères qui signalent une complexité
            # Si une ligne contient l'un de ces caractères, on ne la touche pas pour éviter les erreurs de syntaxe.
            # ; = fin de commande
            # | = pipe
            # & = logique
            # ( ) = sous-shell
            # \ = multiligne
            # { } = bloc
            COMPLEX_MARKERS = [";", "|", "&", "(", ")", "{", "}", "\\", "`", "if ", "then", "else", "elif", "fi", "do", "done", "case", "esac"]

            for line in lines:
                l = line.strip()
                should_wrap = False
                
                # Vérification 1 : Est-ce une ligne vide ou un commentaire ?
                if not l or l.startswith("#"):
                    should_wrap = False
                
                # Vérification 2 : Est-ce une ligne indentée ? (On ne touche pas au code dans les fonctions/boucles)
                elif line.startswith(" ") or line.startswith("\t"):
                    should_wrap = False
                    
                # Vérification 3 : La ligne est-elle "Pure" ? (Pas de caractères complexes)
                elif any(marker in l for marker in COMPLEX_MARKERS):
                    should_wrap = False
                    
                else:
                    # Vérification 4 : Est-ce une commande dangereuse ?
                    for cmd in DANGEROUS_COMMANDS:
                        if l.startswith(cmd):
                            should_wrap = True
                            break
                    
                    # Vérification 5 : Redirection destructrice simple (ex: echo "x" > file)
                    if " > " in l and not " >> " in l:
                        should_wrap = True

                if should_wrap:
                    # On échappe les guillemets pour le read -p
                    safe_l = l.replace('"', '\\"').replace("'", "")
                    new_lines.append(f'read -p "[DRY-RUN] Execute: {safe_l}? [y/N] " confirm')
                    new_lines.append('if [[ $confirm == [yY] || $confirm == [yY]es ]]; then')
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
    app.generate_html_report(report_data)
    fix_script = app.generate_fix(report_data)
    app.save_script(fix_script)

if __name__ == "__main__":
    main()