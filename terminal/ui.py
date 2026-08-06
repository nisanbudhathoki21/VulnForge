from __future__ import annotations
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich import box
import asyncio

console = Console()

class StartupBanner:
    @staticmethod
    def show():
        banner = """
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"""
        console.print(banner, style="bold cyan")
        console.print("VulnForge v1.0 | Security Research Platform", style="bold white", justify="center")

class ScanDashboard:
    def __init__(self):
        self.start_time = datetime.now()
        self.requests = 0
        self.findings = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        self.phase = "Init"
        self.current_target = "None"
        self.current_template = "None"
        self.technologies = []
        self._stop = False

    def update_requests(self, n=1): self.requests += n
    def add_finding(self, sev):
        s = str(sev).capitalize()
        if s in self.findings: self.findings[s] += 1
    def set_phase(self, p): self.phase = p
    def set_target(self, t): self.current_target = t
    def set_template(self, t): self.current_template = t
    def add_technology(self, t):
        if t not in self.technologies: self.technologies.append(t)
    def set_stop(self): self._stop = True

    def render(self):
        info = Table(show_header=False, box=box.SIMPLE, expand=True)
        info.add_row("Target", self.current_target)
        info.add_row("Phase", f"[bold yellow]{self.phase}[/bold yellow]")
        info.add_row("Template", f"[bold blue]{self.current_template[:35]}[/bold blue]")
        info.add_row("Requests", f"[bold white]{self.requests}[/bold white]")

        find = Table(show_header=True, box=box.SIMPLE, expand=True)
        find.add_column("Severity")
        find.add_column("Count", justify="right")
        for k in ["Critical", "High", "Medium", "Low", "Informational"]:
            color = {"Critical": "red", "High": "bright_red", "Medium": "yellow", "Low": "green"}.get(k, "blue")
            find.add_row(f"[{color}]{k}[/{color}]", str(self.findings[k]))

        layout = Layout()
        layout.split_column(
            Layout(name="top", size=11), 
            Layout(Panel(", ".join(self.technologies), title="Tech Stack", border_style="green"), size=3)
        )
        layout["top"].split_row(
            Layout(Panel(info, title="System Status", border_style="cyan"), ratio=2),
            Layout(Panel(find, title="Findings", border_style="magenta"), ratio=1)
        )
        return Panel(layout, title="[bold white]VulnForge Research Dashboard[/bold white]", border_style="blue", height=16)

    async def live_display(self):
        with Live(self.render(), refresh_per_second=10, transient=True) as live:
            while not self._stop:
                live.update(self.render())
                await asyncio.sleep(0.1)

class LogPrinter:
    @staticmethod
    def info(m): console.print(f"[bold blue][INFO][/bold blue] {m}")
    @staticmethod
    def separator(): console.print("─" * 65, style="dim")

class LogStyleReporter:
    """Streaming, non-transient scan log matching a scanner-style CLI aesthetic."""

    SEVERITY_TAG = {
        "Critical": "[bold white on red][CRITICAL][/bold white on red]",
        "High": "[bold red][HIGH][/bold red]",
        "Medium": "[bold yellow][MEDIUM][/bold yellow]",
        "Low": "[bold green][LOW][/bold green]",
        "Informational": "[dim][INFO][/dim]",
    }

    def __init__(self):
        self.start_time = datetime.now()
        self.requests = 0
        self.errors = 0
        self.findings_by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    def phase(self, name: str):
        console.print(f"\n[bold cyan][{name.upper()}][/bold cyan]")

    def ok(self, msg: str):
        console.print(f"[bold green][OK][/bold green] {msg}")

    def running(self, msg: str):
        console.print(f"[bold yellow][RUNNING][/bold yellow] {msg}")

    def passed(self, msg: str):
        console.print(f"[bold green][PASS][/bold green] {msg}")

    def finding(self, title: str, severity: str, endpoint: str, evidence: str):
        sev = severity if severity in self.findings_by_sev else "Informational"
        self.findings_by_sev[sev] += 1
        tag = self.SEVERITY_TAG.get(sev, sev.upper())
        console.print(f"{tag} {title}")
        console.print(f"  [dim]Endpoint:[/dim]")
        console.print(f"    {endpoint}")
        console.print(f"  [dim]Evidence:[/dim]")
        console.print(f"    {evidence}")

    def register_request(self):
        self.requests += 1

    def register_error(self):
        self.errors += 1

    def summary_bar(self):
        elapsed = datetime.now() - self.start_time
        total_findings = sum(self.findings_by_sev.values())
        top_sev = next((s for s in ["Critical", "High", "Medium", "Low", "Informational"]
                         if self.findings_by_sev[s] > 0), None)
        findings_str = f"{total_findings}"
        if top_sev:
            findings_str += f" {top_sev}"

        console.print("\n" + "─" * 65, style="dim")
        line = Table(show_header=False, box=None, expand=True, padding=(0, 2))
        line.add_column()
        line.add_column()
        line.add_column()
        line.add_column()
        line.add_row(
            f"[bold]Requests[/bold] : {self.requests:,}",
            f"[bold]Errors[/bold] : {self.errors}",
            f"[bold]Findings[/bold] : {findings_str}",
            f"[bold]Time[/bold] : {str(elapsed).split('.')[0]}",
        )
        console.print(line)
