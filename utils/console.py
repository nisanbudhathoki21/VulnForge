from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

def print_banner() -> None:
    title = Text("VulnForge", style="bold cyan")
    subtitle = Text("AI-assisted Vulnerability Scanner (MVP)", style="dim")
    console.print(Panel.fit(
        Text.assemble(title, "\n", subtitle),
        border_style="cyan",
        title="Phase 1",
        subtitle="Project Setup"
    ))
