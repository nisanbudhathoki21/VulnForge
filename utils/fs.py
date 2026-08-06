from pathlib import Path
from typing import Iterable
from rich.console import Console

console = Console()

def ensure_dirs(paths: Iterable[Path]) -> None:
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)

def ensure_project_dirs(settings) -> None:
    ensure_dirs([
        settings.ROOT,
        settings.TEMPLATES_DIR,
        settings.DOCS_DIR,
        settings.OUTPUT_DIR,
        settings.TESTS_DIR,
        settings.SCANNER_DIR,
        settings.DATABASE_DIR,
        settings.AI_DIR,
        settings.REPORTS_DIR,
        settings.UTILS_DIR,
        settings.CONFIG_DIR,
    ])
    console.print(f"[green]Ensured directories under[/green] {settings.ROOT}")
