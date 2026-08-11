from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Settings:
    ROOT: Path = Path(__file__).resolve().parents[1]
    TEMPLATES_DIR: Path = ROOT / "templates"
    DOCS_DIR: Path = ROOT / "docs"
    OUTPUT_DIR: Path = ROOT / "output"
    TESTS_DIR: Path = ROOT / "tests"
    SCANNER_DIR: Path = ROOT / "scanner"
    DATABASE_DIR: Path = ROOT / "database"
    AI_DIR: Path = ROOT / "ai"
    REPORTS_DIR: Path = ROOT / "reports"
    UTILS_DIR: Path = ROOT / "utils"
    CONFIG_DIR: Path = ROOT / "config"
    DB_PATH: Path = ROOT / "vulnforge.db"
