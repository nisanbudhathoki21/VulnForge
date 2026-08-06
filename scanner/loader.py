from pathlib import Path
from typing import List, Any
import yaml
from rich.console import Console
from scanner.templates import VFTemplate, Matcher, Extractor

console = Console()

class TemplateLoadError(Exception):
    pass

def _as_matchers(raw: Any) -> List[Matcher]:
    out: List[Matcher] = []
    if not raw:
        return out
    if not isinstance(raw, list):
        raise TemplateLoadError("matchers must be a list")
    for m in raw:
        if not isinstance(m, dict) or "type" not in m or "value" not in m:
            raise TemplateLoadError("each matcher must have 'type' and 'value'")
        out.append(Matcher(type=str(m["type"]), value=m["value"]))
    return out

def _as_extractors(raw: Any) -> List[Extractor]:
    out: List[Extractor] = []
    if not raw:
        return out
    if not isinstance(raw, list):
        raise TemplateLoadError("extractors must be a list")
    for e in raw:
        if not isinstance(e, dict) or not {"type","name","value"}.issubset(e):
            raise TemplateLoadError("each extractor needs 'type','name','value'")
        out.append(Extractor(type=str(e["type"]), name=str(e["name"]), value=str(e["value"])))
    return out

def load_templates(dir_path: Path) -> List[VFTemplate]:
    if not dir_path.exists():
        raise TemplateLoadError(f"templates dir not found: {dir_path}")
    files = sorted([p for p in dir_path.glob("*.y*ml") if p.is_file()])
    templates: List[VFTemplate] = []
    for fp in files:
        try:
            data = yaml.safe_load(fp.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise TemplateLoadError("top-level YAML must be a mapping")
            t = VFTemplate(
                id=str(data["id"]),
                name=str(data["name"]),
                description=str(data.get("description","")),
                severity=str(data["severity"]).lower(),
                category=str(data.get("category","general")).lower(),
                method=str(data.get("method","GET")).upper(),
                path=str(data.get("path","/")),
                headers=dict(data.get("headers",{}) or {}),
                payload=(None if data.get("payload") in (None, "") else str(data.get("payload"))),
                matchers=_as_matchers(data.get("matchers")),
                extractors=_as_extractors(data.get("extractors")),
                recommendation=str(data.get("recommendation","")),
            )
            templates.append(t)
        except Exception as e:
            console.print(f"[red]Failed to load {fp.name}: {e}[/red]")
    return templates
