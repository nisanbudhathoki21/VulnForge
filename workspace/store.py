from __future__ import annotations
from typing import Optional
import json, os
from .models import Workspace, Target, Evidence
class WorkspaceStore:
    def __init__(self, base_path: str=".vulnforge") -> None:
        self.base = base_path
        os.makedirs(self.base, exist_ok=True)
    def path(self, ws_id: str) -> str:
        return os.path.join(self.base, f"{ws_id}.json")
    def save(self, ws: Workspace) -> None:
        with open(self.path(ws.id), "w", encoding="utf-8") as f:
            json.dump(ws.to_json(), f, indent=2)
    def load(self, ws_id: str) -> Optional[Workspace]:
        fn = self.path(ws_id)
        if not os.path.exists(fn):
            return None
        with open(fn, "r", encoding="utf-8") as f:
            data = json.load(f)
        ws = Workspace(id=data["id"], name=data["name"])
        ws.targets = [Target(**t) for t in data.get("targets", [])]
        ws.notes = data.get("notes", {})
        ws.history = data.get("history", [])
        ws.templates_used = data.get("templates_used", [])
        ws.reports = data.get("reports", [])
        ws.evidence = {k: Evidence(**v) for k,v in data.get("evidence", {}).items()}
        ws.screenshots = data.get("screenshots", {})
        ws.bookmarks = data.get("bookmarks", [])
        ws.tags = data.get("tags", [])
        ws.timeline = data.get("timeline", [])
        ws.ai_context = data.get("ai_context", {})
        return ws
