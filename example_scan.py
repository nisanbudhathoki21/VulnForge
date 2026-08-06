#!/usr/bin/env python3
"""Example VulnForge scan."""
from __future__ import annotations
import asyncio
from core import setup_logging
from workspace import Workspace, WorkspaceStore
from templates import TemplateLoader
from httpclient import HttpClient
from scanner import Scanner
from report import to_markdown
import logging

async def main() -> None:
    setup_logging(logging.INFO)
    log = logging.getLogger("vulnforge.example")
    
    # Load templates
    loader = TemplateLoader("templates")
    templates = loader.load_all()
    log.info(f"Loaded {len(templates)} templates")
    
    # Create workspace
    ws = Workspace.new("example-scan")
    log.info(f"Created workspace: {ws.id}")
    
    # Setup scanner
    http = HttpClient(timeout=10.0)
    scanner = Scanner(http)
    
    # Run scan
    targets = ["https://example.com"]
    log.info(f"Scanning {targets}")
    result = await scanner.scan(ws, targets, templates)
    
    log.info(f"Found {len(result.findings)} findings")
    log.info(f"Collected {len(result.evidence)} evidence items")
    
    # Generate report
    report = to_markdown(ws.name, result.findings)
    print(report)
    
    # Save workspace
    store = WorkspaceStore()
    store.save(ws)
    log.info(f"Workspace saved to .vulnforge/{ws.id}.json")
    
    await http.close()

if __name__ == "__main__":
    asyncio.run(main())
