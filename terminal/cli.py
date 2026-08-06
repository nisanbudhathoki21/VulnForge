from __future__ import annotations
import argparse, asyncio, logging, sys
from core import setup_logging
from workspace import Workspace, WorkspaceStore
from templates import TemplateLoader
from httpclient import HttpClient
from scanner import Scanner
from correlation import Correlated
from report import to_markdown, to_json

async def run_scan(urls: list, templates_dir: str, workspace_name: str, output_json: bool) -> None:
    log = logging.getLogger("vulnforge")
    
    loader = TemplateLoader(templates_dir)
    templates = loader.load_all()
    log.info(f"Loaded {len(templates)} templates")
    
    if not templates:
        log.error(f"No templates in {templates_dir}")
        return
    
    ws = Workspace.new(workspace_name or f"scan-{len(urls)}-targets")
    log.info(f"Workspace: {ws.id}")
    
    http = HttpClient(timeout=10.0)
    scanner = Scanner(http)
    
    log.info(f"Scanning {len(urls)} target(s)...")
    result = await scanner.scan(ws, urls, templates)
    
    log.info(f"Found {len(result.findings)} findings, {len(result.evidence)} evidence")
    
    if result.findings:
        corr = Correlated(result.findings)
        corr.correlate()
        log.info(f"Correlated {len(corr.edges)} relationships")
    
    report = to_json(ws.id, result.findings) if output_json else to_markdown(ws.name, result.findings)
    print("\n" + "="*80)
    print(report)
    print("="*80)
    
    store = WorkspaceStore()
    store.save(ws)
    log.info(f"Workspace saved: .vulnforge/{ws.id}.json")
    await http.close()

def main() -> None:
    parser = argparse.ArgumentParser(prog="vulnforge", description="VulnForge Security Research Platform")
    parser.add_argument("-u", "--url", dest="urls", action="append", required=True, help="Target URL (repeat for multiple)")
    parser.add_argument("-w", "--workspace", help="Workspace name")
    parser.add_argument("-t", "--templates", default="templates", help="Templates directory")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("--version", action="version", version="VulnForge 0.1.0")
    
    args = parser.parse_args()
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    log = logging.getLogger("vulnforge")
    
    log.info("VulnForge 0.1.0")
    log.info(f"Targets: {', '.join(args.urls)}")
    
    asyncio.run(run_scan(args.urls, args.templates, args.workspace, args.json))

if __name__ == "__main__":
    main()
