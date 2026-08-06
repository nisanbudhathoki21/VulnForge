def run_report(scan_id: str):
    """Generate and save a Markdown report for the given scan_id."""
    init_db()
    report_text = generate_markdown_report(scan_id)
    filename = f"vulnforge_report_{scan_id[:8]}.md"
    with open(filename, "w") as f:
        f.write(report_text)
    print(f"[INFO] Report written to {filename}")
