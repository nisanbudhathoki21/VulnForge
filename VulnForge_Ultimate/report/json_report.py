import json

def to_json(workspace_id, findings):
    """Package level function for JSON export."""
    data = []
    for f in findings:
        data.append({
            "title": f.title,
            "severity": f.severity,
            "url": f.context.get("url"),
            "evidence": f.context.get("evidence")
        })
    return json.dumps({"workspace": workspace_id, "findings": data}, indent=4)

class JsonReporter:
    @staticmethod
    def generate(url, findings):
        """CLI level method for JSON export."""
        report = {
            "target": url,
            "total_findings": len(findings),
            "findings": []
        }
        for f in findings:
            report["findings"].append({
                "title": f.title,
                "severity": f.severity,
                "url": f.context.get("url"),
                "evidence": f.context.get("evidence"),
                "poc": f"curl -is -X GET '{f.context.get('url')}'"
            })
        return json.dumps(report, indent=4)
