#!/usr/bin/env python3
"""
core/report.py – God‑Level Report Generator
Generates HTML, PDF, and Markdown reports with full metadata.
"""

import os
import json
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import jinja2
except ImportError:
    jinja2 = None

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

try:
    import requests
except ImportError:
    requests = None


# ------------------------------------------------------------------
# AI Clients
# ------------------------------------------------------------------
class BaseAIClient:
    def generate(self, prompt: str) -> str:
        raise NotImplementedError


class OllamaClient(BaseAIClient):
    """Free, local AI via Ollama."""
    def __init__(self, model="qwen3:8b", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def generate(self, prompt: str) -> str:
        url = f"{self.base_url}/api/generate"
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        try:
            resp = requests.post(url, json=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return data.get('response', '').strip()
        except Exception as e:
            return f"AI error: {e}"


class ClaudeClient(BaseAIClient):
    """Anthropic Claude API."""
    def __init__(self, api_key: str, model="claude-3-haiku-20240307"):
        self.api_key = api_key
        self.model = model

    def generate(self, prompt: str) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        data = {
            "model": self.model,
            "max_tokens": 150,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=30)
            resp.raise_for_status()
            return resp.json().get('content', [{}])[0].get('text', '').strip()
        except Exception as e:
            return f"AI error: {e}"


class HackerAIClient(BaseAIClient):
    """OpenAI‑compatible API (HackerAI, DeepSeek, etc.)"""
    def __init__(self, api_key: str, base_url: str, model: str = "gpt-3.5-turbo"):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.model = model

    def generate(self, prompt: str) -> str:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 150,
            "temperature": 0.3
        }
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=30)
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']['content'].strip()
        except Exception as e:
            return f"AI error: {e}"


# ------------------------------------------------------------------
# Report Generator
# ------------------------------------------------------------------
class ReportGenerator:
    def __init__(
        self,
        scan_data: Dict,
        output_dir: str = "output",
        ai_client=None,
        timezone_name: Optional[str] = None,
        city: Optional[str] = None,
        country: Optional[str] = None,
    ):
        self.scan_data = scan_data
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.ai_client = ai_client

        self.target = scan_data.get('target', scan_data.get('url', 'Unknown'))
        self.scan_id = scan_data.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.findings = scan_data.get('findings', [])
        self.fingerprint = scan_data.get('fingerprint', {})
        self.start_time = scan_data.get('start_time')
        self.end_time = scan_data.get('end_time', datetime.now().isoformat())

        self._parse_times()
        self.timezone_name = timezone_name or self._detect_timezone()
        self.city = city or self._detect_city()
        self.country = country or self._detect_country()
        self.target_ip = self._resolve_target_ip()
        self.metadata = self._build_metadata()

    # ------------------------------------------------------------------
    # Time & Location Detection
    # ------------------------------------------------------------------
    def _parse_times(self):
        try:
            self.start_dt = datetime.fromisoformat(self.start_time) if self.start_time else None
        except:
            self.start_dt = None
        try:
            self.end_dt = datetime.fromisoformat(self.end_time) if self.end_time else None
        except:
            self.end_dt = None
        if self.start_dt and self.end_dt:
            self.duration_seconds = (self.end_dt - self.start_dt).total_seconds()
        else:
            self.duration_seconds = 0
        if self.duration_seconds < 60:
            self.duration_str = f"{self.duration_seconds:.1f} seconds"
        elif self.duration_seconds < 3600:
            self.duration_str = f"{self.duration_seconds/60:.1f} minutes"
        else:
            self.duration_str = f"{self.duration_seconds/3600:.1f} hours"

    def _detect_timezone(self) -> str:
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo("local")
            return str(tz)
        except:
            try:
                import tzlocal
                return str(tzlocal.get_localzone())
            except:
                return "UTC"

    def _get_public_ip(self) -> Optional[str]:
        if requests is None:
            return None
        try:
            resp = requests.get("https://api.ipify.org?format=json", timeout=5)
            data = resp.json()
            return data.get('ip')
        except:
            return None

    def _geo_ip(self, ip: str) -> Dict:
        if requests is None:
            return {}
        try:
            resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            data = resp.json()
            return {
                'city': data.get('city'),
                'country_name': data.get('country_name'),
                'country_code': data.get('country_code'),
            }
        except:
            return {}

    def _detect_city(self) -> str:
        ip = self._get_public_ip()
        if ip:
            geo = self._geo_ip(ip)
            return geo.get('city', 'Unknown')
        return 'Unknown'

    def _detect_country(self) -> str:
        ip = self._get_public_ip()
        if ip:
            geo = self._geo_ip(ip)
            return geo.get('country_name', 'Unknown')
        return 'Unknown'

    def _resolve_target_ip(self) -> str:
        try:
            hostname = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            return socket.gethostbyname(hostname)
        except:
            return 'N/A'

    def _build_metadata(self) -> Dict:
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'target_ip': self.target_ip,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration_str,
            'duration_seconds': self.duration_seconds,
            'timezone': self.timezone_name,
            'location': f"{self.city}, {self.country}",
            'city': self.city,
            'country': self.country,
            'server': self.fingerprint.get('server', 'Unknown'),
            'waf': ', '.join(self.fingerprint.get('waf', [])),
            'cdn': ', '.join(self.fingerprint.get('cdn', [])),
            'tech_stack': ', '.join(self.fingerprint.get('tech_stack', [])),
            'os': self.fingerprint.get('os', 'Unknown'),
            'total_findings': len(self.findings),
        }

    # ------------------------------------------------------------------
    # AI Analysis
    # ------------------------------------------------------------------
    def _ai_analysis(self) -> Optional[str]:
        if not self.ai_client:
            return None
        if not self.findings:
            return "✅ No vulnerabilities found in this scan."

        prompt = (
            "You are a senior security consultant. Given the following findings from a web vulnerability scan, "
            "provide a concise executive summary (3-4 sentences) that highlights:\n"
            "- The most critical issues\n"
            "- Their potential business impact\n"
            "- Recommended immediate actions\n\n"
            f"Target: {self.target}\n"
            f"Findings ({len(self.findings)}):\n"
        )
        for f in self.findings[:10]:
            prompt += f"- {f.get('name', 'Unnamed')} [{f.get('severity', 'info')}]: {f.get('impact', '')}\n"
        try:
            return self.ai_client.generate(prompt)
        except Exception as e:
            return f"AI analysis error: {e}"

    # ------------------------------------------------------------------
    # Severity Counts
    # ------------------------------------------------------------------
    def _severity_counts(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in self.findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    # ------------------------------------------------------------------
    # HTML Generation
    # ------------------------------------------------------------------
    def _generate_html(self) -> str:
        if not jinja2:
            raise ImportError("jinja2 required. Install with: pip install jinja2")

        severity_counts = self._severity_counts()
        total = len(self.findings)
        ai_summary = self._ai_analysis()

        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnForge Scan Report – {{ metadata.target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0b0e14; color: #e0e0e0; padding: 30px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { border-bottom: 2px solid #2a3a4a; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; }
        .header h1 { font-size: 2.5rem; color: #58a6ff; }
        .header .meta { color: #8b949e; font-size: 0.9rem; margin-top: 8px; }
        .header .meta span { margin-right: 15px; }
        .metadata-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; background: #1c2333; padding: 20px; border-radius: 10px; margin-bottom: 30px; }
        .metadata-item { display: flex; flex-direction: column; }
        .metadata-item .label { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .metadata-item .value { font-weight: 600; font-size: 1rem; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #1c2333; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #58a6ff; }
        .summary-card .number { font-size: 2rem; font-weight: bold; }
        .summary-card .label { color: #8b949e; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
        .sev-critical .number { color: #ff4d4d; }
        .sev-high .number { color: #ff9f4d; }
        .sev-medium .number { color: #ffd64d; }
        .sev-low .number { color: #4dff4d; }
        .ai-summary { background: #1c2333; padding: 20px; border-radius: 10px; margin-bottom: 30px; border-left: 4px solid #58a6ff; }
        .ai-summary h2 { color: #58a6ff; margin-bottom: 10px; font-size: 1.2rem; }
        .findings-list { margin-top: 30px; }
        .finding-item { background: #141a24; padding: 20px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #58a6ff; }
        .finding-item.sev-critical { border-left-color: #ff4d4d; }
        .finding-item.sev-high { border-left-color: #ff9f4d; }
        .finding-item.sev-medium { border-left-color: #ffd64d; }
        .finding-item.sev-low { border-left-color: #4dff4d; }
        .finding-title { font-size: 1.2rem; font-weight: bold; }
        .finding-severity { display: inline-block; padding: 2px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; background: #2a3a4a; color: #fff; margin-left: 10px; }
        .finding-severity.critical { background: #ff4d4d; }
        .finding-severity.high { background: #ff9f4d; }
        .finding-severity.medium { background: #ffd64d; color: #000; }
        .finding-severity.low { background: #4dff4d; color: #000; }
        .finding-details { margin-top: 10px; color: #b0b8c0; font-size: 0.95rem; }
        .finding-evidence { background: #0b0e14; padding: 12px; border-radius: 6px; margin-top: 8px; overflow-x: auto; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #2a3a4a; text-align: center; color: #8b949e; font-size: 0.9rem; }
        @media print {
            body { background: #fff; color: #000; }
            .summary-card { background: #f0f0f0; border-left-color: #333; }
            .finding-item { background: #f9f9f9; border-left-color: #333; }
            .finding-evidence { background: #eee; }
            .ai-summary { background: #f0f0f0; }
            .header h1 { color: #0366d6; }
            .metadata-grid { background: #f0f0f0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ VulnForge Scan Report</h1>
                <div class="meta">
                    <span>🌐 <strong>Target:</strong> {{ metadata.target }}</span>
                    <span>🆔 <strong>Scan ID:</strong> {{ metadata.scan_id }}</span>
                    <span>📅 <strong>Date:</strong> {{ metadata.end_time }}</span>
                </div>
            </div>
            <div style="text-align: right; font-size: 0.9rem; color: #8b949e;">
                <div>⏱️ <strong>Duration:</strong> {{ metadata.duration }}</div>
                <div>🕐 <strong>Timezone:</strong> {{ metadata.timezone }}</div>
                <div>📍 <strong>Location:</strong> {{ metadata.location }}</div>
            </div>
        </div>

        <div class="metadata-grid">
            <div class="metadata-item">
                <span class="label">Target IP</span>
                <span class="value">{{ metadata.target_ip }}</span>
            </div>
            <div class="metadata-item">
                <span class="label">Server</span>
                <span class="value">{{ metadata.server }}</span>
            </div>
            <div class="metadata-item">
                <span class="label">WAF</span>
                <span class="value">{{ metadata.waf or 'None detected' }}</span>
            </div>
            <div class="metadata-item">
                <span class="label">CDN</span>
                <span class="value">{{ metadata.cdn or 'None detected' }}</span>
            </div>
            <div class="metadata-item">
                <span class="label">Tech Stack</span>
                <span class="value">{{ metadata.tech_stack or 'Unknown' }}</span>
            </div>
            <div class="metadata-item">
                <span class="label">OS</span>
                <span class="value">{{ metadata.os }}</span>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="number">{{ metadata.total_findings }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card sev-critical">
                <div class="number">{{ severity_counts.critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card sev-high">
                <div class="number">{{ severity_counts.high }}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card sev-medium">
                <div class="number">{{ severity_counts.medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card sev-low">
                <div class="number">{{ severity_counts.low }}</div>
                <div class="label">Low</div>
            </div>
        </div>

        {% if ai_summary %}
        <div class="ai-summary">
            <h2>🧠 AI Executive Summary</h2>
            <p>{{ ai_summary }}</p>
        </div>
        {% endif %}

        <div class="findings-list">
            <h2>📋 Detailed Findings</h2>
            {% for finding in findings %}
            <div class="finding-item sev-{{ finding.severity.lower() }}">
                <div class="finding-title">
                    {{ finding.name }}
                    <span class="finding-severity {{ finding.severity.lower() }}">{{ finding.severity }}</span>
                </div>
                <div class="finding-details">
                    <strong>Impact:</strong> {{ finding.impact or 'N/A' }}<br>
                    <strong>Chain:</strong> {{ finding.chain or 'N/A' }}
                </div>
                <div class="finding-evidence">
                    <strong>Request:</strong> {{ finding.evidence.method }} {{ finding.evidence.url }}<br>
                    <strong>Status:</strong> {{ finding.evidence.status }}<br>
                    <strong>Response snippet:</strong> {{ finding.evidence.response_body[:300] if finding.evidence.response_body else 'N/A' }}
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            Generated by VulnForge v1.0 &bull; Report ID: {{ metadata.scan_id }} &bull; 🕐 {{ metadata.timezone }} &bull; 📍 {{ metadata.location }}
        </div>
    </div>
</body>
</html>
        """

        template = jinja2.Template(template_str)
        html = template.render(
            metadata=self.metadata,
            severity_counts=severity_counts,
            findings=self.findings,
            ai_summary=ai_summary,
        )
        return html

    # ------------------------------------------------------------------
    # Markdown Generation
    # ------------------------------------------------------------------
    def generate_markdown(self) -> str:
        lines = []
        lines.append(f"# VulnForge Scan Report\n")
        lines.append(f"**Target:** {self.metadata['target']}\n")
        lines.append(f"**Scan ID:** {self.metadata['scan_id']}\n")
        lines.append(f"**Date:** {self.metadata['end_time']}\n")
        lines.append(f"**Timezone:** {self.metadata['timezone']}\n")
        lines.append(f"**Location:** {self.metadata['location']}\n")
        lines.append(f"**Target IP:** {self.metadata['target_ip']}\n")
        lines.append(f"**Server:** {self.metadata['server']}\n")
        lines.append(f"**WAF:** {self.metadata['waf'] or 'None'}\n")
        lines.append(f"**CDN:** {self.metadata['cdn'] or 'None'}\n")
        lines.append(f"**Tech Stack:** {self.metadata['tech_stack'] or 'Unknown'}\n")
        lines.append(f"**OS:** {self.metadata['os']}\n")
        lines.append(f"**Duration:** {self.metadata['duration']}\n")
        lines.append(f"**Total Findings:** {self.metadata['total_findings']}\n\n")
        if not self.findings:
            lines.append("✅ No vulnerabilities found.\n")
            return ''.join(lines)
        for f in self.findings:
            lines.append(f"## {f.get('name', 'Unnamed')}")
            lines.append(f"- **Severity:** {f.get('severity', 'info')}")
            lines.append(f"- **Impact:** {f.get('impact', 'N/A')}")
            lines.append(f"- **Chain:** {f.get('chain', 'N/A')}")
            ev = f.get('evidence', {})
            lines.append(f"- **Endpoint:** `{ev.get('method', 'GET')} {ev.get('url', '')}`")
            lines.append(f"- **Status:** {ev.get('status', 'N/A')}")
            if ev.get('request_body'):
                lines.append(f"- **Request Body:** ```\n{ev['request_body'][:500]}\n```")
            if ev.get('response_body'):
                lines.append(f"- **Response Snippet:** ```\n{ev['response_body'][:500]}\n```")
            lines.append("")
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # PDF Generation
    # ------------------------------------------------------------------
    def generate_pdf(self) -> bytes:
        if HTML is None:
            raise ImportError("weasyprint required. Install with: pip install weasyprint")
        html_content = self._generate_html()
        pdf = HTML(string=html_content).write_pdf()
        return pdf

    # ------------------------------------------------------------------
    # Save Report
    # ------------------------------------------------------------------
    def save_report(self, format: str = 'html') -> Path:
        if format == 'html':
            content = self._generate_html()
            ext = '.html'
            mode = 'w'
        elif format == 'pdf':
            content = self.generate_pdf()
            ext = '.pdf'
            mode = 'wb'
        elif format == 'md':
            content = self.generate_markdown()
            ext = '.md'
            mode = 'w'
        else:
            raise ValueError(f"Unsupported format: {format}")

        filename = f"{self.scan_id}_report{ext}"
        filepath = self.output_dir / filename
        with open(filepath, mode) as f:
            f.write(content)
        return filepath
