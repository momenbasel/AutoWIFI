import json
import os
import time
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, session_data, fmt="all"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        essid = session_data.get("target_essid", "unknown").replace(" ", "_")
        base_name = f"autowifi_{essid}_{timestamp}"

        files = []
        if fmt in ("all", "json"):
            f = self._generate_json(session_data, base_name)
            if f:
                files.append(f)
        if fmt in ("all", "html"):
            f = self._generate_html(session_data, base_name)
            if f:
                files.append(f)
        if fmt in ("all", "txt"):
            f = self._generate_text(session_data, base_name)
            if f:
                files.append(f)
        return files

    def _generate_json(self, data, base_name):
        filepath = self.output_dir / f"{base_name}.json"
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return str(filepath)

    def _generate_text(self, data, base_name):
        filepath = self.output_dir / f"{base_name}.txt"
        lines = []
        lines.append("=" * 72)
        lines.append("AUTOWIFI - Wireless Security Audit Report")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target BSSID: {data.get('target_bssid', 'N/A')}")
        lines.append(f"Target ESSID: {data.get('target_essid', 'N/A')}")
        lines.append(f"Attack Type: {data.get('attack_type', 'N/A')}")
        lines.append(f"Status: {data.get('status', 'N/A').upper()}")
        lines.append("")

        if data.get("key"):
            lines.append("-" * 72)
            lines.append(f"RECOVERED KEY: {data['key']}")
            lines.append("-" * 72)
            lines.append("")

        if data.get("results"):
            lines.append("ATTACK RESULTS")
            lines.append("-" * 40)
            for i, result in enumerate(data["results"], 1):
                lines.append(f"\n  [{i}] {result.get('attack_type', 'unknown')}")
                lines.append(f"      Success: {result.get('success', False)}")
                if result.get("key"):
                    lines.append(f"      Key: {result['key']}")
                if result.get("pin"):
                    lines.append(f"      PIN: {result['pin']}")
                duration = result.get("duration", 0)
                lines.append(f"      Duration: {duration:.1f}s")
            lines.append("")

        if data.get("files"):
            lines.append("CAPTURED FILES")
            lines.append("-" * 40)
            for f in data["files"]:
                lines.append(f"  {f.get('path', 'N/A')}")
                if f.get("description"):
                    lines.append(f"    {f['description']}")
            lines.append("")

        created = data.get("created", 0)
        completed = data.get("completed", data.get("updated", 0))
        if created and completed:
            total = completed - created
            lines.append(f"Total Duration: {total:.0f}s ({total / 60:.1f}m)")
        lines.append("")
        lines.append("=" * 72)

        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        return str(filepath)

    def _generate_html(self, data, base_name):
        filepath = self.output_dir / f"{base_name}.html"

        status = data.get("status", "unknown")
        status_color = "#22c55e" if status == "completed" and data.get("key") else "#ef4444" if status == "failed" else "#eab308"

        results_html = ""
        for i, result in enumerate(data.get("results", []), 1):
            success = result.get("success", False)
            badge = '<span style="color:#22c55e;font-weight:700">CRACKED</span>' if success else '<span style="color:#ef4444">FAILED</span>'
            results_html += f"""
            <tr>
                <td>{i}</td>
                <td><code>{result.get('attack_type', 'N/A')}</code></td>
                <td>{badge}</td>
                <td><code>{result.get('key', '-')}</code></td>
                <td>{result.get('duration', 0):.1f}s</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoWIFI Report - {data.get('target_essid', 'Unknown')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#e0e0e0;padding:2rem}}
.container{{max-width:900px;margin:0 auto}}
.header{{border:1px solid #22c55e;padding:1.5rem;margin-bottom:2rem;position:relative}}
.header::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#22c55e,transparent)}}
.header h1{{color:#22c55e;font-size:1.5rem;letter-spacing:4px;text-transform:uppercase}}
.header .subtitle{{color:#666;font-size:0.85rem;margin-top:0.5rem}}
.meta{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}}
.meta-card{{border:1px solid #222;padding:1rem;background:#111}}
.meta-card .label{{color:#666;font-size:0.75rem;text-transform:uppercase;letter-spacing:2px}}
.meta-card .value{{color:#22c55e;font-size:1.1rem;margin-top:0.3rem;font-weight:700}}
.key-box{{border:2px solid #22c55e;padding:1.5rem;text-align:center;margin-bottom:2rem;background:#0a1a0a}}
.key-box .label{{color:#666;font-size:0.85rem;text-transform:uppercase;letter-spacing:3px}}
.key-box .key{{color:#22c55e;font-size:2rem;margin-top:0.5rem;font-weight:700;letter-spacing:2px}}
.section{{margin-bottom:2rem}}
.section h2{{color:#22c55e;font-size:1rem;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #222;padding-bottom:0.5rem;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:0.6rem;border-bottom:1px solid #333;color:#666;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px}}
td{{padding:0.6rem;border-bottom:1px solid #1a1a1a;font-size:0.9rem}}
code{{background:#1a1a1a;padding:0.15rem 0.4rem;border-radius:2px;font-size:0.85rem}}
.status{{display:inline-block;padding:0.2rem 0.6rem;border-radius:2px;font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;background:{status_color}20;color:{status_color};border:1px solid {status_color}}}
.footer{{text-align:center;color:#333;font-size:0.75rem;margin-top:3rem;padding-top:1rem;border-top:1px solid #111}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>AutoWIFI</h1>
<div class="subtitle">Wireless Security Audit Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div>
<div class="meta">
<div class="meta-card">
<div class="label">Target BSSID</div>
<div class="value">{data.get('target_bssid', 'N/A')}</div>
</div>
<div class="meta-card">
<div class="label">Target ESSID</div>
<div class="value">{data.get('target_essid', 'N/A')}</div>
</div>
<div class="meta-card">
<div class="label">Attack Vector</div>
<div class="value">{data.get('attack_type', 'N/A')}</div>
</div>
<div class="meta-card">
<div class="label">Status</div>
<div class="value"><span class="status">{status}</span></div>
</div>
</div>
{"<div class='key-box'><div class='label'>Recovered Key</div><div class='key'>" + data.get('key', '') + "</div></div>" if data.get('key') else ""}
<div class="section">
<h2>Attack Results</h2>
<table>
<thead><tr><th>#</th><th>Attack</th><th>Result</th><th>Key</th><th>Duration</th></tr></thead>
<tbody>{results_html if results_html else "<tr><td colspan='5' style='color:#666;text-align:center'>No results recorded</td></tr>"}</tbody>
</table>
</div>
<div class="footer">AutoWIFI v2.0.0</div>
</div>
</body>
</html>"""

        with open(filepath, "w") as f:
            f.write(html)
        return str(filepath)
