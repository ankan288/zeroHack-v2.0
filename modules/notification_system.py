"""
ZeroHack v2.0 - Notification & Reporting System
Rich-based console output, finding classification, JSON/HTML report generation.
"""

import json
import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich import box
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# ─────────────────────────────────────────────
# Severity levels
# ─────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "blue",
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "ℹ️ ",
}

SEVERITY_SCORE = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      2,
    "INFO":     0,
}

# ─────────────────────────────────────────────
# Finding data structure
# ─────────────────────────────────────────────
@dataclass
class Finding:
    module:      str
    title:       str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    target:      str
    evidence:    str = ""
    remediation: str = ""
    cve:         Optional[str] = None
    owasp:       Optional[str] = None
    timestamp:   str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity.upper(), 0)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────
# Console helpers
# ─────────────────────────────────────────────
def print_banner():
    if not RICH_AVAILABLE:
        print("=" * 60)
        print("  ZeroHack v2.0 - Advanced Vulnerability Scanner")
        print("=" * 60)
        return

    banner = r"""
 ______              _   _            _    
|___  /             | | | |          | |   
   / /  ___ _ __ ___| |_| | __ _  ___| | __
  / /  / _ \ '__/ _ \ __| |/ _` |/ __| |/ /
 / /__| (_) | | | (_) | |_| | (_| | (__|   < 
/_____|\___/|_|  \___/ \__|_|\__,_|\___|_|\_\
                                    v2.0
"""
    console.print(Panel(
        Text(banner, style="bold cyan", justify="center"),
        subtitle="[bold white]Advanced Vulnerability Assessment Tool[/bold white]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print(
        "[dim]⚠  For authorized testing in controlled environments only.[/dim]\n",
        justify="center"
    )


def print_module_start(module_name: str, target: str):
    if RICH_AVAILABLE:
        console.print(
            f"\n[bold cyan]┌─[/bold cyan] [bold white]Module:[/bold white] [cyan]{module_name}[/cyan]"
            f"  [dim]→[/dim]  [white]{target}[/white]"
        )
    else:
        print(f"\n[*] Module: {module_name} → {target}")


def print_finding(finding: Finding):
    color = SEVERITY_COLORS.get(finding.severity.upper(), "white")
    icon  = SEVERITY_ICONS.get(finding.severity.upper(), "?")
    if RICH_AVAILABLE:
        console.print(
            f"  {icon} [{color}][{finding.severity}][/{color}] "
            f"[bold]{finding.title}[/bold]  [dim]({finding.target})[/dim]"
        )
        if finding.evidence:
            console.print(f"     [dim]Evidence:[/dim] {finding.evidence[:120]}")
    else:
        print(f"  [{finding.severity}] {finding.title} ({finding.target})")


def print_info(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [dim]→[/dim] {msg}")
    else:
        print(f"  [i] {msg}")


def print_success(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [green]✓[/green] {msg}")
    else:
        print(f"  [+] {msg}")


def print_error(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [red]✗[/red] {msg}")
    else:
        print(f"  [-] {msg}")


def print_warning(msg: str):
    if RICH_AVAILABLE:
        console.print(f"  [yellow]![/yellow] {msg}")
    else:
        print(f"  [!] {msg}")


def get_progress():
    if RICH_AVAILABLE:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        )
    return None


# ─────────────────────────────────────────────
# Summary table
# ─────────────────────────────────────────────
def print_summary_table(findings: List[Finding], elapsed: float):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1

    total_score = sum(f.score() for f in findings)

    if RICH_AVAILABLE:
        table = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
        table.add_column("Severity",  style="bold", justify="center")
        table.add_column("Count",     justify="center")
        table.add_column("Icon",      justify="center")

        for sev, cnt in counts.items():
            color = SEVERITY_COLORS[sev]
            icon  = SEVERITY_ICONS[sev]
            table.add_row(
                f"[{color}]{sev}[/{color}]",
                str(cnt),
                icon,
            )

        console.print("\n")
        console.print(table)
        console.print(
            f"\n  [bold]Total Findings:[/bold] {len(findings)}  |  "
            f"[bold]Risk Score:[/bold] {total_score}  |  "
            f"[bold]Time:[/bold] {elapsed:.2f}s\n"
        )
    else:
        print("\n=== Scan Summary ===")
        for sev, cnt in counts.items():
            print(f"  {sev}: {cnt}")
        print(f"Total: {len(findings)} | Score: {total_score} | Time: {elapsed:.2f}s")


# ─────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────
def save_json_report(findings: List[Finding], target: str, elapsed: float,
                     output_path: str = "zerohack_report.json"):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1

    report = {
        "tool":       "ZeroHack v2.0",
        "target":     target,
        "scan_time":  datetime.datetime.utcnow().isoformat(),
        "duration_s": round(elapsed, 2),
        "summary":    counts,
        "risk_score": sum(f.score() for f in findings),
        "findings":   [f.to_dict() for f in findings],
    }

    path = Path(output_path)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_success(f"JSON report saved → {path.resolve()}")
    return report


# ─────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────
def save_html_report(findings: List[Finding], target: str, elapsed: float,
                     output_path: str = "zerohack_report.html"):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1

    risk_score = sum(f.score() for f in findings)
    scan_time  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build findings rows
    rows_html = ""
    for f in findings:
        sev_class = f.severity.lower()
        rows_html += f"""
        <tr>
            <td><span class="badge badge-{sev_class}">{f.severity}</span></td>
            <td><strong>{_esc(f.title)}</strong></td>
            <td>{_esc(f.module)}</td>
            <td class="target-cell">{_esc(f.target)}</td>
            <td>{_esc(f.description)}</td>
            <td><code>{_esc(f.evidence[:120]) if f.evidence else '—'}</code></td>
            <td>{_esc(f.remediation) or '—'}</td>
        </tr>"""

    # Chart data
    chart_labels = list(counts.keys())
    chart_values = list(counts.values())
    chart_colors = ["#dc2626", "#f97316", "#eab308", "#3b82f6", "#6b7280"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ZeroHack v2.0 — Vulnerability Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:       #0d1117;
    --bg2:      #161b22;
    --border:   #30363d;
    --text:     #c9d1d9;
    --accent:   #58a6ff;
    --critical: #dc2626;
    --high:     #f97316;
    --medium:   #eab308;
    --low:      #3b82f6;
    --info:     #6b7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}

  .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
             border-bottom: 1px solid var(--border); padding: 40px 60px; }}
  .header h1 {{ font-size: 2.4rem; color: #58a6ff; letter-spacing: 2px; }}
  .header .subtitle {{ color: #8b949e; margin-top: 6px; }}
  .header .meta {{ margin-top: 16px; font-size: 0.85rem; color: #8b949e; }}
  .header .meta span {{ margin-right: 24px; }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 60px; }}

  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                 gap: 16px; margin-bottom: 40px; }}
  .stat-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 12px;
                padding: 20px; text-align: center; transition: transform 0.2s; }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-card .num {{ font-size: 2.5rem; font-weight: 700; }}
  .stat-card .label {{ font-size: 0.8rem; color: #8b949e; letter-spacing: 1px; margin-top: 4px; }}
  .stat-card.critical .num {{ color: var(--critical); }}
  .stat-card.high    .num {{ color: var(--high); }}
  .stat-card.medium  .num {{ color: var(--medium); }}
  .stat-card.low     .num {{ color: var(--low); }}
  .stat-card.info    .num {{ color: var(--info); }}
  .stat-card.score   .num {{ color: #58a6ff; }}

  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 40px; }}
  .chart-card {{ background: var(--bg2); border: 1px solid var(--border);
                 border-radius: 12px; padding: 24px; }}
  .chart-card h3 {{ font-size: 1rem; color: #8b949e; margin-bottom: 20px; }}
  canvas {{ max-height: 260px; }}

  .section-title {{ font-size: 1.2rem; font-weight: 600; color: var(--accent);
                    margin-bottom: 16px; padding-bottom: 8px;
                    border-bottom: 1px solid var(--border); }}
  .filter-bar {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 16px; border-radius: 6px; border: 1px solid var(--border);
                 background: var(--bg); color: var(--text); cursor: pointer; font-size: 0.85rem;
                 transition: all 0.2s; }}
  .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #0d1117; border-color: var(--accent); }}

  table {{ width: 100%; border-collapse: collapse; background: var(--bg2);
           border-radius: 12px; overflow: hidden; font-size: 0.875rem; }}
  th {{ background: #21262d; color: #8b949e; font-size: 0.75rem; letter-spacing: 1px;
        text-transform: uppercase; padding: 12px 16px; text-align: left; }}
  td {{ padding: 12px 16px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: rgba(88, 166, 255, 0.04); }}
  .target-cell {{ font-family: monospace; font-size: 0.8rem; color: #8b949e; max-width: 200px;
                  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px;
          font-family: monospace; font-size: 0.8rem; color: #ffa657; }}

  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
            font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }}
  .badge-critical {{ background: rgba(220,38,38,0.2);   color: #fca5a5; border: 1px solid #dc2626; }}
  .badge-high     {{ background: rgba(249,115,22,0.2);  color: #fdba74; border: 1px solid #f97316; }}
  .badge-medium   {{ background: rgba(234,179,8,0.2);   color: #fde047; border: 1px solid #eab308; }}
  .badge-low      {{ background: rgba(59,130,246,0.2);  color: #93c5fd; border: 1px solid #3b82f6; }}
  .badge-info     {{ background: rgba(107,114,128,0.2); color: #9ca3af; border: 1px solid #6b7280; }}

  .footer {{ text-align: center; color: #8b949e; font-size: 0.8rem;
             padding: 32px; border-top: 1px solid var(--border); margin-top: 40px; }}
  @media (max-width: 768px) {{
    .container, .header {{ padding: 20px; }}
    .charts {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ ZeroHack v2.0</h1>
  <div class="subtitle">Vulnerability Assessment Report</div>
  <div class="meta">
    <span>🎯 Target: <strong>{_esc(target)}</strong></span>
    <span>📅 Scan Time: <strong>{scan_time}</strong></span>
    <span>⏱ Duration: <strong>{elapsed:.2f}s</strong></span>
    <span>🔍 Findings: <strong>{len(findings)}</strong></span>
  </div>
</div>

<div class="container">
  <!-- Stats Grid -->
  <div class="stats-grid">
    <div class="stat-card critical"><div class="num">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
    <div class="stat-card high">   <div class="num">{counts['HIGH']}</div>   <div class="label">HIGH</div></div>
    <div class="stat-card medium"> <div class="num">{counts['MEDIUM']}</div> <div class="label">MEDIUM</div></div>
    <div class="stat-card low">    <div class="num">{counts['LOW']}</div>    <div class="label">LOW</div></div>
    <div class="stat-card info">   <div class="num">{counts['INFO']}</div>   <div class="label">INFO</div></div>
    <div class="stat-card score">  <div class="num">{risk_score}</div>       <div class="label">RISK SCORE</div></div>
  </div>

  <!-- Charts -->
  <div class="charts">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <canvas id="pieChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>Findings by Module</h3>
      <canvas id="barChart"></canvas>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="section-title">All Findings</div>
  <div class="filter-bar" id="filterBar">
    <button class="filter-btn active" onclick="filterTable('ALL')">All ({len(findings)})</button>
    <button class="filter-btn" onclick="filterTable('CRITICAL')">Critical ({counts['CRITICAL']})</button>
    <button class="filter-btn" onclick="filterTable('HIGH')">High ({counts['HIGH']})</button>
    <button class="filter-btn" onclick="filterTable('MEDIUM')">Medium ({counts['MEDIUM']})</button>
    <button class="filter-btn" onclick="filterTable('LOW')">Low ({counts['LOW']})</button>
    <button class="filter-btn" onclick="filterTable('INFO')">Info ({counts['INFO']})</button>
  </div>

  <table id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th><th>Title</th><th>Module</th><th>Target</th>
        <th>Description</th><th>Evidence</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by ZeroHack v2.0 — For authorized testing only.
  Always obtain written permission before testing.
</div>

<script>
// Pie chart
const pieCtx = document.getElementById('pieChart').getContext('2d');
new Chart(pieCtx, {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(chart_labels)},
    datasets: [{{ data: {json.dumps(chart_values)}, backgroundColor: {json.dumps(chart_colors)}, borderWidth: 0 }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}, cutout: '65%' }}
}});

// Bar chart by module
const moduleCounts = {{}};
const rows = document.querySelectorAll('#findingsTable tbody tr');
rows.forEach(r => {{
  const mod = r.cells[2].textContent.trim();
  moduleCounts[mod] = (moduleCounts[mod] || 0) + 1;
}});
const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {{
  type: 'bar',
  data: {{
    labels: Object.keys(moduleCounts),
    datasets: [{{ label: 'Findings', data: Object.values(moduleCounts),
                 backgroundColor: '#58a6ff44', borderColor: '#58a6ff', borderWidth: 1 }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }}, beginAtZero: true }}
    }}
  }}
}});

// Filter
function filterTable(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  rows.forEach(r => {{
    const badge = r.querySelector('.badge');
    if (!badge) return;
    r.style.display = (sev === 'ALL' || badge.textContent.trim() === sev) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    path = Path(output_path)
    path.write_text(html, encoding="utf-8")
    print_success(f"HTML report saved → {path.resolve()}")


def _esc(s: str) -> str:
    """HTML escape helper."""
    if not s:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
