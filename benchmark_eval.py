"""
ZeroHack v2.0 - Benchmark Evaluation Framework
============================================================
Measures ZeroHack's capabilities against known-vulnerable targets.

Metrics:
  - Detection Rate   : % of known vulnerabilities correctly identified
  - False Positives  : Findings on clean/safe pages
  - Scan Speed       : Time per module in milliseconds
  - Memory Usage     : Peak RAM during scan (MB)
  - Coverage Score   : Number of vulnerability classes covered
  - Nmap Accuracy    : Port scanner agreement with Nmap

Targets (no Docker required):
  1. http://testphp.vulnweb.com   — Acunetix deliberately vulnerable PHP app
  2. http://localhost/dvwa/       — DVWA (if running locally)
  3. http://localhost:3000        — OWASP Juice Shop (if running locally)

Usage:
  python benchmark_eval.py --target http://testphp.vulnweb.com
  python benchmark_eval.py --target http://localhost/dvwa --all
  python benchmark_eval.py --target http://localhost:3000 --quick
  python benchmark_eval.py --compare-nmap --target http://localhost
"""

import argparse
import json
import os
import sys
import time
import traceback
import threading
import datetime
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ─────────────────────────────────────────────────────────────
# Known Ground Truth for benchmark targets
# ─────────────────────────────────────────────────────────────

# Known vulnerabilities present in testphp.vulnweb.com and DVWA
KNOWN_VULNERABILITIES = {
    "http://testphp.vulnweb.com": {
        "SQL Injection":             True,
        "XSS":                       True,
        "LFI":                       True,
        "Missing Security Headers":  True,
        "Directory Traversal":       True,
        "CORS Misconfiguration":     False,  # Not present
        "XXE":                       False,
        "SSRF":                      False,
    },
    "http://localhost/dvwa": {
        "SQL Injection":             True,
        "XSS":                       True,
        "LFI":                       True,
        "RCE":                       True,
        "Missing Security Headers":  True,
        "CSRF":                      True,
        "File Upload":               True,
        "SSRF":                      False,
    },
    "http://localhost:3000": {
        "SQL Injection":             True,
        "XSS":                       True,
        "IDOR":                      True,
        "API Security":              True,
        "JWT Vulnerabilities":       True,
        "Missing Security Headers":  True,
        "SSRF":                      False,
    },
}

# ZeroHack module → vulnerability category mapping
MODULE_TO_VULN = {
    "sql":      ["SQL Injection"],
    "xss":      ["XSS"],
    "ssrf":     ["SSRF"],
    "rce":      ["RCE", "Command Injection"],
    "idor":     ["IDOR"],
    "headers":  ["Missing Security Headers", "CORS Misconfiguration", "LFI", "Directory Traversal"],
    "cache":    ["Web Cache Poisoning"],
    "logic":    ["Business Logic"],
    "ports":    ["Open Ports"],
    "api":      ["API Security", "JWT Vulnerabilities"],
    "cloud":    ["Cloud Misconfiguration"],
    "iot":      ["IoT Default Credentials"],
    "mobile":   ["Mobile Security"],
    "contract": ["Smart Contract Vulnerabilities"],
    "web3":     ["Web3 / DeFi"],
}

# ─────────────────────────────────────────────────────────────
# Benchmark data structures
# ─────────────────────────────────────────────────────────────
@dataclass
class ModuleBenchmark:
    module_key:     str
    module_name:    str
    duration_ms:    float
    findings_count: int
    peak_mem_mb:    float
    error:          Optional[str] = None


@dataclass
class BenchmarkResult:
    target:             str
    scan_date:          str
    total_duration_s:   float
    modules_run:        int
    total_findings:     int
    detection_rate:     float     # 0.0 – 1.0
    false_positives:    int
    coverage_score:     float     # 0.0 – 100.0
    capability_score:   float     # 0.0 – 100.0
    module_benchmarks:  List[ModuleBenchmark] = field(default_factory=list)
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    nmap_comparison:    Optional[Dict] = None


# ─────────────────────────────────────────────────────────────
# Memory monitor
# ─────────────────────────────────────────────────────────────
class MemoryMonitor:
    def __init__(self):
        self._peak = 0.0
        self._running = False
        self._thread  = None

    def start(self):
        self._running = True
        self._peak    = 0.0
        self._thread  = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self) -> float:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        return self._peak

    def _monitor(self):
        if not PSUTIL_AVAILABLE:
            return
        proc = psutil.Process(os.getpid())
        while self._running:
            try:
                mem_mb = proc.memory_info().rss / 1024 / 1024
                if mem_mb > self._peak:
                    self._peak = mem_mb
            except Exception:
                pass
            time.sleep(0.25)


# ─────────────────────────────────────────────────────────────
# Benchmark runner
# ─────────────────────────────────────────────────────────────
class ZeroHackBenchmark:
    def __init__(self, target: str, module_keys: Optional[List[str]] = None,
                 quick: bool = False, compare_nmap: bool = False):
        self.target       = target.rstrip("/")
        self.quick        = quick
        self.compare_nmap = compare_nmap

        # Default: run web + network modules for general benchmark
        if module_keys:
            self.module_keys = module_keys
        elif quick:
            self.module_keys = ["sql", "xss", "headers", "ports"]
        else:
            self.module_keys = ["sql", "xss", "ssrf", "rce", "idor",
                                 "headers", "cache", "logic", "ports", "api"]

        self.all_findings: List = []
        self.module_benchmarks: List[ModuleBenchmark] = []

    def run(self) -> BenchmarkResult:
        self._print_header()

        total_start = time.perf_counter()

        for key in self.module_keys:
            self._run_single_module(key)

        total_elapsed = time.perf_counter() - total_start

        result = self._compute_scores(total_elapsed)
        self._save_reports(result)
        self._print_report(result)

        return result

    # ─────── Single module run ────────────────────────────────
    def _run_single_module(self, key: str):
        from vulnscanner import MODULE_REGISTRY, load_scanner_class

        meta = MODULE_REGISTRY.get(key)
        if not meta:
            return

        if RICH_AVAILABLE:
            console.print(f"  [dim]→[/dim] [cyan]{meta['name']}[/cyan]...", end=" ")

        mem_monitor = MemoryMonitor()
        mem_monitor.start()
        start = time.perf_counter()
        error = None
        n_findings = 0

        try:
            ScannerClass = load_scanner_class(key)
            scanner_kwargs = {
                "target":  self.target,
                "timeout": 8,
                "delay":   0.2,
            }
            if meta.get("needs_url", True):
                scanner = ScannerClass(**scanner_kwargs)
            else:
                scanner = ScannerClass(target=self.target)

            findings = scanner.scan(mode="both")
            self.all_findings.extend(findings)
            n_findings = len(findings)

        except Exception as e:
            error = str(e)

        duration_ms = (time.perf_counter() - start) * 1000
        peak_mem    = mem_monitor.stop()

        bench = ModuleBenchmark(
            module_key=key,
            module_name=meta["name"],
            duration_ms=duration_ms,
            findings_count=n_findings,
            peak_mem_mb=peak_mem,
            error=error,
        )
        self.module_benchmarks.append(bench)

        if RICH_AVAILABLE:
            status = f"[red]{error[:40]}[/red]" if error else f"[green]{n_findings} finding(s)[/green]"
            console.print(f"{status} [dim]({duration_ms:.0f}ms)[/dim]")
        else:
            print(f"  [{key}] {n_findings} findings | {duration_ms:.0f}ms | error={error}")

    # ─────── Score computation ────────────────────────────────
    def _compute_scores(self, total_elapsed: float) -> BenchmarkResult:
        # Severity breakdown
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.all_findings:
            sev = getattr(f, "severity", "INFO").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # Detection rate vs known ground truth
        detection_rate = self._compute_detection_rate()

        # False positives (findings that are UNLIKELY for the target type)
        false_positives = self._estimate_false_positives()

        # Coverage score: how many vulnerability categories were tested
        all_cats = set()
        for cats in MODULE_TO_VULN.values():
            all_cats.update(cats)
        tested_cats = set()
        for key in self.module_keys:
            tested_cats.update(MODULE_TO_VULN.get(key, []))
        coverage_score = (len(tested_cats) / max(len(all_cats), 1)) * 100

        # Nmap comparison
        nmap_data = None
        if self.compare_nmap:
            nmap_data = self._run_nmap_comparison()

        # Weighted capability score
        w_detection  = detection_rate * 40         # 40 points max
        w_coverage   = (coverage_score / 100) * 30 # 30 points max
        w_speed      = self._speed_score() * 20     # 20 points max
        w_fp         = max(0, 10 - false_positives) # 10 points max (penalize FPs)
        capability   = min(100.0, w_detection + w_coverage + w_speed + w_fp)

        return BenchmarkResult(
            target=self.target,
            scan_date=datetime.datetime.utcnow().isoformat(),
            total_duration_s=round(total_elapsed, 2),
            modules_run=len(self.module_keys),
            total_findings=len(self.all_findings),
            detection_rate=round(detection_rate, 3),
            false_positives=false_positives,
            coverage_score=round(coverage_score, 1),
            capability_score=round(capability, 1),
            module_benchmarks=self.module_benchmarks,
            severity_breakdown=sev_counts,
            nmap_comparison=nmap_data,
        )

    def _compute_detection_rate(self) -> float:
        """Compare findings against known vulnerabilities for this target."""
        # Normalize target URL for lookup
        base_target = self.target.split("?")[0].rstrip("/")
        known = None
        for k, v in KNOWN_VULNERABILITIES.items():
            if k in base_target or base_target in k:
                known = v
                break

        if not known:
            # Unknown target — estimate based on finding count relative to modules
            # A tool that finds at least 1 finding per web module is considered effective
            web_modules_run = [k for k in self.module_keys if k in
                               ["sql", "xss", "ssrf", "rce", "idor", "headers"]]
            if not web_modules_run:
                return 0.5
            findings_per_module = len(self.all_findings) / max(len(web_modules_run), 1)
            # Normalize: >3 findings per module = high detection
            return min(1.0, findings_per_module / 5.0)

        # Check which known vulns were detected
        detected = 0
        total_known = sum(1 for v in known.values() if v)  # only count vulns that ARE present

        for vuln_present, finding_cats in [
            (known.get("SQL Injection"),            ["SQL Injection"]),
            (known.get("XSS"),                      ["XSS"]),
            (known.get("LFI"),                      ["Local File Inclusion", "LFI"]),
            (known.get("Missing Security Headers"),  ["Missing Security Header"]),
            (known.get("SSRF"),                     ["SSRF"]),
            (known.get("RCE"),                      ["Command Injection", "RCE", "SSTI"]),
        ]:
            if not vuln_present:
                continue
            for f in self.all_findings:
                title = getattr(f, "title", "").upper()
                if any(cat.upper() in title for cat in finding_cats):
                    detected += 1
                    break

        return detected / max(total_known, 1)

    def _estimate_false_positives(self) -> int:
        """
        Estimate false positives by counting HIGH/CRITICAL findings
        that don't match common known-vulnerable patterns.
        """
        suspicious = 0
        for f in self.all_findings:
            sev   = getattr(f, "severity", "").upper()
            title = getattr(f, "title",    "").lower()
            if sev in ("HIGH", "CRITICAL"):
                # If it's a port scanner or subdomain finding, likely valid
                mod = getattr(f, "module", "")
                if "Port" in mod or "Subdomain" in mod:
                    continue
                # Very generic findings are FP candidates
                if "potential" in title or "possible" in title:
                    suspicious += 1
        return suspicious

    def _speed_score(self) -> float:
        """Score based on average module speed. Faster = higher score."""
        if not self.module_benchmarks:
            return 0.5
        avg_ms = sum(b.duration_ms for b in self.module_benchmarks) / len(self.module_benchmarks)
        # <500ms = 1.0, <2000ms = 0.7, <5000ms = 0.4, <10000ms = 0.2
        if avg_ms < 500:   return 1.0
        if avg_ms < 2000:  return 0.7
        if avg_ms < 5000:  return 0.4
        if avg_ms < 10000: return 0.2
        return 0.1

    # ─────── Nmap comparison ─────────────────────────────────
    def _run_nmap_comparison(self) -> Optional[Dict]:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        host   = parsed.hostname or self.target

        # ZeroHack ports
        zh_ports = set()
        for f in self.all_findings:
            mod = getattr(f, "module", "")
            if "Port" in mod:
                import re
                m = re.search(r"Open Port (\d+)", getattr(f, "title", ""))
                if m:
                    zh_ports.add(int(m.group(1)))

        # Nmap ports
        nmap_ports = set()
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--open", "-F", host, "-oX", "-"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                for host_el in root.findall("host"):
                    for port_el in host_el.findall(".//port"):
                        state = port_el.find("state")
                        if state is not None and state.get("state") == "open":
                            nmap_ports.add(int(port_el.get("portid", 0)))
        except FileNotFoundError:
            return {"error": "nmap not installed"}
        except Exception as e:
            return {"error": str(e)}

        missed_by_zh = sorted(nmap_ports - zh_ports)
        extra_by_zh  = sorted(zh_ports - nmap_ports)
        agreement    = len(zh_ports & nmap_ports)
        total        = len(zh_ports | nmap_ports)
        accuracy     = (agreement / total * 100) if total > 0 else 100.0

        return {
            "zerohack_ports": sorted(zh_ports),
            "nmap_ports":     sorted(nmap_ports),
            "missed_by_zh":   missed_by_zh,
            "extra_by_zh":    extra_by_zh,
            "accuracy_pct":   round(accuracy, 1),
        }

    # ─────── Reports ─────────────────────────────────────────
    def _save_reports(self, result: BenchmarkResult):
        # JSON
        data = asdict(result)
        with open("benchmark_report.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        # HTML
        self._save_html_report(result)

        if RICH_AVAILABLE:
            console.print(f"\n[green]✓[/green] benchmark_report.json saved")
            console.print(f"[green]✓[/green] benchmark_report.html saved")
        else:
            print("\nbenchmark_report.json and benchmark_report.html saved.")

    def _save_html_report(self, result: BenchmarkResult):
        # Module benchmarks table rows
        module_rows = ""
        for b in result.module_benchmarks:
            status_icon = "✅" if not b.error else "❌"
            error_text  = f" ({b.error[:40]})" if b.error else ""
            module_rows += f"""
            <tr>
                <td>{status_icon} <strong>{b.module_name}</strong></td>
                <td>{b.findings_count}</td>
                <td>{b.duration_ms:.0f} ms</td>
                <td>{b.peak_mem_mb:.1f} MB</td>
                <td style="color:{'#ef4444' if b.error else '#22c55e'}">{('ERROR' + error_text) if b.error else 'OK'}</td>
            </tr>"""

        # Score bar helper
        score = result.capability_score
        score_color = "#22c55e" if score >= 70 else ("#eab308" if score >= 40 else "#ef4444")

        nmap_section = ""
        if result.nmap_comparison:
            nc = result.nmap_comparison
            if "error" in nc:
                nmap_section = f'<p style="color:#ef4444">Nmap error: {nc["error"]}</p>'
            else:
                nmap_section = f"""
                <div class="metric-card">
                    <h3>🔍 Nmap Comparison</h3>
                    <table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>
                    <tr><td>ZeroHack ports</td><td>{nc['zerohack_ports']}</td></tr>
                    <tr><td>Nmap ports</td><td>{nc['nmap_ports']}</td></tr>
                    <tr><td>Missed by ZeroHack</td><td style="color:#ef4444">{nc['missed_by_zh'] or 'none'}</td></tr>
                    <tr><td>Extra by ZeroHack</td><td style="color:#eab308">{nc['extra_by_zh'] or 'none'}</td></tr>
                    <tr><td>Accuracy</td><td style="color:#22c55e"><strong>{nc['accuracy_pct']}%</strong></td></tr>
                    </tbody></table>
                </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ZeroHack v2.0 — Benchmark Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --border: #30363d;
    --text: #c9d1d9; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
          color: var(--text); line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #0d1117, #161b22, #0d1117);
             border-bottom: 1px solid var(--border); padding: 40px 60px; }}
  .header h1 {{ font-size: 2.2rem; color: #58a6ff; }}
  .header .sub {{ color: #8b949e; margin-top: 4px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 60px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 16px; margin-bottom: 32px; }}
  .metric-card {{ background: var(--bg2); border: 1px solid var(--border);
                  border-radius: 12px; padding: 20px; }}
  .metric-card h3 {{ font-size: 0.85rem; color: #8b949e; margin-bottom: 12px; letter-spacing: 1px; }}
  .big-num {{ font-size: 2.5rem; font-weight: 700; color: var(--accent); }}
  .score-bar {{ height: 12px; background: #21262d; border-radius: 6px; margin: 8px 0; overflow: hidden; }}
  .score-fill {{ height: 100%; border-radius: 6px; transition: width 1s ease; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg2);
           border-radius: 12px; overflow: hidden; font-size: 0.875rem; }}
  th {{ background: #21262d; color: #8b949e; font-size: 0.75rem; letter-spacing: 1px;
        text-transform: uppercase; padding: 12px 16px; text-align: left; }}
  td {{ padding: 12px 16px; border-top: 1px solid var(--border); }}
  tr:hover td {{ background: rgba(88,166,255,0.04); }}
  .section-title {{ font-size: 1.1rem; font-weight: 600; color: var(--accent);
                    margin: 28px 0 14px; padding-bottom: 8px;
                    border-bottom: 1px solid var(--border); }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
  .chart-card {{ background: var(--bg2); border: 1px solid var(--border);
                 border-radius: 12px; padding: 20px; }}
  .chart-card h3 {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 16px; }}
  canvas {{ max-height: 220px; }}
  .footer {{ text-align: center; color: #8b949e; font-size: 0.8rem;
             padding: 24px; border-top: 1px solid var(--border); margin-top: 40px; }}
  @media (max-width: 768px) {{ .container, .header {{ padding: 20px; }}
                               .charts {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ ZeroHack v2.0 — Benchmark Report</h1>
  <div class="sub">Objective capability evaluation against {result.target}</div>
  <div style="margin-top:12px;font-size:0.85rem;color:#8b949e;">
    Scan Date: {result.scan_date[:19]} UTC &nbsp;|&nbsp;
    Duration: {result.total_duration_s}s &nbsp;|&nbsp;
    Modules: {result.modules_run} &nbsp;|&nbsp;
    Findings: {result.total_findings}
  </div>
</div>
<div class="container">

  <div class="metrics">
    <div class="metric-card">
      <h3>CAPABILITY SCORE</h3>
      <div class="big-num" style="color:{score_color}">{result.capability_score}</div>
      <div class="score-bar"><div class="score-fill" style="width:{result.capability_score}%;background:{score_color}"></div></div>
      <div style="font-size:0.8rem;color:#8b949e">out of 100</div>
    </div>
    <div class="metric-card">
      <h3>DETECTION RATE</h3>
      <div class="big-num">{result.detection_rate*100:.0f}%</div>
      <div class="score-bar"><div class="score-fill" style="width:{result.detection_rate*100}%;background:#22c55e"></div></div>
    </div>
    <div class="metric-card">
      <h3>COVERAGE SCORE</h3>
      <div class="big-num">{result.coverage_score}%</div>
      <div class="score-bar"><div class="score-fill" style="width:{result.coverage_score}%;background:#3b82f6"></div></div>
    </div>
    <div class="metric-card">
      <h3>FALSE POSITIVES</h3>
      <div class="big-num" style="color:{'#ef4444' if result.false_positives > 5 else '#22c55e'}">{result.false_positives}</div>
    </div>
    <div class="metric-card">
      <h3>TOTAL FINDINGS</h3>
      <div class="big-num">{result.total_findings}</div>
    </div>
    <div class="metric-card">
      <h3>SCAN DURATION</h3>
      <div class="big-num">{result.total_duration_s}s</div>
    </div>
  </div>

  <div class="charts">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <canvas id="sevChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>Module Performance (ms)</h3>
      <canvas id="speedChart"></canvas>
    </div>
  </div>

  {nmap_section}

  <div class="section-title">Module Benchmarks</div>
  <table>
    <thead><tr>
      <th>Module</th><th>Findings</th><th>Duration</th><th>Peak RAM</th><th>Status</th>
    </tr></thead>
    <tbody>{module_rows}</tbody>
  </table>

</div>
<div class="footer">ZeroHack v2.0 Benchmark — {result.scan_date[:10]} — For authorized testing only</div>
<script>
const sevData = {{
  labels: {json.dumps(list(result.severity_breakdown.keys()))},
  datasets: [{{ data: {json.dumps(list(result.severity_breakdown.values()))},
               backgroundColor:['#dc2626','#f97316','#eab308','#3b82f6','#6b7280'],
               borderWidth:0 }}]
}};
new Chart(document.getElementById('sevChart'), {{
  type:'doughnut', data:sevData,
  options:{{ plugins:{{ legend:{{ labels:{{ color:'#c9d1d9' }} }} }}, cutout:'60%' }}
}});

const modNames  = {json.dumps([b.module_name[:20] for b in result.module_benchmarks])};
const modSpeeds = {json.dumps([round(b.duration_ms) for b in result.module_benchmarks])};
new Chart(document.getElementById('speedChart'), {{
  type:'bar',
  data:{{ labels:modNames, datasets:[{{ label:'ms', data:modSpeeds,
          backgroundColor:'#58a6ff44', borderColor:'#58a6ff', borderWidth:1 }}] }},
  options:{{
    plugins:{{ legend:{{ display:false }} }},
    scales:{{
      x:{{ ticks:{{ color:'#8b949e' }}, grid:{{ color:'#30363d' }} }},
      y:{{ ticks:{{ color:'#8b949e' }}, grid:{{ color:'#30363d' }}, beginAtZero:true }}
    }}
  }}
}});
</script>
</body>
</html>"""

        with open("benchmark_report.html", "w", encoding="utf-8") as f:
            f.write(html)

    # ─────── Terminal report ──────────────────────────────────
    def _print_report(self, result: BenchmarkResult):
        if not RICH_AVAILABLE:
            print("\n=== BENCHMARK RESULTS ===")
            print(f"Capability Score : {result.capability_score}/100")
            print(f"Detection Rate   : {result.detection_rate*100:.0f}%")
            print(f"Coverage Score   : {result.coverage_score}%")
            print(f"False Positives  : {result.false_positives}")
            print(f"Total Findings   : {result.total_findings}")
            print(f"Duration         : {result.total_duration_s}s")
            return

        score = result.capability_score
        score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")

        console.print(f"\n")
        console.print(Panel(
            f"[{score_color}][bold]{score}/100[/bold][/{score_color}]  Capability Score\n"
            f"[green]{result.detection_rate*100:.0f}%[/green]  Detection Rate  |  "
            f"[blue]{result.coverage_score}%[/blue]  Coverage  |  "
            f"[yellow]{result.false_positives}[/yellow]  Est. False Positives\n"
            f"[dim]{result.total_findings} total findings in {result.total_duration_s}s[/dim]",
            title="[bold cyan]⚡ ZeroHack v2.0 Benchmark Results[/bold cyan]",
            border_style="cyan",
        ))

        # Module table
        table = Table(title="Module Performance", box=box.ROUNDED, border_style="dim")
        table.add_column("Module",   style="white",  width=35)
        table.add_column("Findings", justify="center")
        table.add_column("Time",     justify="right")
        table.add_column("RAM",      justify="right")
        table.add_column("Status",   justify="center")

        for b in result.module_benchmarks:
            status  = "[red]ERROR[/red]" if b.error else "[green]✓ OK[/green]"
            ram_str = f"{b.peak_mem_mb:.0f} MB" if b.peak_mem_mb else "—"
            table.add_row(b.module_name, str(b.findings_count),
                          f"{b.duration_ms:.0f} ms", ram_str, status)

        console.print(table)

        if result.nmap_comparison and "error" not in result.nmap_comparison:
            nc = result.nmap_comparison
            console.print(f"\n  [bold]Nmap Accuracy:[/bold] [green]{nc['accuracy_pct']}%[/green]")
            if nc["missed_by_zh"]:
                console.print(f"  [yellow]Ports missed by ZeroHack:[/yellow] {nc['missed_by_zh']}")

    def _print_header(self):
        if RICH_AVAILABLE:
            console.print(Panel(
                "[bold cyan]ZeroHack v2.0 — Benchmark Evaluation[/bold cyan]\n"
                f"[dim]Target: {self.target}[/dim]\n"
                f"[dim]Modules: {', '.join(self.module_keys)}[/dim]",
                border_style="cyan",
            ))
        else:
            print(f"=== ZeroHack Benchmark | Target: {self.target} ===")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="benchmark_eval",
        description="ZeroHack v2.0 Benchmark Evaluation Framework",
    )
    parser.add_argument("--target",   "-t", required=True,
                        help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--modules",  "-m", default=None,
                        help="Comma-separated module keys (default: all web+network)")
    parser.add_argument("--all",      "-a", action="store_true",
                        help="Run all available modules")
    parser.add_argument("--quick",    "-q", action="store_true",
                        help="Quick benchmark (sql, xss, headers, ports only)")
    parser.add_argument("--compare-nmap", action="store_true",
                        help="Run Nmap and compare port scan results")
    args = parser.parse_args()

    module_keys = None
    if args.all:
        from vulnscanner import MODULE_REGISTRY
        module_keys = list(MODULE_REGISTRY.keys())
    elif args.modules:
        module_keys = [k.strip() for k in args.modules.split(",")]

    bench = ZeroHackBenchmark(
        target=args.target,
        module_keys=module_keys,
        quick=args.quick,
        compare_nmap=args.compare_nmap,
    )
    bench.run()


if __name__ == "__main__":
    main()
