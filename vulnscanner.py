"""
ZeroHack v2.0 - Main Entry Point
CLI + TUI orchestrator with concurrent/async scanning and report generation.

Usage:
  python vulnscanner.py --target https://example.com
  python vulnscanner.py --target https://example.com --modules sql,xss,headers
  python vulnscanner.py --target https://example.com --all --async-mode
  python vulnscanner.py --target https://example.com --apk myapp.apk
  python vulnscanner.py                              (launches interactive TUI)
"""

import argparse
import sys
import time
import json
import threading
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Try Rich TUI imports ────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# ── ZeroHack imports ────────────────────────────────────────
from modules.notification_system import (
    Finding, print_banner, print_summary_table,
    save_json_report, save_html_report,
    print_info, print_success, print_error, print_warning
)
from modules.enhanced_scanner import BaseScanner

# ─────────────────────────────────────────────────────────────
# Module registry
# ─────────────────────────────────────────────────────────────
MODULE_REGISTRY: Dict[str, dict] = {
    "sql": {
        "name":    "SQL Injection",
        "class":   "SQLInjectionTester",
        "module":  "modules.sql_injection",
        "needs_url": True,
        "category": "web",
    },
    "xss": {
        "name":    "XSS",
        "class":   "XSSTester",
        "module":  "modules.xss_tester",
        "needs_url": True,
        "category": "web",
    },
    "ssrf": {
        "name":    "SSRF",
        "class":   "SSRFTester",
        "module":  "modules.ssrf_tester",
        "needs_url": True,
        "category": "web",
    },
    "rce": {
        "name":    "RCE / Command Injection / SSTI",
        "class":   "RCETester",
        "module":  "modules.rce_tester",
        "needs_url": True,
        "category": "web",
    },
    "idor": {
        "name":    "IDOR",
        "class":   "IDORTester",
        "module":  "modules.idor_tester",
        "needs_url": True,
        "category": "web",
    },
    "headers": {
        "name":    "Additional Vulns (Headers / CORS / LFI / XXE)",
        "class":   "AdditionalVulnsTester",
        "module":  "modules.additional_vulns",
        "needs_url": True,
        "category": "web",
    },
    "cache": {
        "name":    "Web Cache Poisoning",
        "class":   "WebCacheTester",
        "module":  "modules.web_cache_tester",
        "needs_url": True,
        "category": "web",
    },
    "logic": {
        "name":    "Business Logic",
        "class":   "BusinessLogicTester",
        "module":  "modules.business_logic_tester",
        "needs_url": True,
        "category": "web",
    },
    "ports": {
        "name":    "Port Scanner",
        "class":   "PortScanner",
        "module":  "modules.port_scanner",
        "needs_url": False,
        "category": "network",
    },
    "subdomain": {
        "name":    "Subdomain Enumeration",
        "class":   "SubdomainEnumerator",
        "module":  "modules.subdomain_enum",
        "needs_url": False,
        "category": "network",
    },
    "api": {
        "name":    "API Security",
        "class":   "APISecurityTester",
        "module":  "modules.api_security_tester",
        "needs_url": True,
        "category": "api",
    },
    "cloud": {
        "name":    "Cloud Security",
        "class":   "CloudSecurityTester",
        "module":  "modules.cloud_security_tester",
        "needs_url": True,
        "category": "cloud",
    },
    "iot": {
        "name":    "IoT Security",
        "class":   "IoTSecurityTester",
        "module":  "modules.iot_security_tester",
        "needs_url": True,
        "category": "iot",
    },
    "mobile": {
        "name":    "Mobile Security",
        "class":   "MobileSecurityTester",
        "module":  "modules.mobile_security_tester",
        "needs_url": True,
        "category": "mobile",
    },
    "contract": {
        "name":    "Smart Contract",
        "class":   "SmartContractTester",
        "module":  "modules.smart_contract_tester",
        "needs_url": True,
        "category": "blockchain",
    },
    "web3": {
        "name":    "Web3 / DeFi",
        "class":   "Web3Tester",
        "module":  "modules.web3_tester",
        "needs_url": True,
        "category": "blockchain",
    },
}

CATEGORY_DESCRIPTIONS = {
    "web":        "Web Application Testing",
    "network":    "Network & Infrastructure",
    "api":        "API & REST Security",
    "cloud":      "Cloud Security",
    "iot":        "IoT Device Security",
    "mobile":     "Mobile Application Security",
    "blockchain": "Smart Contract & Web3",
}


# ─────────────────────────────────────────────────────────────
# Dynamic module loader
# ─────────────────────────────────────────────────────────────
def load_scanner_class(key: str):
    """Dynamically import and return a scanner class by registry key."""
    meta = MODULE_REGISTRY[key]
    import importlib
    mod = importlib.import_module(meta["module"])
    return getattr(mod, meta["class"])


# ─────────────────────────────────────────────────────────────
# Core scan orchestrator
# ─────────────────────────────────────────────────────────────
def run_scan(target: str, module_keys: List[str], mode: str = "both",
             timeout: int = 10, delay: float = 0.3, proxy: Optional[str] = None,
             cookies: Optional[str] = None, headers: Optional[str] = None,
             apk_path: Optional[str] = None, max_workers: int = 10,
             output_json: str = "zerohack_report.json",
             output_html: str = "zerohack_report.html") -> List[Finding]:

    all_findings: List[Finding] = []
    _lock = threading.Lock()

    # Parse cookies and extra headers
    cookie_dict = {}
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookie_dict[k.strip()] = v.strip()

    header_dict = {}
    if headers:
        for pair in headers.split(";"):
            if ":" in pair:
                k, v = pair.strip().split(":", 1)
                header_dict[k.strip()] = v.strip()

    # Scanner kwargs shared across URL-based modules
    scanner_kwargs = {
        "target":      target,
        "timeout":     timeout,
        "delay":       delay,
        "cookies":     cookie_dict,
        "headers":     header_dict,
        "proxy":       proxy,
        "max_workers": max_workers,
    }

    start_time = time.perf_counter()

    # WAF detection
    base_scanner = BaseScanner(**scanner_kwargs)
    waf = base_scanner.detect_waf()
    if waf:
        print_warning(f"WAF detected: {waf} — some payloads may be blocked")
    else:
        print_info("No WAF detected")

    # ── Run modules concurrently ──────────────────────────────
    def run_module(key: str):
        try:
            ScannerClass = load_scanner_class(key)
            meta = MODULE_REGISTRY[key]

            if meta.get("needs_url", True):
                scanner = ScannerClass(**scanner_kwargs)
            else:
                # Port scanner and subdomain enum only need target
                scanner = ScannerClass(target=target)

            # Special case: mobile needs APK path
            if key == "mobile" and apk_path:
                findings = scanner.scan(mode=mode, apk_path=apk_path)
            else:
                findings = scanner.scan(mode=mode)

            with _lock:
                all_findings.extend(findings)

            return key, len(findings)
        except ImportError as e:
            print_error(f"Module '{key}' import error: {e}")
            return key, 0
        except Exception as e:
            print_error(f"Module '{key}' runtime error: {e}")
            return key, 0

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            tasks = {key: progress.add_task(f"[cyan]{MODULE_REGISTRY[key]['name']}...", total=None)
                     for key in module_keys}

            with ThreadPoolExecutor(max_workers=min(len(module_keys), 4)) as pool:
                futures = {pool.submit(run_module, key): key for key in module_keys}
                for future in as_completed(futures):
                    key  = futures[future]
                    _, n = future.result()
                    progress.update(tasks[key],
                                    description=f"[green]{MODULE_REGISTRY[key]['name']} — {n} finding(s)",
                                    completed=True)
    else:
        with ThreadPoolExecutor(max_workers=min(len(module_keys), 4)) as pool:
            futures = {pool.submit(run_module, key): key for key in module_keys}
            for future in as_completed(futures):
                future.result()

    elapsed = time.perf_counter() - start_time

    # ── Reporting ─────────────────────────────────────────────
    print_summary_table(all_findings, elapsed)

    save_json_report(all_findings, target, elapsed, output_json)
    save_html_report(all_findings, target, elapsed, output_html)

    return all_findings


# ─────────────────────────────────────────────────────────────
# Interactive TUI
# ─────────────────────────────────────────────────────────────
def launch_tui():
    """Rich-based interactive menu."""
    if not RICH_AVAILABLE:
        print("Rich not installed. Please install it: pip install rich")
        print("Falling back to CLI mode. Use: python vulnscanner.py --help")
        return

    print_banner()

    # ── Target ────────────────────────────────────────────────
    target = Prompt.ask("\n[bold cyan]  Target URL[/bold cyan]",
                        default="http://localhost:80")

    # ── Module selection ──────────────────────────────────────
    console.print("\n[bold white]Available Modules:[/bold white]")
    categories: Dict[str, List[str]] = {}
    for key, meta in MODULE_REGISTRY.items():
        cat = meta["category"]
        categories.setdefault(cat, []).append(key)

    for cat, keys in categories.items():
        cat_label = CATEGORY_DESCRIPTIONS.get(cat, cat)
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Key",   style="bold yellow", width=10)
        table.add_column("Name",  style="white")
        for k in keys:
            table.add_row(f"[{k}]", MODULE_REGISTRY[k]["name"])
        console.print(Panel(table, title=f"[bold cyan]{cat_label}[/bold cyan]",
                            border_style="dim", padding=(0, 2)))

    console.print("  [dim]Type module keys separated by commas, or 'all' for all modules[/dim]")
    modules_input = Prompt.ask("[bold cyan]  Modules to run[/bold cyan]", default="all")

    if modules_input.strip().lower() == "all":
        module_keys = list(MODULE_REGISTRY.keys())
    else:
        module_keys = [k.strip() for k in modules_input.split(",") if k.strip() in MODULE_REGISTRY]

    if not module_keys:
        print_error("No valid modules selected. Exiting.")
        return

    # ── Scan mode ─────────────────────────────────────────────
    mode = Prompt.ask(
        "[bold cyan]  Scan mode[/bold cyan]",
        choices=["sync", "async", "both"],
        default="both",
    )

    # ── Advanced options ──────────────────────────────────────
    show_advanced = Confirm.ask("[bold cyan]  Show advanced options?[/bold cyan]", default=False)
    timeout = 10
    delay   = 0.3
    proxy   = None
    cookies = None
    headers = None
    apk_path = None

    if show_advanced:
        timeout  = int(Prompt.ask("  Timeout (seconds)", default="10"))
        delay    = float(Prompt.ask("  Request delay (seconds)", default="0.3"))
        proxy    = Prompt.ask("  Proxy (e.g. http://127.0.0.1:8080)", default="") or None
        cookies  = Prompt.ask("  Cookies (key=val;key=val)", default="") or None
        headers  = Prompt.ask("  Extra headers (key:val;key:val)", default="") or None
        if "mobile" in module_keys:
            apk_path = Prompt.ask("  APK path (leave blank to skip)", default="") or None

    output_json = Prompt.ask("[bold cyan]  JSON report output", default="zerohack_report.json")
    output_html = Prompt.ask("[bold cyan]  HTML report output", default="zerohack_report.html")

    # ── Confirm ───────────────────────────────────────────────
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Modules:[/bold] {', '.join(module_keys)}")
    console.print(f"[bold]Mode:[/bold]    {mode}")
    if not Confirm.ask("\n[bold cyan]Start scan?[/bold cyan]", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        return

    console.print("\n")
    run_scan(
        target=target,
        module_keys=module_keys,
        mode=mode,
        timeout=timeout,
        delay=delay,
        proxy=proxy,
        cookies=cookies,
        headers=headers,
        apk_path=apk_path,
        output_json=output_json,
        output_html=output_html,
    )


# ─────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="zerohack",
        description="ZeroHack v2.0 — Advanced Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnscanner.py
      Launch interactive TUI menu

  python vulnscanner.py --target http://localhost/dvwa --modules sql,xss
      Run SQL injection + XSS modules against DVWA

  python vulnscanner.py --target http://example.com --all --async-mode
      Full scan with async mode

  python vulnscanner.py --target http://example.com --modules ports --port-range 1-1024

  python vulnscanner.py --target http://example.com --modules mobile --apk myapp.apk

  python vulnscanner.py --target http://example.com --proxy http://127.0.0.1:8080
      Route through Burp Suite proxy

Module keys:
  sql, xss, ssrf, rce, idor, headers, cache, logic,
  ports, subdomain, api, cloud, iot, mobile, contract, web3
        """
    )
    parser.add_argument("--target", "-t",   help="Target URL (e.g. https://example.com)")
    parser.add_argument("--modules", "-m",  help="Comma-separated module keys (default: all)",
                        default="all")
    parser.add_argument("--all", "-a",      action="store_true", help="Run all modules")
    parser.add_argument("--async-mode",     action="store_true", help="Prefer async HTTP requests")
    parser.add_argument("--sync-mode",      action="store_true", help="Use synchronous requests only")
    parser.add_argument("--timeout",        type=int,   default=10,   help="HTTP request timeout in seconds")
    parser.add_argument("--delay",          type=float, default=0.3,  help="Delay between requests (seconds)")
    parser.add_argument("--proxy",          help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies",        help="Cookies string (key=val;key=val)")
    parser.add_argument("--headers",        help="Extra headers (key:val;key:val)")
    parser.add_argument("--apk",            help="Path to APK file for mobile security analysis")
    parser.add_argument("--port-range",     help="Port range for port scanner (e.g. 1-1024, 80,443,8080)")
    parser.add_argument("--workers",        type=int, default=10, help="Max concurrent workers")
    parser.add_argument("--output-json",    default="zerohack_report.json", help="JSON report output path")
    parser.add_argument("--output-html",    default="zerohack_report.html", help="HTML report output path")
    parser.add_argument("--no-report",      action="store_true", help="Skip file report generation")
    parser.add_argument("--list-modules",   action="store_true", help="List all available modules and exit")
    return parser


def cli_main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── List modules ──────────────────────────────────────────
    if args.list_modules:
        print_banner()
        if RICH_AVAILABLE:
            table = Table(title="Available Modules", box=box.ROUNDED, border_style="cyan")
            table.add_column("Key",      style="bold yellow", width=12)
            table.add_column("Name",     style="white",       width=40)
            table.add_column("Category", style="cyan",        width=15)
            for key, meta in MODULE_REGISTRY.items():
                table.add_row(key, meta["name"], CATEGORY_DESCRIPTIONS.get(meta["category"], meta["category"]))
            console.print(table)
        else:
            for key, meta in MODULE_REGISTRY.items():
                print(f"  {key:12s}  {meta['name']}")
        return

    # ── No target → TUI ──────────────────────────────────────
    if not args.target:
        launch_tui()
        return

    # ── CLI mode ──────────────────────────────────────────────
    print_banner()

    # Module selection
    if args.all or args.modules == "all":
        module_keys = list(MODULE_REGISTRY.keys())
    else:
        raw_keys    = [k.strip() for k in args.modules.split(",")]
        module_keys = [k for k in raw_keys if k in MODULE_REGISTRY]
        invalid     = [k for k in raw_keys if k not in MODULE_REGISTRY]
        if invalid:
            print_warning(f"Unknown module(s): {invalid}. Skipping.")
        if not module_keys:
            print_error("No valid modules. Use --list-modules to see options.")
            sys.exit(1)

    # Scan mode
    if args.async_mode:
        mode = "async"
    elif args.sync_mode:
        mode = "sync"
    else:
        mode = "both"

    findings = run_scan(
        target=args.target,
        module_keys=module_keys,
        mode=mode,
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        cookies=args.cookies,
        headers=args.headers,
        apk_path=args.apk,
        max_workers=args.workers,
        output_json=args.output_json,
        output_html=args.output_html,
    )

    # Exit code: 1 if any CRITICAL or HIGH findings
    critical_high = [f for f in findings if f.severity.upper() in ("CRITICAL", "HIGH")]
    if critical_high:
        sys.exit(1)
    sys.exit(0)


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cli_main()
