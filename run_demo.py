#!/usr/bin/env python3
"""
CloudSentinel Standalone Demo Runner.

Demonstrates automated Zero-Trust IaC scanning, Cedar policy verification,
and local sandbox simulation using FastMCP tools.
"""

import json
import sys
from pathlib import Path

# Ensure root directory is on sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

from server import scan_infrastructure, simulate_in_sandbox


def print_banner():
    if HAS_RICH:
        banner = Panel.fit(
            "[bold cyan]🛡️  CloudSentinel DevSecOps & FinOps Gatekeeper[/bold cyan]\n"
            "[dim]Autonomous Zero-Trust IaC Verification & Mock AWS Sandboxing[/dim]\n"
            "[green]Powered by TrueForge Orchestration & AWS Cedar Formal Policies[/green]",
            border_style="cyan",
        )
        console.print(banner)
    else:
        print("=" * 70)
        print("🛡️  CloudSentinel DevSecOps & FinOps Gatekeeper")
        print("Autonomous Zero-Trust IaC Verification & Mock AWS Sandboxing")
        print("=" * 70)


def run_demo(target_file: str):
    file_path = Path(target_file)
    if not file_path.exists():
        print(f"Error: Target file '{target_file}' not found.")
        return

    if HAS_RICH:
        console.print(f"\n[bold yellow]🔍 Scanning Target Infrastructure:[/bold yellow] [bold]{file_path}[/bold]")
    else:
        print(f"\nScanning Target Infrastructure: {file_path}")

    # 1. Execute static scan
    raw_scan = scan_infrastructure(str(file_path))
    scan_data = json.loads(raw_scan)

    compliant = scan_data.get("compliant", False)
    violations_count = scan_data.get("violations_count", 0)
    exec_time = scan_data.get("execution_time_ms", 0.0)
    violations = scan_data.get("violations", [])

    if HAS_RICH:
        status_text = "[bold green]✅ COMPLIANT (ALLOW)[/bold green]" if compliant else "[bold red]❌ NON-COMPLIANT (DENY)[/bold red]"
        console.print(f"Verdict: {status_text} | Violations: [bold]{violations_count}[/bold] | Evaluated in: [bold cyan]{exec_time} ms[/bold cyan]")

        if violations:
            table = Table(title="Detected Zero-Trust Policy Violations", border_style="red")
            table.add_column("Severity", style="bold red", width=12)
            table.add_column("Resource ID", style="bold yellow", width=24)
            table.add_column("Rule ID", style="cyan", width=32)
            table.add_column("Reason & Recommendation", style="white")

            for v in violations:
                sev = v.get("severity", "UNKNOWN")
                res_id = v.get("resource_id", "N/A")
                rule_id = v.get("rule_id", "N/A")
                reason = v.get("reason", "")
                rec = v.get("recommendation", "")
                detail = f"[bold]{reason}[/bold]\n[dim]Fix: {rec}[/dim]"
                table.add_row(sev, res_id, rule_id, detail)

            console.print(table)
        else:
            console.print("[bold green]Zero policy violations found. Template satisfies all Zero-Trust guardrails.[/bold green]")
    else:
        print(f"Verdict: {'COMPLIANT' if compliant else 'NON-COMPLIANT'} | Violations: {violations_count} | Evaluated in: {exec_time} ms")
        for v in violations:
            print(f"  - [{v.get('severity')}] {v.get('resource_id')}: {v.get('reason')}")

    # 2. Run simulation in sandbox
    if HAS_RICH:
        console.print("\n[bold yellow]🧪 Running In-Memory Moto Sandbox Simulation...[/bold yellow]")
    else:
        print("\nRunning In-Memory Moto Sandbox Simulation...")

    content = file_path.read_text(encoding="utf-8")
    raw_sim = simulate_in_sandbox(content)
    sim_data = json.loads(raw_sim)

    sim_success = sim_data.get("success", False)
    sim_resources = sim_data.get("simulated_resources", [])
    savings = sim_data.get("cost_savings_monthly", 0.0)

    if HAS_RICH:
        sim_status = "[bold green]PASSED[/bold green]" if sim_success else "[bold red]FAILED[/bold red]"
        console.print(f"Simulation Status: {sim_status} | Synthesized Resources: [bold]{len(sim_resources)}[/bold]")
        if savings > 0:
            console.print(f"[bold green]💰 Projected Monthly FinOps Savings: ${savings:.2f}/month (${savings * 12:.2f}/year)[/bold green]")
        console.print(Panel(sim_data.get("diagnostics", "No diagnostics available"), title="Sandbox Diagnostics", border_style="blue"))
    else:
        print(f"Simulation Status: {'PASSED' if sim_success else 'FAILED'} | Synthesized Resources: {len(sim_resources)}")
        if savings > 0:
            print(f"Projected Monthly FinOps Savings: ${savings:.2f}/month")
        print("Diagnostics:\n" + sim_data.get("diagnostics", ""))


def main():
    print_banner()

    target = "examples/vulnerable.json"
    if len(sys.argv) > 1:
        target = sys.argv[1]

    run_demo(target)


if __name__ == "__main__":
    main()
