"""
CloudSec-Copilot CLI Interface
"""

import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloudsec_copilot.ai.ai_reasoner import AIReasoner
from cloudsec_copilot.discovery.collector import DiscoveryCollector
from cloudsec_copilot.executor.executor import Executor
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.verifier.verifier import Verifier

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="cloudsec")
def cli():
    """CloudSec-Copilot: Agentic Cloud Security Posture & Verified Remediation Framework"""
    pass


@cli.command()
@click.option("--discover-only", is_flag=True, help="Run infrastructure discovery only without scanning rules.")
@click.option("--endpoint-url", default=None, help="Custom AWS/LocalStack API endpoint URL.")
@click.option("--output", default="infra_state.json", help="Output file for discovery snapshot.")
def scan(discover_only, endpoint_url, output):
    """Run cloud infrastructure discovery, vulnerability scan, and attack graph risk analysis."""
    console.print(Panel.fit("[bold blue]CloudSec-Copilot[/bold blue] - Cloud Security Posture Scan", border_style="blue"))

    collector = DiscoveryCollector(endpoint_url=endpoint_url)

    if discover_only:
        console.print("[yellow][*] Running Cloud Discovery Engine...[/yellow]")
        snapshot = collector.export_snapshot(output_path=output)
        console.print(f"[green][+] Infrastructure inventory captured successfully -> {output}[/green]")
        console.print(f"    S3 Buckets: {len(snapshot.resources.s3_buckets)}")
        console.print(f"    Security Groups: {len(snapshot.resources.security_groups)}")
        console.print(f"    IAM Roles: {len(snapshot.resources.iam_roles)}")
        console.print(f"    RDS Instances: {len(snapshot.resources.rds_instances)}")
        return

    console.print("[bold yellow][*] Phase 1: Capturing Infrastructure Snapshot...[/bold yellow]")
    snapshot = collector.collect_all()

    if not snapshot.resources.s3_buckets and not snapshot.resources.security_groups and not snapshot.resources.iam_roles and not snapshot.resources.rds_instances and not snapshot.resources.ec2_instances:
        console.print("[bold red]No live cloud resources were discovered.[/bold red]")
        console.print("[yellow]Start LocalStack with: docker compose up -d[/yellow]")
        console.print("[yellow]Then run the vulnerable lab setup: python scripts/setup_vulnerable_lab.py[/yellow]")
        return

    console.print("[bold yellow][*] Phase 2: Running Deterministic Security Rules...[/bold yellow]")
    findings = Scanner().scan(snapshot)
    if not findings:
        console.print("[green][+] No active security findings were detected in the live inventory.[/green]")
        return

    console.print("[bold yellow][*] Phase 3: Constructing Attack Dependency Graph...[/bold yellow]")
    graph = CloudGraphBuilder().build(snapshot)
    risk_report = RiskEngine().prioritize(findings, graph)

    table = Table(title="Security Findings Summary")
    table.add_column("Vuln ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold red")
    table.add_column("Resource", style="magenta")
    table.add_column("Risk Score", style="bold yellow")
    table.add_column("Description", style="white")

    for item in risk_report["prioritized_findings"]:
        match = next((f for f in findings if f["id"] == item["vuln_id"]), None)
        if not match:
            continue
        table.add_row(match["id"], match["severity"], match["resource_id"], f"{item['composite_score']}/10", match["title"])

    console.print(table)
    console.print("\n[bold green]To remediate a finding, run:[/bold green] [cyan]cloudsec fix --id <VULN_ID>[/cyan]\n")


@cli.command()
@click.option("--id", "vuln_id", required=True, help="Vulnerability ID to remediate (e.g. VULN-001).")
@click.option("--yes", "-y", is_flag=True, help="Skip interactive approval prompt.")
def fix(vuln_id, yes):
    """Generate a validated remediation plan, request approval, execute it, and rescan."""
    console.print(Panel.fit(f"[bold red]Remediation Workflow[/bold red] - Finding: [cyan]{vuln_id}[/cyan]", border_style="red"))
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    finding = next((item for item in findings if item["id"] == vuln_id), None)
    if not finding:
        console.print(f"[bold red]Finding {vuln_id} was not found in the current inventory.[/bold red]")
        return

    risk_report = RiskEngine().prioritize(findings, CloudGraphBuilder().build(snapshot))
    score = next((item["composite_score"] for item in risk_report["prioritized_findings"] if item["vuln_id"] == vuln_id), 5.0)
    reasoning = AIReasoner().reason(finding, score, risk_report["attack_graph_summary"])
    plan = RemediationPlanner().plan(finding["rule_id"], finding["resource_id"], dry_run=False)
    if reasoning.get("action"):
        plan["action"] = reasoning["action"]

    console.print("[yellow][*] Generating AI Contextual Analysis & Remediation Plan...[/yellow]")
    console.print(f"[bold white]AI Provider:[/bold white] {reasoning.get('provider', 'fallback')}")
    console.print(f"[bold white]Reasoning Summary:[/bold white] {reasoning['summary']}")
    console.print(f"[bold white]Proposed Action:[/bold white] {plan['action']['action']} -> {plan['action']['resource_id']}")
    console.print(f"[bold white]Rollback Plan:[/bold white] {plan['rollback']['action']}")

    if not yes and not click.confirm("Do you approve executing this cloud remediation action?"):
        console.print("[bold red]Action cancelled by user.[/bold red]")
        return

    console.print("[bold yellow][*] Executing Cloud Mutation via Boto3...[/bold yellow]")
    result = Executor().execute(plan, finding, approved=True)
    if result["status"] != "APPLIED":
        console.print(f"[bold red]Execution failed: {result.get('reason')}[/bold red]")
        return

    after_snapshot = collector.collect_all()
    after_findings = Scanner().scan(after_snapshot)
    verification = Verifier().verify_finding_removed([finding], after_findings, vuln_id)

    console.print(f"[bold green][+] Fix applied successfully: {result['status']}[/bold green]")
    console.print("[bold yellow][*] Running Post-Remediation Verification Rescan...[/bold yellow]")
    status_text = "VERIFIED/RESOLVED" if verification["status"] == "VERIFIED" else verification["status"]
    console.print(f"[bold green][✓] {vuln_id} -> {status_text}[/bold green]")
    console.print(f"[bold green][✓] Verification Result: {verification['status']}[/bold green]")


@cli.command()
def verify():
    """Verify that the current inventory is free from previously known remediations."""
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    console.print("[bold blue][*] Running Verification Rescan Engine...[/bold blue]")
    if not findings:
        console.print("[green][✓] All remediated assets verified secure. Zero regressions detected.[/green]")
        return
    console.print(f"[yellow]Current findings remaining: {len(findings)}[/yellow]")
    for finding in findings:
        console.print(f"  - {finding['id']} -> {finding['resource_id']} ({finding['severity']})")


@cli.command()
@click.option("--format", "report_format", type=click.Choice(["json", "markdown", "html"]), default="json", help="Output format.")
@click.option("--output", default="scan_report.json", help="Output file path.")
def report(report_format, output):
    """Export scan results and audit trail."""
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    payload = {"title": "CloudSec-Copilot Security Audit Report", "version": "0.1.0", "status": "COMPLETED", "summary": {"total_findings": len(findings), "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"), "high": sum(1 for f in findings if f["severity"] == "HIGH")}, "findings": findings}
    console.print(f"[bold blue][*] Exporting report in {report_format.upper()} format to {output}...[/bold blue]")
    with open(output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    console.print(f"[bold green][+] Report exported successfully to {output}[/bold green]")

if __name__ == "__main__":
    cli()
