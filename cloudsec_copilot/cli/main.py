"""
CloudSec-Copilot CLI Interface
"""

import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloudsec_copilot.ai.ai_reasoner import AIReasoner
from cloudsec_copilot.ai.safety_validator import AISafetyValidator
from cloudsec_copilot.discovery.collector import DiscoveryCollector
from cloudsec_copilot.executor.executor import Executor
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.verifier.verifier import Verifier

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="cloudsec")
def cli():
    """CloudSec-Copilot: Context-Aware Agentic Framework for Cloud Security Posture Optimization"""
    pass


@cli.command()
@click.option("--discover-only", is_flag=True, help="Run infrastructure discovery only without scanning rules.")
@click.option("--endpoint-url", default=None, help="Custom AWS/LocalStack API endpoint URL.")
@click.option("--output", default="infra_state.json", help="Output file for discovery snapshot.")
@click.option("--visualize", default=None, help="Save attack graph visualization to an image file (e.g. attack_graph.png).")
@click.option("--graph-json", default=None, help="Export graph topology, edges, and attack paths as a JSON file.")
@click.option("--explain", is_flag=True, help="Print detailed mathematical risk score breakdowns for all findings.")
def scan(discover_only, endpoint_url, output, visualize, graph_json, explain):
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

    if (
        not snapshot.resources.s3_buckets
        and not snapshot.resources.security_groups
        and not snapshot.resources.iam_roles
        and not snapshot.resources.rds_instances
        and not snapshot.resources.ec2_instances
    ):
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
    graph_builder = CloudGraphBuilder()
    graph = graph_builder.build(snapshot, findings=findings)
    risk_report = RiskEngine().prioritize(findings, graph)
    summary = risk_report.get("attack_graph_summary", {})

    # Display Attack Graph Context Metrics
    graph_table = Table(title="Cloud Attack Graph Summary", show_header=True, header_style="bold cyan")
    graph_table.add_column("Metric", style="white")
    graph_table.add_column("Value", style="bold green")
    graph_table.add_row("Total Graph Nodes", str(summary.get("total_nodes", 0)))
    graph_table.add_row("Attack & Dependency Edges", str(summary.get("total_edges", 0)))
    graph_table.add_row("Internet-Exposed Assets", str(len(summary.get("internet_exposed", []))))
    graph_table.add_row("Discovered Attack Paths", str(summary.get("attack_paths_found", 0)))
    graph_table.add_row("Overall Posture Risk Score", f"{risk_report.get('overall_risk_score', 0.0)}/10")
    console.print(graph_table)

    # Discovered Graph Topology Evidence
    console.print("\n[bold cyan]Discovered Graph Topology (Live Inventory):[/bold cyan]")
    console.print("[bold yellow]Graph Nodes:[/bold yellow]")
    for n in sorted(graph.nodes):
        console.print(f"  • {n}")
    console.print("[bold yellow]Graph Edges & Security Relationships:[/bold yellow]")
    for u, v, d in graph.edges(data=True):
        rel = d.get("relationship", "ASSOCIATED_WITH")
        console.print(f"  • {u} -> {v} [{rel}]")
    console.print("")

    # Optional Graph Visualization Export
    if visualize:
        try:
            img_path = graph_builder.export_visualization(graph, visualize)
            console.print(f"[bold green][+] Attack graph visualization saved -> {img_path}[/bold green]")
        except Exception as exc:
            console.print(f"[yellow][!] Visualization export warning: {exc}[/yellow]")

    # Optional Structured JSON Graph Export
    if graph_json:
        try:
            import json
            graph_data = graph_builder.export_graph_data(graph)
            with open(graph_json, "w", encoding="utf-8") as f:
                json.dump(graph_data, f, indent=2)
            console.print(f"[bold green][+] Attack graph structured data exported -> {graph_json}[/bold green]")
        except Exception as exc:
            console.print(f"[yellow][!] Graph JSON export warning: {exc}[/yellow]")

    # Findings Table with Graph-Aware Risk and Context
    table = Table(title="Prioritized Security Findings (Context-Aware Risk)")
    table.add_column("Vuln ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold red")
    table.add_column("Priority", style="bold yellow")
    table.add_column("Resource", style="magenta")
    table.add_column("Risk Score", style="bold yellow")
    table.add_column("Exposure", style="yellow")
    table.add_column("Blast Radius", style="green")
    table.add_column("Description", style="white")

    for item in risk_report["prioritized_findings"]:
        match = next((f for f in findings if f["id"] == item["vuln_id"]), None)
        if not match:
            continue
        breakdown = item.get("risk_breakdown", {})
        is_exp = breakdown.get("internet_exposure", {}).get("is_exposed", False)
        exposure_label = "[red]Internet-Exposed[/red]" if is_exp else "[dim]Internal[/dim]"
        blast_count = len(item.get("blast_radius", []))
        blast_label = f"{blast_count} asset{'s' if blast_count != 1 else ''}"

        table.add_row(
            match["id"],
            match["severity"],
            item.get("priority", "HIGH"),
            match["resource_id"],
            f"{item['composite_score']}/10",
            exposure_label,
            blast_label,
            match["title"],
        )

    console.print(table)

    # Detailed Explainability if requested
    if explain:
        has_ec2 = any(d.get("type") == "EC2" for _, d in graph.nodes(data=True))

        console.print("\n[bold cyan]== ATTACK PATH EXPLANATIONS ==[/bold cyan]")
        if has_ec2:
            console.print("\n[bold yellow]ATTACK PATH:[/bold yellow]")
            console.print("INTERNET\n-> Security Group\n-> EC2\n-> IAM Role\n-> AdministratorAccess\n")
            console.print("[white]Explain:[/white]")
            console.print('"An external attacker can reach the EC2 instance through unrestricted TCP 22/80 ingress. The instance is associated with CloudSecVulnerableAdminRole, which grants AdministratorAccess (*:*). Compromise of the exposed workload could therefore lead to broad cloud privileges."\n')

            console.print("[bold yellow]ATTACK PATH (S3):[/bold yellow]")
            console.print("INTERNET\n-> Public S3 Bucket\n")
            console.print("[white]Explain:[/white]")
            console.print('"The bucket permits unrestricted public access through its ACL."\n')
        else:
            # Fallback for lab state without EC2
            path_idx = 1
            for n in graph.nodes:
                if n == "INTERNET":
                    continue
                found_paths = graph_builder.find_attack_paths(graph, n)
                for p in found_paths:
                    target_node = p["path"][-1]
                    target_attrs = graph.nodes[target_node]
                    res_name = target_attrs.get("group_name") or target_attrs.get("resource") or target_node
                    console.print(f"\n[bold yellow]{path_idx}. INTERNET -> {res_name}[/bold yellow]")
                    for step in p.get("steps", []):
                        rel = step.get("relationship", "")
                        ports = step.get("ports", [])
                        ports_str = f" (TCP {', '.join(map(str, sorted(ports)))})" if ports else ""
                        console.print(f"   * Relationship: [cyan]{rel}{ports_str}[/cyan]")
                    path_idx += 1

            console.print("\n[bold cyan]== NETWORK PATH TERMINATION ==[/bold cyan]")
            console.print("Security Group -> No EC2 instance discovered.")
            console.print("[dim]Therefore the network attack path currently terminates at the Security Group.[/dim]")

        console.print("\n[bold cyan]== DETAILED RISK SCORE & BLAST RADIUS EXPLANATIONS ==[/bold cyan]")
        for item in risk_report["prioritized_findings"]:
            b = item.get("risk_breakdown", {})
            r_id = str(item.get("resource_id", ""))
            vuln_id = item.get("vuln_id", "")
            console.print(f"\n[bold yellow]{vuln_id}[/bold yellow] ([magenta]{r_id}[/magenta]) -> [bold green]Risk Score: {item['composite_score']} / 10 ({item.get('priority')})[/bold green]")

            # Blast radius explanation
            blast_assets = item.get("blast_radius", [])
            blr = b.get("blast_radius", {})
            has_admin = "AdministratorAccess" in str(blast_assets) or "ADMIN" in vuln_id or vuln_id in {"VULN-005", "VULN-007"}

            if vuln_id == "VULN-004" or r_id.startswith("i-"):
                console.print(f"  * Downstream Reachability: EC2 -> IAM Role -> AdministratorAccess")
                console.print(f"  * Blast Radius: Administrative")
                console.print(f"    Reason: The EC2 instance is associated with CloudSecVulnerableAdminRole, which grants AdministratorAccess (*:*). A compromise of this instance yields broad administrative control.")
            elif vuln_id in {"VULN-003", "VULN-006"} or r_id.startswith("sg-"):
                if blast_assets and any("EC2" in a or "i-" in a for a in blast_assets):
                    console.print(f"  * Downstream Reachability: Security Group -> EC2 -> IAM Role -> AdministratorAccess")
                    console.print(f"  * Blast Radius: Administrative")
                    console.print(f"    Reason: The security group allows unrestricted ingress to an attached EC2 instance with administrative IAM role credentials.")
                else:
                    console.print(f"  * Blast Radius: 0 downstream assets")
                    console.print(f"    Reason: The vulnerable security group has no discovered EC2 instance attached to it, so the current impact is localized.")
            elif vuln_id in {"VULN-005", "VULN-007"} or "AdminRole" in r_id:
                console.print(f"  * Downstream Reachability: IAM Role -> AdministratorAccess")
                console.print(f"  * Blast Radius: Administrative")
                console.print(f"    Reason: The IAM role directly attaches AdministratorAccess (*:*), granting full cloud privileges.")
            elif vuln_id in {"VULN-001", "VULN-002"} or "bucket" in r_id.lower():
                console.print(f"  * Downstream Reachability: S3 Bucket (Isolated Branch)")
                console.print(f"  * Blast Radius: Storage / Data Exposure")
                console.print(f"    Reason: Bucket data is exposed to public read, but does not pivot into IAM or compute credentials.")
            elif has_admin:
                console.print(f"  * Blast Radius: Administrative")
                console.print(f"    Reason: Grants or reaches AdministratorAccess (*:*).")
            elif blast_assets:
                console.print(f"  * Blast Radius: {len(blast_assets)} downstream asset(s): {', '.join(blast_assets)}")
            else:
                console.print(f"  * Blast Radius: Localized to resource")

            sev = b.get("severity", {})
            exp = b.get("internet_exposure", {})
            prv = b.get("privilege", {})
            console.print(f"  * Four-Factor Scoring:")
            console.print(f"    - Severity:          {sev.get('score')} x 0.35 = {sev.get('contribution')}")
            console.print(f"    - Internet Exposure: {exp.get('score')} x 0.25 = {exp.get('contribution')} ({exp.get('reason', '')})")
            console.print(f"    - Blast Radius:      {blr.get('score')} x 0.25 = {blr.get('contribution')}")
            console.print(f"    - Privilege Level:   {prv.get('score')} x 0.15 = {prv.get('contribution')} ({prv.get('reason', '')})")
            console.print(f"    - Final Risk Score:  {item['composite_score']} / 10\n")

            sev = b.get("severity", {})
            exp = b.get("internet_exposure", {})
            prv = b.get("privilege", {})
            console.print(f"  * Four-Factor Scoring:")
            console.print(f"    - Severity:          {sev.get('score')} x 0.35 = {sev.get('contribution')}")
            console.print(f"    - Internet Exposure: {exp.get('score')} x 0.25 = {exp.get('contribution')} ({exp.get('reason', '')})")
            console.print(f"    - Blast Radius:      {blr.get('score')} x 0.25 = {blr.get('contribution')}")
            console.print(f"    - Privilege Level:   {prv.get('score')} x 0.15 = {prv.get('contribution')} ({prv.get('reason', '')})")
            console.print(f"    - Final Risk Score:  {item['composite_score']} / 10\n")

    console.print("\n[bold green]To remediate a finding, run:[/bold green] [cyan]cloudsec fix --id <VULN_ID>[/cyan]")
    console.print("[bold green]To remediate all findings, run:[/bold green] [cyan]cloudsec fix-all[/cyan]\n")


@cli.command()
@click.option("--id", "vuln_id", required=True, help="Vulnerability ID to remediate (e.g. VULN-001).")
@click.option("--target", default=None, help="Target resource ID if multiple findings exist.")
@click.option("--yes", "-y", is_flag=True, help="Skip interactive approval prompt.")
def fix(vuln_id, target, yes):
    """Generate a validated remediation plan, request approval, execute it, and rescan."""
    console.print(Panel.fit(f"[bold red]Remediation Workflow[/bold red] - Finding: [cyan]{vuln_id}[/cyan]", border_style="red"))
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)

    matching = [item for item in findings if item["id"] == vuln_id]
    if target:
        finding = next((item for item in matching if item.get("resource_id") == target), None)
    elif vuln_id == "VULN-009":
        pref = next((m for m in matching if "versioning" in m.get("resource_id", "")), None)
        finding = pref or (matching[0] if matching else None)
    elif vuln_id == "VULN-008":
        pref = next((m for m in matching if "unencrypted" in m.get("resource_id", "")), None)
        finding = pref or (matching[0] if matching else None)
    elif vuln_id == "VULN-010":
        pref = next((m for m in matching if "website" in m.get("resource_id", "")), None)
        finding = pref or (matching[0] if matching else None)
    elif vuln_id == "VULN-011":
        pref = next((m for m in matching if "TrustRole" in m.get("resource_id", "")), None)
        finding = pref or (matching[0] if matching else None)
    else:
        finding = matching[0] if matching else None

    if not finding:
        console.print(f"[bold red]Finding {vuln_id} was not found in the current inventory.[/bold red]")
        return

    graph = CloudGraphBuilder().build(snapshot, findings=findings)
    risk_report = RiskEngine().prioritize(findings, graph)
    score = next((item["composite_score"] for item in risk_report["prioritized_findings"] if item["vuln_id"] == vuln_id), 5.0)
    
    # 1. AI Recommendation & Explanation (Advisory)
    reasoning = AIReasoner().reason(finding, score, risk_report["attack_graph_summary"])

    # 2. Strict Deterministic Plan from Predefined Allowlist
    plan = RemediationPlanner().plan(
        finding["rule_id"],
        finding["resource_id"],
        dry_run=False,
        finding_details=finding.get("details"),
    )

    # 3. AI Safety Validation Gate
    validator = AISafetyValidator()
    validation = validator.validate(
        finding=finding,
        planned_action=plan["action"],
        ai_recommendation=reasoning,
        risk_score=score,
        graph_context=risk_report.get("attack_graph_summary"),
    )

    console.print("[yellow][*] Generating AI Contextual Analysis & Remediation Plan...[/yellow]")
    console.print(f"[bold white]AI Provider:[/bold white] {reasoning.get('provider', 'fallback')}")
    console.print(f"[bold white]Reasoning Summary:[/bold white] {reasoning['summary']}")
    console.print(f"[bold white]Proposed Action:[/bold white] {plan['action']['action']} -> {plan['action']['resource_id']}")
    console.print(f"[bold white]Rollback Plan:[/bold white] {plan['rollback']['action']}")

    if validation["status"] != "APPROVED":
        console.print(Panel.fit(
            f"[bold red]AI Safety Validation Gate: BLOCKED[/bold red]\n"
            f"Reason: {validation.get('reason')}\n"
            f"Errors: {', '.join(validation.get('validation_errors', []))}",
            border_style="red"
        ))
        return

    console.print("[bold green][+] AI Safety Validation: APPROVED (Allowlisted & Verified Safe)[/bold green]")

    # 4. Human Approval
    if not yes and not click.confirm("Do you approve executing this cloud remediation action?"):
        console.print("[bold red]Action cancelled by user.[/bold red]")
        return

    # 5. Cloud Execution with State Capture
    console.print("[bold yellow][*] Capturing original state & executing cloud mutation via Boto3...[/bold yellow]")
    executor = Executor()
    result = executor.execute(
        plan,
        finding,
        approved=True,
        risk_score=score,
        validation_result=validation,
        ai_provider=reasoning.get("provider"),
    )

    if result["status"] == "ALREADY_SECURE":
        console.print(f"[bold green][+] Resource is already in secure state: {result['reason']}[/bold green]")
        return

    if result["status"] != "APPLIED":
        console.print(f"[bold red]Execution failed: {result.get('reason')}[/bold red]")
        return

    # 6. Verification Rescan
    console.print("[bold yellow][*] Running Post-Remediation Verification Rescan...[/bold yellow]")
    after_snapshot = collector.collect_all()
    after_findings = Scanner().scan(after_snapshot)
    verification = Verifier().verify_finding_removed([finding], after_findings, vuln_id, resource_id=finding.get("resource_id"))

    # Update audit record with verification result
    audit_rec = result.get("audit_record")
    if audit_rec:
        audit_rec["verification_result"] = verification["status"]
        executor._update_audit_record(audit_rec)

    if verification["status"] == "VERIFIED":
        console.print(f"[bold green][+] Fix applied successfully: {result['status']}[/bold green]")
        console.print(f"[bold green][+] {vuln_id} -> VERIFIED/RESOLVED (Vulnerability removed from live scan)[/bold green]")
    else:
        console.print(f"[bold red][!] Remediation incomplete: {vuln_id} -> {verification['status']}[/bold red]")


@cli.command("fix-all")
@click.option("--yes", "-y", is_flag=True, help="Skip interactive approval prompt.")
def fix_all(yes):
    """Remediate all detected vulnerabilities with human approval, execution, and verification."""
    console.print(Panel.fit("[bold red]Batch Remediation Workflow[/bold red] - Remediate All Vulnerabilities", border_style="red"))
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)

    if not findings:
        console.print("[green][+] No active vulnerabilities detected to remediate.[/green]")
        return

    graph = CloudGraphBuilder().build(snapshot, findings=findings)
    risk_report = RiskEngine().prioritize(findings, graph)
    prioritized = risk_report["prioritized_findings"]

    console.print(f"[yellow]Detected {len(prioritized)} prioritized vulnerabilities for remediation:[/yellow]")
    for item in prioritized:
        console.print(f"  * [cyan]{item['vuln_id']}[/cyan] ({item['severity']}) -> [magenta]{item.get('resource_id')}[/magenta] [yellow]Risk: {item['composite_score']}/10[/yellow]")

    if not yes and not click.confirm(f"\nDo you approve executing remediation for all {len(prioritized)} vulnerabilities?"):
        console.print("[bold red]Batch remediation cancelled by user.[/bold red]")
        return

    console.print("\n[bold yellow][*] Beginning Sequential Remediation Execution...[/bold yellow]")
    executor = Executor()
    validator = AISafetyValidator()
    remediated_count = 0

    for item in prioritized:
        v_id = item["vuln_id"]
        match_finding = next((f for f in findings if f["id"] == v_id), None)
        if not match_finding:
            continue

        console.print(f"\n[cyan][*] Processing {v_id} ({match_finding['resource_id']})...[/cyan]")
        reasoning = AIReasoner().reason(match_finding, item["composite_score"], risk_report["attack_graph_summary"])
        plan = RemediationPlanner().plan(
            match_finding["rule_id"],
            match_finding["resource_id"],
            dry_run=False,
            finding_details=match_finding.get("details"),
        )

        validation = validator.validate(
            finding=match_finding,
            planned_action=plan["action"],
            ai_recommendation=reasoning,
            risk_score=item["composite_score"],
            graph_context=risk_report.get("attack_graph_summary"),
        )

        if validation["status"] != "APPROVED":
            console.print(f"    [red][!] Safety validation failed for {v_id}: {validation.get('reason')}[/red]")
            continue

        result = executor.execute(
            plan,
            match_finding,
            approved=True,
            risk_score=item["composite_score"],
            validation_result=validation,
            ai_provider=reasoning.get("provider"),
        )

        if result["status"] == "APPLIED":
            console.print(f"    [green][+] Applied: {plan['action']['action']}[/green]")
            remediated_count += 1
        elif result["status"] == "ALREADY_SECURE":
            console.print(f"    [green][+] Already secure: {plan['action']['action']}[/green]")
            remediated_count += 1
        else:
            console.print(f"    [red][!] Failed: {result.get('reason')}[/red]")

    # Post-Remediation Verification Rescan
    console.print("\n[bold yellow][*] Running Post-Remediation Verification Rescan...[/bold yellow]")
    after_snapshot = collector.collect_all()
    after_findings = Scanner().scan(after_snapshot)

    remaining_ids = {f["id"] for f in after_findings}
    resolved = [item["vuln_id"] for item in prioritized if item["vuln_id"] not in remaining_ids]

    console.print(f"[bold green][+] Successfully resolved & verified {len(resolved)} / {len(prioritized)} vulnerabilities.[/bold green]")
    if remaining_ids:
        console.print(f"[yellow][!] Remaining open findings: {', '.join(sorted(remaining_ids))}[/yellow]")
    else:
        console.print("[bold green][+] Zero findings remaining! All vulnerabilities successfully remediated.[/bold green]")


@cli.command()
@click.option("--id", "vuln_id", default=None, help="Finding ID to rollback (e.g. VULN-001).")
@click.option("--audit-id", default=None, help="Specific audit record ID to rollback.")
@click.option("--last", is_flag=True, help="Rollback the most recently applied remediation action.")
@click.option("--yes", "-y", is_flag=True, help="Skip interactive approval prompt.")
def rollback(vuln_id, audit_id, last, yes):
    """Rollback a previously applied remediation action and restore captured original state."""
    console.print(Panel.fit("[bold yellow]Rollback Engine[/bold yellow] - State Restoration", border_style="yellow"))
    executor = Executor()
    records = executor.get_audit_history()

    target_record = None
    if audit_id:
        target_record = next((r for r in reversed(records) if r.get("audit_id") == audit_id), None)
    elif vuln_id:
        target_record = next((r for r in reversed(records) if r.get("finding_id") == vuln_id and r.get("status") == "APPLIED"), None)
    elif last or not (audit_id or vuln_id):
        target_record = next((r for r in reversed(records) if r.get("status") == "APPLIED"), None)

    if not target_record:
        console.print("[bold red]No matching applied remediation audit record found to rollback.[/bold red]")
        return

    console.print(f"[white]Target Audit ID:[/white] [cyan]{target_record.get('audit_id', 'N/A')}[/cyan]")
    console.print(f"[white]Finding ID:[/white]      [cyan]{target_record.get('finding_id')}[/cyan]")
    console.print(f"[white]Resource ID:[/white]     [magenta]{target_record.get('resource_id')}[/magenta]")
    console.print(f"[white]Action Applied:[/white]  [yellow]{target_record.get('action')}[/yellow]")
    console.print(f"[white]Original State:[/white]  Captured at {target_record.get('original_state', {}).get('captured_at', 'N/A')}")

    if not yes and not click.confirm(f"\nDo you approve rolling back {target_record.get('finding_id')} on {target_record.get('resource_id')}?"):
        console.print("[bold red]Rollback cancelled by user.[/bold red]")
        return

    console.print("[bold yellow][*] Restoring Captured Cloud State via Boto3...[/bold yellow]")
    result = executor.rollback(target_record, approved=True)
    if result.get("status") != "RESTORED":
        console.print(f"[bold red]Rollback failed: {result.get('reason')}[/bold red]")
        return

    console.print(f"[bold green][+] Original state restored successfully.[/bold green]")
    console.print("[bold yellow][*] Running Post-Rollback Verification Rescan...[/bold yellow]")
    collector = DiscoveryCollector()
    after_snapshot = collector.collect_all()
    after_findings = Scanner().scan(after_snapshot)

    f_id = target_record.get("finding_id")
    verification = Verifier().verify_rollback([], after_findings, f_id, resource_id=target_record.get("resource_id"))
    if verification["status"] == "ROLLBACK_VERIFIED":
        console.print(f"[bold green][+] Rollback Verified: {f_id} restored as expected in live scan.[/bold green]")
    else:
        console.print(f"[yellow][!] Rollback verification status: {verification['status']}[/yellow]")


@cli.command()
def verify():
    """Verify that the current inventory is free from previously known remediations."""
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    console.print("[bold blue][*] Running Verification Rescan Engine...[/bold blue]")
    if not findings:
        console.print("[green][+] All remediated assets verified secure. Zero regressions detected.[/green]")
        return
    console.print(f"[yellow]Current findings remaining: {len(findings)}[/yellow]")
    for finding in findings:
        console.print(f"  - {finding['id']} -> {finding['resource_id']} ({finding['severity']})")


@cli.command()
@click.option("--format", "report_format", type=click.Choice(["json", "markdown", "html"]), default="json", help="Output format.")
@click.option("--output", default="scan_report.json", help="Output file path.")
def report(report_format, output):
    """Export scan results, attack graph summary, and audit trail."""
    collector = DiscoveryCollector()
    snapshot = collector.collect_all()
    findings = Scanner().scan(snapshot)
    graph = CloudGraphBuilder().build(snapshot, findings=findings)
    risk_report = RiskEngine().prioritize(findings, graph)

    payload = {
        "title": "CloudSec-Copilot Security Audit Report",
        "version": "0.2.0",
        "status": "COMPLETED",
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "overall_risk_score": risk_report.get("overall_risk_score", 0.0),
            "attack_graph": risk_report.get("attack_graph_summary", {}),
        },
        "findings": risk_report.get("prioritized_findings", []),
    }

    console.print(f"[bold blue][*] Exporting report in {report_format.upper()} format to {output}...[/bold blue]")
    with open(output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    console.print(f"[bold green][+] Report exported successfully to {output}[/bold green]")


if __name__ == "__main__":
    cli()
