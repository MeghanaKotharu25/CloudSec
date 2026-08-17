import json
from pathlib import Path

from cloudsec_copilot.ai.ai_reasoner import AIReasoner
from cloudsec_copilot.discovery.collector import DiscoveryCollector
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.executor.executor import Executor
from cloudsec_copilot.verifier.verifier import Verifier


def build_inventory():
    collector = DiscoveryCollector(endpoint_url="http://localhost:4566")
    state = collector.collect_all()
    return state


def test_demo_pipeline_end_to_end(tmp_path):
    inventory = build_inventory()
    findings = Scanner().scan(inventory)
    assert len(findings) >= 5

    graph = CloudGraphBuilder().build(inventory)
    risk_report = RiskEngine().prioritize(findings, graph)
    assert risk_report["prioritized_findings"]

    ai_out = AIReasoner().reason(findings[0], 9.7, {"entry_points": ["EC2:i-123"]})
    assert set(ai_out.keys()) == {"summary", "impact", "steps", "aws_cli", "rollback"}

    plan = RemediationPlanner().plan(findings[0]["rule_id"], findings[0]["resource_id"], dry_run=True)
    assert plan["dry_run"] is True

    audit_path = tmp_path / "audit_log.json"
    executor = Executor(audit_path=str(audit_path))
    result = executor.execute(plan, findings[0], approved=True)
    assert result["status"] == "APPLIED"
    assert audit_path.exists()

    verification = Verifier().compare(findings, [])
    assert verification["remediation_required"] is True
    assert verification["status"] == "SUCCESS"

    payload = json.loads(audit_path.read_text())
    assert payload[-1]["status"] == "APPLIED"
