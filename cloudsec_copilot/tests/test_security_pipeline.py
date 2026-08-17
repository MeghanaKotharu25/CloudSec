import json
from unittest.mock import MagicMock, patch

from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    ResourceInventoryModel,
    S3BucketModel,
    SecurityGroupModel,
    InboundRuleModel,
    IAMRoleModel,
    RDSInstanceModel,
    EC2InstanceModel,
)
from cloudsec_copilot.scanner.scanner import Scanner
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.ai.ai_reasoner import AIReasoner
from cloudsec_copilot.remediation.remediation import RemediationPlanner
from cloudsec_copilot.verifier.verifier import Verifier


def build_sample_inventory():
    return InfrastructureStateModel(
        account_id="123456789012",
        region="us-east-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="public-data-bucket",
                    is_public=True,
                    acl_public=True,
                    encryption_enabled=False,
                    arn="arn:aws:s3:::public-data-bucket",
                )
            ],
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-open-1",
                    group_name="allow-world",
                    description="Open ingress",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                        InboundRuleModel(protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0"),
                    ],
                )
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="admin-role",
                    arn="arn:aws:iam::123456789012:role/admin-role",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                )
            ],
            rds_instances=[],
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-123",
                    instance_type="t3.micro",
                    state="running",
                    public_ip="54.1.1.1",
                    private_ip="10.0.0.10",
                    security_groups=["sg-open-1"],
                    iam_instance_profile="admin-role",
                )
            ],
        ),
    )


def test_scanner_detects_known_vulnerabilities():
    inventory = build_sample_inventory()
    findings = Scanner().scan(inventory)

    rules = {finding["rule_id"] for finding in findings}
    assert {"RULE-S3-PUBLIC", "RULE-S3-NO-ENCRYPTION", "RULE-SG-OPEN", "RULE-IAM-ADMIN"} <= rules
    assert len(findings) >= 4


def test_graph_builder_builds_expected_dependency_chain():
    inventory = build_sample_inventory()
    graph = CloudGraphBuilder().build(inventory)

    assert "EC2:i-123" in graph.nodes
    assert "IAM:admin-role" in graph.nodes
    assert "S3:public-data-bucket" in graph.nodes
    assert "POLICY:AdministratorAccess" in graph.nodes
    assert graph.has_edge("EC2:i-123", "IAM:admin-role")
    assert graph.has_edge("IAM:admin-role", "POLICY:AdministratorAccess")
    assert graph.has_edge("EC2:i-123", "SG:sg-open-1")
    assert not graph.has_edge("IAM:admin-role", "S3:public-data-bucket")
    assert not any(node.startswith("RDS:") for node in graph.nodes)
    assert not any(graph.has_edge("SG:sg-open-1", node) for node in graph.nodes if node.startswith("RDS:"))


def test_risk_engine_prioritizes_high_blast_radius():
    inventory = build_sample_inventory()
    findings = Scanner().scan(inventory)
    graph = CloudGraphBuilder().build(inventory)

    risk_report = RiskEngine().prioritize(findings, graph)

    assert "overall_risk_score" in risk_report
    assert len(risk_report["prioritized_findings"]) >= 4
    assert risk_report["prioritized_findings"][0]["composite_score"] >= 0
    assert risk_report["prioritized_findings"][0]["blast_radius"]


def test_scanner_exports_json_report(tmp_path):
    inventory = build_sample_inventory()
    output_path = tmp_path / "vulnerabilities.json"

    report = Scanner().export_report(inventory, output_path=str(output_path))

    assert output_path.exists()
    payload = json.loads(output_path.read_text())
    assert "findings" in payload
    assert payload["findings"]


def test_ai_reasoner_generates_structured_plan():
    finding = {
        "id": "VULN-001",
        "title": "Public S3 bucket exposure",
        "severity": "CRITICAL",
        "resource_id": "public-data-bucket",
        "resource_type": "S3Bucket",
        "details": {"bucket_name": "public-data-bucket"},
        "remediation_hint": "Set bucket to private",
    }

    response = AIReasoner().reason(finding, score=9.7, graph_summary={"entry_points": ["EC2:i-123"]})

    assert set(response.keys()) >= {"summary", "impact", "steps", "action", "rollback"}
    assert response["summary"]
    assert response["steps"]
    assert response["action"]["resource_type"] == "s3"
    assert response["action"]["resource_id"] == "public-data-bucket"


def test_remediation_planner_generates_valid_actions():
    plan = RemediationPlanner().plan(
        "RULE-S3-PUBLIC",
        target="public-data-bucket",
        dry_run=True,
    )

    assert plan["dry_run"] is True
    assert plan["action"]["action"] == "BLOCK_S3_PUBLIC_ACCESS"
    assert plan["action"]["resource_type"] == "s3"
    assert plan["action"]["resource_id"] == "public-data-bucket"
    assert plan["rollback"]["action"] == "RESTORE_S3_PUBLIC_ACCESS"


def test_verifier_detects_remediation_success():
    before = [
        {"id": "VULN-001", "resource_id": "public-data-bucket", "severity": "CRITICAL"},
        {"id": "VULN-002", "resource_id": "sg-open-1", "severity": "HIGH"},
    ]
    after = [
        {"id": "VULN-002", "resource_id": "sg-open-1", "severity": "HIGH"},
    ]

    report = Verifier().compare(before, after)

    assert report["remediation_required"] is True
    assert report["resolved"] == ["VULN-001"]
    assert report["status"] in {"PARTIAL", "SUCCESS"}


def test_executor_blocks_public_s3_access_and_sets_private_acl():
    fake_s3 = MagicMock()

    with patch("cloudsec_copilot.executor.executor.boto3.client", return_value=fake_s3):
        executor = __import__("cloudsec_copilot.executor.executor", fromlist=["Executor"]).Executor()
        result = executor._apply_action({
            "action": "BLOCK_S3_PUBLIC_ACCESS",
            "resource_id": "cloudsec-vulnerable-public-bucket",
            "parameters": {
                "block_public_acls": True,
                "ignore_public_acls": True,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
        })

    assert result["status"] == "APPLIED"
    fake_s3.put_public_access_block.assert_called_once()
    fake_s3.put_bucket_acl.assert_called_once_with(Bucket="cloudsec-vulnerable-public-bucket", ACL="private")
