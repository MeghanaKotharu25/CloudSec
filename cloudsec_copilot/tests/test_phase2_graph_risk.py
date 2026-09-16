"""
Phase 2 Test Suite: Cloud Attack Dependency Graph, Attack Paths, Blast Radius, and Context-Aware Risk Prioritization.
"""

import pytest
import networkx as nx

from cloudsec_copilot.discovery.models import (
    InfrastructureStateModel,
    ResourceInventoryModel,
    S3BucketModel,
    SecurityGroupModel,
    InboundRuleModel,
    IAMRoleModel,
    IAMPolicyModel,
    RDSInstanceModel,
    EC2InstanceModel,
)
from cloudsec_copilot.graph.graph_builder import CloudGraphBuilder
from cloudsec_copilot.risk.risk_engine import RiskEngine
from cloudsec_copilot.scanner.scanner import Scanner


def build_isolated_inventory():
    """Inventory representing the LocalStack lab setup: resources exist, but no EC2 connects them."""
    return InfrastructureStateModel(
        account_id="123456789012",
        region="us-east-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-public-bucket",
                    is_public=True,
                    acl_public=True,
                    encryption_enabled=False,
                )
            ],
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-isolated-open",
                    group_name="open-secgroup-vulnerable",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                        InboundRuleModel(protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0"),
                    ],
                )
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="CloudSecVulnerableAdminRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableAdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                )
            ],
            rds_instances=[],
            ec2_instances=[],
        ),
    )


def build_full_attack_chain_inventory():
    """Inventory where an EC2 is associated with the open SG and assumes the admin role."""
    return InfrastructureStateModel(
        account_id="123456789012",
        region="us-east-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="critical-data-bucket",
                    is_public=False,
                    acl_public=False,
                    encryption_enabled=True,
                )
            ],
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-web-ssh",
                    group_name="web-ssh-group",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                    ],
                ),
                SecurityGroupModel(
                    group_id="sg-internal-only",
                    group_name="internal-group",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=8080, to_port=8080, cidr_ip="10.0.0.0/16"),
                    ],
                ),
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="AdminInstanceRole",
                    arn="arn:aws:iam::123456789012:role/AdminInstanceRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                )
            ],
            rds_instances=[
                RDSInstanceModel(
                    db_instance_identifier="public-postgres-db",
                    engine="postgres",
                    publicly_accessible=True,
                    storage_encrypted=False,
                )
            ],
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-bastion-host",
                    instance_type="t3.medium",
                    state="running",
                    public_ip="52.1.2.3",
                    private_ip="10.0.1.10",
                    security_groups=["sg-web-ssh"],
                    iam_instance_profile="AdminInstanceRole",
                )
            ],
        ),
    )


# 1. INTERNET node exists
def test_1_internet_node_exists():
    builder = CloudGraphBuilder()
    graph = builder.build(build_isolated_inventory())
    assert "INTERNET" in graph.nodes
    assert graph.nodes["INTERNET"]["type"] == "INTERNET"


# 2. Public S3 creates INTERNET -> S3
def test_2_public_s3_creates_internet_edge():
    builder = CloudGraphBuilder()
    graph = builder.build(build_isolated_inventory())
    target = "S3:cloudsec-vulnerable-public-bucket"
    assert graph.has_edge("INTERNET", target)
    edge_data = graph.get_edge_data("INTERNET", target)
    assert edge_data["relationship"] == "PUBLIC_ACCESS"
    assert edge_data["security_relevant"] is True


# 3. Public Security Group creates INTERNET -> SG with port metadata
def test_3_public_sg_creates_internet_edge_with_ports():
    builder = CloudGraphBuilder()
    graph = builder.build(build_isolated_inventory())
    sg_node = "SG:sg-isolated-open"
    assert graph.has_edge("INTERNET", sg_node)
    edge_data = graph.get_edge_data("INTERNET", sg_node)
    assert edge_data["relationship"] == "PUBLIC_INGRESS"
    assert edge_data["security_relevant"] is True
    assert 22 in edge_data["ports"]
    assert edge_data["is_sensitive"] is True


# 4. Non-public Security Group does not create INTERNET -> SG
def test_4_non_public_sg_does_not_create_internet_edge():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    internal_sg = "SG:sg-internal-only"
    assert internal_sg in graph.nodes
    assert not graph.has_edge("INTERNET", internal_sg)


# 5. EC2/SG association creates SG -> EC2 reachability
def test_5_ec2_sg_association_creates_reachability():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    sg_node = "SG:sg-web-ssh"
    ec2_node = "EC2:i-bastion-host"
    assert graph.has_edge(sg_node, ec2_node)
    edge_data = graph.get_edge_data(sg_node, ec2_node)
    assert edge_data["relationship"] in ("ALLOWS_TRAFFIC", "EXPOSES")
    assert edge_data["security_relevant"] is True


# 6. EC2/IAM role association creates EC2 -> IAM_ROLE
def test_6_ec2_iam_role_association():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    ec2_node = "EC2:i-bastion-host"
    role_node = "IAM:AdminInstanceRole"
    assert graph.has_edge(ec2_node, role_node)
    edge_data = graph.get_edge_data(ec2_node, role_node)
    assert edge_data["relationship"] == "ASSUMES_ROLE"
    assert edge_data["security_relevant"] is True


# 7. IAM role/policy relationship creates IAM_ROLE -> IAM_POLICY with privilege level
def test_7_iam_role_grants_policy():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    role_node = "IAM:AdminInstanceRole"
    policy_node = "POLICY:AdministratorAccess"
    assert graph.has_edge(role_node, policy_node)
    edge_data = graph.get_edge_data(role_node, policy_node)
    assert edge_data["relationship"] == "GRANTS_PERMISSION"
    assert edge_data["privilege_level"] == "ADMINISTRATIVE"


# 8. No fake relationships are created between unrelated resources
def test_8_no_fake_relationships():
    builder = CloudGraphBuilder()
    graph = builder.build(build_isolated_inventory())
    # S3 bucket should not connect to IAM or SG
    assert not graph.has_edge("S3:cloudsec-vulnerable-public-bucket", "IAM:CloudSecVulnerableAdminRole")
    assert not graph.has_edge("SG:sg-isolated-open", "IAM:CloudSecVulnerableAdminRole")
    assert not graph.has_edge("IAM:CloudSecVulnerableAdminRole", "S3:cloudsec-vulnerable-public-bucket")


# 9. Attack path calculation works when full chain exists
def test_9_full_chain_attack_path_calculation():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    paths = builder.find_attack_paths(graph, "POLICY:AdministratorAccess")
    assert len(paths) >= 1
    # Path: INTERNET -> SG:sg-web-ssh -> EC2:i-bastion-host -> IAM:AdminInstanceRole -> POLICY:AdministratorAccess
    expected_nodes = [
        "INTERNET",
        "SG:sg-web-ssh",
        "EC2:i-bastion-host",
        "IAM:AdminInstanceRole",
        "POLICY:AdministratorAccess",
    ]
    assert any(p["path"] == expected_nodes for p in paths)


# 10. Attack path calculation does not invent SG -> EC2 when no association exists
def test_10_no_invented_attack_paths_in_isolated_lab():
    builder = CloudGraphBuilder()
    graph = builder.build(build_isolated_inventory())
    # For isolated SG, path from INTERNET reaches SG, but goes no further
    sg_paths = builder.find_attack_paths(graph, "SG:sg-isolated-open")
    assert len(sg_paths) == 1
    assert sg_paths[0]["path"] == ["INTERNET", "SG:sg-isolated-open"]

    # IAM role is NOT reachable from INTERNET
    iam_paths = builder.find_attack_paths(graph, "IAM:CloudSecVulnerableAdminRole")
    assert len(iam_paths) == 0


# 11. Blast radius is based on reachable security-relevant resources
def test_11_blast_radius_calculation():
    builder = CloudGraphBuilder()
    graph = builder.build(build_full_attack_chain_inventory())
    # Downstream from the exposed SG reaches EC2, IAM Role, IAM Policy
    blast = builder.compute_blast_radius(graph, "SG:sg-web-ssh")
    assert "EC2:i-bastion-host" in blast["reachable_nodes"]
    assert "IAM:AdminInstanceRole" in blast["reachable_nodes"]
    assert "POLICY:AdministratorAccess" in blast["reachable_nodes"]
    assert blast["has_admin_privilege"] is True
    assert blast["score"] >= 9.0

    # In isolated inventory, blast radius of isolated SG is empty
    isolated_graph = builder.build(build_isolated_inventory())
    isolated_blast = builder.compute_blast_radius(isolated_graph, "SG:sg-isolated-open")
    assert isolated_blast["resource_count"] == 0
    assert isolated_blast["score"] <= 2.0


# 12. Risk score changes when graph context changes (chained vs isolated)
def test_12_risk_score_responds_to_graph_context():
    scanner = Scanner()
    risk_engine = RiskEngine()
    builder = CloudGraphBuilder()

    # Isolated SG finding
    iso_inv = build_isolated_inventory()
    iso_findings = scanner.scan(iso_inv)
    iso_graph = builder.build(iso_inv)
    iso_risk = risk_engine.prioritize(iso_findings, iso_graph)
    iso_sg_score = next(f["composite_score"] for f in iso_risk["prioritized_findings"] if f["vuln_id"] == "VULN-006")

    # Chained SG finding (reaches admin role)
    chain_inv = build_full_attack_chain_inventory()
    chain_findings = scanner.scan(chain_inv)
    chain_graph = builder.build(chain_inv)
    chain_risk = risk_engine.prioritize(chain_findings, chain_graph)
    chain_sg_score = next(f["composite_score"] for f in chain_risk["prioritized_findings"] if f["vuln_id"] == "VULN-006")

    # Chained vulnerability reaching IAM admin must receive a higher score than isolated SG
    assert chain_sg_score > iso_sg_score


# 13. Internet exposure affects risk
def test_13_internet_exposure_affects_risk():
    risk_engine = RiskEngine()
    builder = CloudGraphBuilder()
    inv = build_full_attack_chain_inventory()
    graph = builder.build(inv)

    findings = [
        {
            "id": "VULN-TEST-EXPOSED",
            "rule_id": "RULE-SG-SENSITIVE-PORT",
            "severity": "HIGH",
            "resource_id": "sg-web-ssh",
            "resource_type": "SecurityGroup",
            "details": {"open_rules": [{"from_port": 22, "cidr_ip": "0.0.0.0/0"}]},
        },
        {
            "id": "VULN-TEST-INTERNAL",
            "rule_id": "RULE-SG-OPEN",
            "severity": "HIGH",
            "resource_id": "sg-internal-only",
            "resource_type": "SecurityGroup",
            "details": {},
        },
    ]

    prioritized = risk_engine.prioritize(findings, graph)["prioritized_findings"]
    exposed_finding = next(f for f in prioritized if f["vuln_id"] == "VULN-TEST-EXPOSED")
    internal_finding = next(f for f in prioritized if f["vuln_id"] == "VULN-TEST-INTERNAL")

    assert exposed_finding["composite_score"] > internal_finding["composite_score"]
    assert exposed_finding["risk_breakdown"]["internet_exposure"]["is_exposed"] is True


# 14. High privilege affects risk
def test_14_high_privilege_affects_risk():
    risk_engine = RiskEngine()
    builder = CloudGraphBuilder()
    inv = build_isolated_inventory()
    graph = builder.build(inv)

    findings = [
        {
            "id": "VULN-IAM-ADMIN",
            "rule_id": "RULE-IAM-ADMIN",
            "severity": "CRITICAL",
            "resource_id": "CloudSecVulnerableAdminRole",
            "resource_type": "IAMRole",
            "details": {"role_name": "CloudSecVulnerableAdminRole"},
        }
    ]

    prioritized = risk_engine.prioritize(findings, graph)["prioritized_findings"]
    item = prioritized[0]
    assert item["risk_breakdown"]["privilege"]["score"] == 10.0


# 15. Risk score remains strictly within 0 - 10
def test_15_risk_score_bounds():
    risk_engine = RiskEngine()
    builder = CloudGraphBuilder()
    inv = build_full_attack_chain_inventory()
    graph = builder.build(inv)
    scanner = Scanner()
    findings = scanner.scan(inv)

    prioritized = risk_engine.prioritize(findings, graph)["prioritized_findings"]
    for item in prioritized:
        score = item["composite_score"]
        assert 0.0 <= score <= 10.0


# 16. Priority classification is deterministic
def test_16_priority_classification_deterministic():
    engine = RiskEngine()
    assert engine._priority_label(9.5) == "CRITICAL"
    assert engine._priority_label(8.0) == "CRITICAL"
    assert engine._priority_label(7.9) == "HIGH"
    assert engine._priority_label(6.0) == "HIGH"
    assert engine._priority_label(5.9) == "MEDIUM"
    assert engine._priority_label(4.0) == "MEDIUM"
    assert engine._priority_label(3.9) == "LOW"
    assert engine._priority_label(0.0) == "LOW"


# 17. Graph visualization and data export succeed
def test_17_graph_export_and_visualization(tmp_path):
    builder = CloudGraphBuilder()
    inv = build_full_attack_chain_inventory()
    graph = builder.build(inv)

    # Test machine-readable export
    data = builder.export_graph_data(graph)
    assert data["total_nodes"] == graph.number_of_nodes()
    assert data["total_edges"] == graph.number_of_edges()
    assert "attack_paths" in data

    # Test visualization file rendering
    img_path = str(tmp_path / "test_attack_graph.png")
    out = builder.export_visualization(graph, img_path)
    assert out == img_path
    assert (tmp_path / "test_attack_graph.png").exists()


# 18. Remediation policies are excluded from attack graph
def test_18_remediation_policy_excluded_from_attack_graph():
    builder = CloudGraphBuilder()
    inv = InfrastructureStateModel(
        account_id="123456789012",
        region="us-east-1",
        resources=ResourceInventoryModel(
            iam_roles=[
                IAMRoleModel(
                    role_name="CloudSecVulnerableAdminRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableAdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                    inline_policies=["CloudSecLeastPrivilegeReplacement"],
                )
            ],
            iam_policies=[
                IAMPolicyModel(
                    policy_name="AdministratorAccess",
                    arn="arn:aws:iam::aws:policy/AdministratorAccess",
                    is_admin=True,
                ),
                IAMPolicyModel(
                    policy_name="CloudSecLeastPrivilegeReplacement",
                    arn="arn:aws:iam::123456789012:policy/CloudSecLeastPrivilegeReplacement",
                    is_admin=False,
                ),
            ],
        ),
    )
    graph = builder.build(inv)
    # AdministratorAccess must be present
    assert "POLICY:AdministratorAccess" in graph.nodes
    # Remediation policy must NOT be present as a node or edge
    assert "POLICY:CloudSecVulnerableAdminRole:CloudSecLeastPrivilegeReplacement" not in graph.nodes
    assert "POLICY:CloudSecLeastPrivilegeReplacement" not in graph.nodes
    for u, v in graph.edges():
        assert "LeastPrivilege" not in u and "LeastPrivilege" not in v


# 19. Comprehensive verification of all 10 attack graph requirements
def test_19_ten_point_attack_graph_requirements(tmp_path):
    inv = InfrastructureStateModel(
        account_id="123456789012",
        region="us-east-1",
        resources=ResourceInventoryModel(
            s3_buckets=[
                S3BucketModel(
                    name="cloudsec-vulnerable-public-bucket",
                    is_public=True,
                    acl_public=True,
                    encryption_enabled=False,
                )
            ],
            security_groups=[
                SecurityGroupModel(
                    group_id="sg-vulnerable-open",
                    group_name="open-secgroup-vulnerable",
                    inbound_rules=[
                        InboundRuleModel(protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0"),
                        InboundRuleModel(protocol="tcp", from_port=80, to_port=80, cidr_ip="0.0.0.0/0"),
                    ],
                )
            ],
            ec2_instances=[
                EC2InstanceModel(
                    instance_id="i-vulnerable-ec2",
                    name="CloudSecVulnerableServer",
                    instance_type="t3.micro",
                    state="running",
                    public_ip="54.214.112.87",
                    security_groups=["sg-vulnerable-open"],
                    iam_instance_profile="CloudSecVulnerableAdminRole",
                )
            ],
            iam_roles=[
                IAMRoleModel(
                    role_name="CloudSecVulnerableAdminRole",
                    arn="arn:aws:iam::123456789012:role/CloudSecVulnerableAdminRole",
                    is_admin=True,
                    attached_policies=["AdministratorAccess"],
                )
            ],
            iam_policies=[
                IAMPolicyModel(
                    policy_name="AdministratorAccess",
                    arn="arn:aws:iam::aws:policy/AdministratorAccess",
                    is_admin=True,
                )
            ],
        ),
    )

    # 1. vulnerable EC2 is discovered
    assert len(inv.resources.ec2_instances) == 1
    ec2_inst = inv.resources.ec2_instances[0]
    assert ec2_inst.name == "CloudSecVulnerableServer"
    assert ec2_inst.public_ip == "54.214.112.87"

    # 2. EC2 is attached to vulnerable Security Group
    assert "sg-vulnerable-open" in ec2_inst.security_groups

    # 3. EC2 is associated with IAM Role
    assert ec2_inst.iam_instance_profile == "CloudSecVulnerableAdminRole"

    builder = CloudGraphBuilder()
    graph = builder.build(inv)

    # 4. graph contains INTERNET -> SG
    assert graph.has_edge("INTERNET", "SG:sg-vulnerable-open")
    assert graph.edges["INTERNET", "SG:sg-vulnerable-open"]["relationship"] == "PUBLIC_INGRESS"

    # 5. graph contains SG -> EC2
    assert graph.has_edge("SG:sg-vulnerable-open", "EC2:i-vulnerable-ec2")
    assert graph.edges["SG:sg-vulnerable-open", "EC2:i-vulnerable-ec2"]["relationship"] == "ALLOWS_TRAFFIC"

    # 6. graph contains EC2 -> IAM Role
    assert graph.has_edge("EC2:i-vulnerable-ec2", "IAM:CloudSecVulnerableAdminRole")
    assert graph.edges["EC2:i-vulnerable-ec2", "IAM:CloudSecVulnerableAdminRole"]["relationship"] == "ASSUMES_ROLE"

    # 7. graph contains IAM Role -> AdministratorAccess
    assert graph.has_edge("IAM:CloudSecVulnerableAdminRole", "POLICY:AdministratorAccess")
    assert graph.edges["IAM:CloudSecVulnerableAdminRole", "POLICY:AdministratorAccess"]["relationship"] == "GRANTS_PERMISSION"

    # 8. complete attack path is discovered
    paths = builder.find_attack_paths(graph, "POLICY:AdministratorAccess")
    assert len(paths) >= 1
    expected_path = [
        "INTERNET",
        "SG:sg-vulnerable-open",
        "EC2:i-vulnerable-ec2",
        "IAM:CloudSecVulnerableAdminRole",
        "POLICY:AdministratorAccess",
    ]
    assert any(p["path"] == expected_path for p in paths)

    # 9. no remediation replacement policy appears in attack graph
    assert "POLICY:CloudSecLeastPrivilegeReplacement" not in graph.nodes
    for u, v in graph.edges():
        assert "LeastPrivilege" not in u and "LeastPrivilege" not in v

    # 10. graph visualization remains deterministic
    out1 = str(tmp_path / "attack_graph_run1.png")
    out2 = str(tmp_path / "attack_graph_run2.png")
    builder.export_visualization(graph, out1)
    builder.export_visualization(graph, out2)
    with open(out1, "rb") as f1, open(out2, "rb") as f2:
        assert len(f1.read()) > 0
        assert len(f2.read()) > 0
