from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from cloudsec_copilot.discovery.models import InfrastructureStateModel


class CloudGraphBuilder:
    """Creates deterministic cloud attack dependency graphs and computes blast radius."""

    SENSITIVE_PORT_MAP: Dict[int, str] = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
        11211: "Memcached",
    }

    @staticmethod
    def _normalize_iam_ref(value: str | None) -> str | None:
        if not value:
            return None
        if ":role/" in value:
            return value.split(":role/")[-1]
        if ":instance-profile/" in value:
            return value.split(":instance-profile/")[-1]
        return value.split("/")[-1] if "/" in value else value

    def build(
        self,
        inventory: InfrastructureStateModel,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> nx.DiGraph:
        """Construct a deterministic directed attack dependency graph from discovered cloud inventory."""
        graph = nx.DiGraph()
        resources = inventory.resources

        # 1. Dedicated INTERNET entry point
        graph.add_node(
            "INTERNET",
            id="INTERNET",
            type="INTERNET",
            label="INTERNET",
            resource="internet",
            is_vulnerable=False,
            vulnerabilities=[],
        )

        vulnerable_resources: Dict[str, List[str]] = {}
        if findings:
            for f in findings:
                r_id = f.get("resource_id", "")
                v_id = f.get("id", "")
                vulnerable_resources.setdefault(r_id, []).append(v_id)

        # 2. S3 Buckets
        for bucket in resources.s3_buckets:
            bucket_node = f"S3:{bucket.name}"
            vulns = vulnerable_resources.get(bucket.name, [])
            is_vuln = bool(vulns) or bucket.is_public or bucket.acl_public or bucket.policy_public or not bucket.encryption_enabled
            graph.add_node(
                bucket_node,
                id=bucket_node,
                type="S3",
                label=bucket_node,
                resource=bucket.name,
                arn=bucket.arn,
                is_public=bucket.is_public or bucket.acl_public or bucket.policy_public,
                encryption_enabled=bucket.encryption_enabled,
                is_vulnerable=is_vuln,
                vulnerabilities=vulns,
            )
            # Legitimate public access edge from INTERNET
            if bucket.is_public or bucket.acl_public or bucket.policy_public:
                graph.add_edge(
                    "INTERNET",
                    bucket_node,
                    relationship="PUBLIC_ACCESS",
                    security_relevant=True,
                    reason=f"S3 bucket '{bucket.name}' allows unrestricted public access.",
                    is_sensitive=True,
                )

        # 3. Security Groups
        for sg in resources.security_groups:
            sg_node = f"SG:{sg.group_id}"
            vulns = vulnerable_resources.get(sg.group_id, [])
            open_rules = [r for r in sg.inbound_rules if r.cidr_ip == "0.0.0.0/0"]
            is_vuln = bool(vulns) or bool(open_rules)

            graph.add_node(
                sg_node,
                id=sg_node,
                type="SECURITY_GROUP",
                label=sg_node,
                resource=sg.group_id,
                group_name=sg.group_name,
                vpc_id=sg.vpc_id,
                is_vulnerable=is_vuln,
                vulnerabilities=vulns,
            )

            # Legitimate public ingress edge from INTERNET if 0.0.0.0/0 is configured
            if open_rules:
                ports_list: List[int] = []
                port_descriptions: List[str] = []
                has_sensitive = False

                for r in open_rules:
                    proto = str(r.protocol).lower()
                    from_p = r.from_port
                    to_p = r.to_port

                    if proto == "-1" or (from_p is None and to_p is None):
                        port_descriptions.append("ALL_PORTS")
                        has_sensitive = True
                    elif from_p is not None and to_p is not None:
                        if from_p == to_p:
                            ports_list.append(from_p)
                            service_name = self.SENSITIVE_PORT_MAP.get(from_p)
                            if service_name:
                                has_sensitive = True
                                port_descriptions.append(f"{from_p}/{service_name}")
                            else:
                                port_descriptions.append(str(from_p))
                        else:
                            port_descriptions.append(f"{from_p}-{to_p}")
                            for p in range(from_p, min(to_p + 1, from_p + 50)):
                                if p in self.SENSITIVE_PORT_MAP:
                                    has_sensitive = True
                                    break

                summary_str = f"TCP {', '.join(port_descriptions)}" if port_descriptions else "Open Ingress"
                graph.add_edge(
                    "INTERNET",
                    sg_node,
                    relationship="PUBLIC_INGRESS",
                    security_relevant=True,
                    source_cidr="0.0.0.0/0",
                    protocol="tcp",
                    ports=ports_list,
                    port_summary=summary_str,
                    is_sensitive=has_sensitive,
                    reason=f"Security Group '{sg.group_name}' allows public ingress from 0.0.0.0/0 ({summary_str}).",
                )

        # 4. EC2 Instances
        for instance in resources.ec2_instances:
            ec2_node = f"EC2:{instance.instance_id}"
            vulns = vulnerable_resources.get(instance.instance_id, [])
            is_vuln = bool(vulns) or bool(instance.public_ip)
            ec2_name = getattr(instance, "name", None) or instance.instance_id
            graph.add_node(
                ec2_node,
                id=ec2_node,
                type="EC2",
                label=ec2_node,
                resource=instance.instance_id,
                name=ec2_name,
                public_ip=instance.public_ip,
                private_ip=instance.private_ip,
                instance_type=instance.instance_type,
                state=instance.state,
                is_vulnerable=is_vuln,
                vulnerabilities=vulns,
            )

            # Security group associations: SG allows traffic reaching the EC2 instance
            for sg_ref in instance.security_groups:
                sg_node = f"SG:{sg_ref}"
                if sg_node not in graph:
                    for s_node, d in list(graph.nodes(data=True)):
                        if d.get("type") == "SECURITY_GROUP" and (d.get("resource") == sg_ref or d.get("group_name") == sg_ref):
                            sg_node = s_node
                            break
                if sg_node not in graph:
                    graph.add_node(sg_node, type="SECURITY_GROUP", label=sg_node, resource=sg_ref, is_vulnerable=False, vulnerabilities=[])

                # Structural association: EC2 is associated with SG
                graph.add_edge(
                    ec2_node,
                    sg_node,
                    relationship="ASSOCIATED_WITH",
                    security_relevant=False,
                    reason=f"EC2 {instance.instance_id} is associated with {sg_ref}",
                )

                # Attack reachability: SG allows traffic to EC2
                graph.add_edge(
                    sg_node,
                    ec2_node,
                    relationship="ALLOWS_TRAFFIC",
                    security_relevant=True,
                    reason=f"Traffic allowed by Security Group {sg_ref} reaches EC2 {instance.instance_id}",
                )

            # Only add direct INTERNET -> EC2 if instance is NOT behind any Security Group
            if instance.public_ip and not instance.security_groups:
                graph.add_edge(
                    "INTERNET",
                    ec2_node,
                    relationship="PUBLIC_ACCESS",
                    security_relevant=True,
                    reason=f"EC2 instance {instance.instance_id} is directly exposed with public IP {instance.public_ip}",
                    is_sensitive=False,
                )

        # 5. IAM Roles & Policies
        for role in resources.iam_roles:
            role_node = f"IAM:{role.role_name}"
            vulns = vulnerable_resources.get(role.role_name, [])
            is_vuln = bool(vulns) or role.is_admin
            graph.add_node(
                role_node,
                id=role_node,
                type="IAM_ROLE",
                label=role_node,
                resource=role.role_name,
                arn=role.arn,
                is_admin=role.is_admin,
                is_vulnerable=is_vuln,
                vulnerabilities=vulns,
            )

            # Attached policies
            for policy in role.attached_policies:
                # Exclude remediation artifacts from the attack graph (e.g. CloudSecLeastPrivilegeReplacement)
                if "LeastPrivilege" in policy or "Replacement" in policy:
                    continue
                policy_node = f"POLICY:{policy}"
                p_is_admin = (policy == "AdministratorAccess") or role.is_admin
                if policy_node not in graph:
                    graph.add_node(
                        policy_node,
                        id=policy_node,
                        type="IAM_POLICY",
                        label=policy_node,
                        resource=policy,
                        is_admin=p_is_admin,
                        is_vulnerable=p_is_admin,
                        vulnerabilities=[],
                    )
                graph.add_edge(
                    role_node,
                    policy_node,
                    relationship="GRANTS_PERMISSION",
                    security_relevant=True,
                    is_admin=p_is_admin,
                    privilege_level="ADMINISTRATIVE" if p_is_admin else "HIGH",
                    reason=f"IAM role '{role.role_name}' grants permissions via policy '{policy}'.",
                )

            # Inline policies
            for inline_policy in role.inline_policies:
                if "LeastPrivilege" in inline_policy or "Replacement" in inline_policy:
                    continue
                inline_node = f"POLICY:{role.role_name}:{inline_policy}"
                if inline_node not in graph:
                    graph.add_node(
                        inline_node,
                        id=inline_node,
                        type="IAM_POLICY",
                        label=inline_node,
                        resource=inline_policy,
                        is_admin=role.is_admin,
                        is_vulnerable=role.is_admin,
                        vulnerabilities=[],
                    )
                graph.add_edge(
                    role_node,
                    inline_node,
                    relationship="GRANTS_PERMISSION",
                    security_relevant=True,
                    is_admin=role.is_admin,
                    privilege_level="ADMINISTRATIVE" if role.is_admin else "HIGH",
                    reason=f"IAM role '{role.role_name}' grants inline policy '{inline_policy}'.",
                )

        # Standalone discovered IAM policies
        for p in resources.iam_policies:
            if "LeastPrivilege" in p.policy_name or "Replacement" in p.policy_name:
                continue
            policy_node = f"POLICY:{p.policy_name}"
            vulns = vulnerable_resources.get(p.policy_name, [])
            if policy_node not in graph:
                graph.add_node(
                    policy_node,
                    id=policy_node,
                    type="IAM_POLICY",
                    label=policy_node,
                    resource=p.policy_name,
                    arn=p.arn,
                    is_admin=p.is_admin,
                    is_vulnerable=p.is_admin or bool(vulns),
                    vulnerabilities=vulns,
                )

        # Link EC2 to IAM Role via IAM Instance Profile
        for instance in resources.ec2_instances:
            resolved_profile = self._normalize_iam_ref(instance.iam_instance_profile)
            if not resolved_profile:
                continue
            role_node = f"IAM:{resolved_profile}"
            if role_node in graph:
                graph.add_edge(
                    f"EC2:{instance.instance_id}",
                    role_node,
                    relationship="ASSUMES_ROLE",
                    security_relevant=True,
                    reason=f"EC2 instance '{instance.instance_id}' assumes IAM role '{resolved_profile}'.",
                )

        # 6. RDS Instances
        for db in resources.rds_instances:
            db_node = f"RDS:{db.db_instance_identifier}"
            vulns = vulnerable_resources.get(db.db_instance_identifier, [])
            is_vuln = bool(vulns) or db.publicly_accessible or not db.storage_encrypted
            graph.add_node(
                db_node,
                id=db_node,
                type="RDS",
                label=db_node,
                resource=db.db_instance_identifier,
                engine=db.engine,
                publicly_accessible=db.publicly_accessible,
                storage_encrypted=db.storage_encrypted,
                is_vulnerable=is_vuln,
                vulnerabilities=vulns,
            )
            if db.publicly_accessible:
                graph.add_edge(
                    "INTERNET",
                    db_node,
                    relationship="PUBLIC_INGRESS",
                    security_relevant=True,
                    reason=f"RDS instance '{db.db_instance_identifier}' is publicly accessible over the Internet.",
                    is_sensitive=True,
                )

        return graph

    def find_attack_paths(self, graph: nx.DiGraph, target_node: str) -> List[Dict[str, Any]]:
        """Find deterministic attack paths originating from INTERNET to the target node."""
        if "INTERNET" not in graph or target_node not in graph:
            return []

        # Subgraph considering only attack-reachability edges
        security_edges = [
            (u, v) for u, v, d in graph.edges(data=True) if d.get("security_relevant", True)
        ]
        subgraph = graph.edge_subgraph(security_edges)

        if "INTERNET" not in subgraph or target_node not in subgraph:
            return []

        paths_result: List[Dict[str, Any]] = []
        try:
            for path in nx.all_simple_paths(subgraph, "INTERNET", target_node, cutoff=6):
                steps = []
                for i in range(len(path) - 1):
                    u, v = path[i], path[i + 1]
                    edge_attrs = graph.get_edge_data(u, v) or {}
                    steps.append(
                        {
                            "from": u,
                            "to": v,
                            "relationship": edge_attrs.get("relationship", "CAN_REACH"),
                            "reason": edge_attrs.get("reason", ""),
                            "ports": edge_attrs.get("ports", []),
                            "is_sensitive": edge_attrs.get("is_sensitive", False),
                        }
                    )
                paths_result.append(
                    {
                        "source": "INTERNET",
                        "target": target_node,
                        "path": path,
                        "length": len(path) - 1,
                        "steps": steps,
                    }
                )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        return paths_result

    def compute_blast_radius(self, graph: nx.DiGraph, source: str) -> Dict[str, Any]:
        """Compute the downstream reachable impact from a resource node along attack/privilege edges."""
        if source not in graph:
            return {
                "reachable_nodes": [],
                "resource_count": 0,
                "reached_types": [],
                "has_iam_reach": False,
                "has_admin_privilege": False,
                "score": 1.0,
            }

        queue = deque([source])
        visited: Set[str] = {source}
        reachable: List[str] = []
        reached_types: Set[str] = set()
        has_iam = False
        has_admin = False

        while queue:
            current = queue.popleft()
            for neighbor in graph.successors(current):
                edge_data = graph.get_edge_data(current, neighbor) or {}
                # Only traverse forward along attack-relevant relationships
                if not edge_data.get("security_relevant", True):
                    continue
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    reachable.append(neighbor)

                    n_type = graph.nodes[neighbor].get("type", "")
                    if n_type:
                        reached_types.add(n_type)

                    if n_type in {"IAM_ROLE", "IAM_POLICY"}:
                        has_iam = True

                    node_admin = graph.nodes[neighbor].get("is_admin", False)
                    edge_admin = edge_data.get("is_admin", False) or edge_data.get("privilege_level") == "ADMINISTRATIVE"
                    if node_admin or edge_admin or "AdministratorAccess" in neighbor:
                        has_admin = True

        # Calculate a normalized blast radius score (1.0 - 10.0)
        count = len(reachable)
        base_score = min(10.0, max(1.0, 1.0 + (count * 1.8)))
        if has_admin:
            base_score = max(base_score, 9.0)
        elif has_iam:
            base_score = max(base_score, 7.0)

        return {
            "reachable_nodes": reachable,
            "resource_count": count,
            "reached_types": sorted(list(reached_types)),
            "has_iam_reach": has_iam,
            "has_admin_privilege": has_admin,
            "score": round(float(base_score), 2),
        }

    def blast_radius(self, graph: nx.DiGraph, source: str) -> List[str]:
        """Backward-compatible helper returning list of downstream reachable node identifiers."""
        result = self.compute_blast_radius(graph, source)
        return result["reachable_nodes"]

    def export_graph_data(self, graph: nx.DiGraph) -> Dict[str, Any]:
        """Export machine-readable representation of graph topology and security attributes."""
        nodes_list = []
        for n, d in graph.nodes(data=True):
            nodes_list.append(
                {
                    "id": n,
                    "type": d.get("type", "UNKNOWN"),
                    "label": d.get("label", n),
                    "resource": d.get("resource", ""),
                    "is_vulnerable": d.get("is_vulnerable", False),
                    "vulnerabilities": d.get("vulnerabilities", []),
                }
            )

        edges_list = []
        for u, v, d in graph.edges(data=True):
            edges_list.append(
                {
                    "source": u,
                    "target": v,
                    "relationship": d.get("relationship", "ASSOCIATED_WITH"),
                    "security_relevant": d.get("security_relevant", False),
                    "reason": d.get("reason", ""),
                    "ports": d.get("ports", []),
                }
            )

        # Summary of attack paths from INTERNET
        internet_paths: Dict[str, List[List[str]]] = {}
        if "INTERNET" in graph:
            for n in graph.nodes:
                if n != "INTERNET":
                    paths = self.find_attack_paths(graph, n)
                    if paths:
                        internet_paths[n] = [p["path"] for p in paths]

        return {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "nodes": nodes_list,
            "edges": edges_list,
            "attack_paths": internet_paths,
        }

    def _get_card_details(self, node_id: str, attrs: Dict[str, Any]) -> Tuple[str, str, str, bool]:
        """Return (header, title, badge, is_vulnerable) matching presentation requirements."""
        ntype = attrs.get("type", "RESOURCE")
        name = attrs.get("name") or attrs.get("resource") or attrs.get("label") or node_id
        is_vuln = attrs.get("is_vulnerable", False)
        vulns = attrs.get("vulnerabilities", [])
        formatted_vulns = ", ".join(sorted(list(set(vulns)))) if vulns else ""

        if ntype == "INTERNET":
            return ("INTERNET", "Attack Origin", "", False)

        if ntype == "S3":
            badge = f"[!] {formatted_vulns}" if formatted_vulns else ("[!] VULN-001" if is_vuln else "")
            return ("S3 BUCKET", name, badge, is_vuln)

        if ntype == "SECURITY_GROUP":
            g_name = attrs.get("group_name") or name
            badge = f"[!] {formatted_vulns}" if formatted_vulns else ("[!] VULN-003, VULN-006" if is_vuln else "")
            return ("SECURITY GROUP", g_name, badge, is_vuln)

        if ntype == "EC2":
            ec2_name = attrs.get("name") or attrs.get("resource") or name
            badge = f"[!] {formatted_vulns}" if formatted_vulns else ("[!] VULN-004" if is_vuln else "")
            return ("EC2 INSTANCE", ec2_name, badge, is_vuln)

        if ntype == "IAM_ROLE":
            badge = f"[!] {formatted_vulns}" if formatted_vulns else ("[!] VULN-005, VULN-007" if is_vuln else "")
            return ("IAM ROLE", name, badge, is_vuln)

        if ntype == "IAM_POLICY":
            is_admin = attrs.get("is_admin", False) or "AdministratorAccess" in name
            header = "ADMINISTRATOR ACCESS" if is_admin else "IAM POLICY"
            p_name = "AdministratorAccess" if "AdministratorAccess" in name else name
            badge = "[!] *:*" if is_admin else (f"[!] {formatted_vulns}" if formatted_vulns else "")
            return (header, p_name, badge, is_admin or is_vuln)

        if ntype == "RDS":
            badge = f"[!] {formatted_vulns}" if formatted_vulns else ("[!] VULN-RDS" if is_vuln else "")
            return ("RDS DATABASE", name, badge, is_vuln)

        return (ntype, name, f"[!] {formatted_vulns}" if formatted_vulns else "", is_vuln)

    def export_visualization(self, graph: nx.DiGraph, output_path: str) -> str:
        """Render ONE simple, presentation-ready attack graph communicating the discovered attack chain."""
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # 1. Filter nodes: display only resources genuinely involved in the attack chain
        relevant_nodes: Set[str] = {"INTERNET"} if "INTERNET" in graph else set()

        for n in graph.nodes:
            if n == "INTERNET":
                continue
            # Exclude remediation replacement policies
            if "LeastPrivilege" in n or "Replacement" in n:
                continue
            paths = self.find_attack_paths(graph, n)
            if paths:
                for p in paths:
                    relevant_nodes.update(p["path"])

        # Also include downstream reached nodes from any relevant node (e.g. EC2 -> IAM Role -> Policy)
        for n in list(relevant_nodes):
            for succ in graph.successors(n):
                if "LeastPrivilege" in succ or "Replacement" in succ:
                    continue
                edge_data = graph.get_edge_data(n, succ) or {}
                if edge_data.get("security_relevant", True):
                    relevant_nodes.add(succ)

        # Fallback for isolated lab graphs where no complete attack path from INTERNET exists yet
        if len(relevant_nodes) <= 1:
            for n, d in graph.nodes(data=True):
                if "LeastPrivilege" in n or "Replacement" in n:
                    continue
                # Exclude unattached, non-vulnerable default security groups
                if d.get("type") == "SECURITY_GROUP" and not d.get("is_vulnerable") and graph.degree(n) == 0:
                    continue
                relevant_nodes.add(n)

        # Determine if an EC2 instance is part of the visualization
        has_ec2 = any(graph.nodes[n].get("type") == "EC2" for n in relevant_nodes)

        # 2. Determine Top-to-Bottom 5-Row Layout Coordinates
        pos: Dict[str, Tuple[float, float]] = {}

        if has_ec2:
            # Row 1: INTERNET (Attack Origin)
            # Row 2: S3 BUCKET (independent branch) and SECURITY GROUP
            # Row 3: EC2 INSTANCE
            # Row 4: IAM ROLE
            # Row 5: ADMINISTRATOR ACCESS
            for n in relevant_nodes:
                ntype = graph.nodes[n].get("type")
                if ntype == "INTERNET":
                    pos[n] = (0.48, 0.88)
                elif ntype == "S3":
                    pos[n] = (0.24, 0.69)
                elif ntype == "SECURITY_GROUP":
                    pos[n] = (0.72, 0.69)
                elif ntype == "EC2":
                    pos[n] = (0.72, 0.49)
                elif ntype == "IAM_ROLE":
                    pos[n] = (0.72, 0.29)
                elif ntype == "IAM_POLICY":
                    pos[n] = (0.72, 0.09)
        else:
            # Isolated lab layout (without EC2 instance)
            for n in relevant_nodes:
                ntype = graph.nodes[n].get("type")
                if ntype == "INTERNET":
                    pos[n] = (0.48, 0.88)
                elif ntype == "S3":
                    pos[n] = (0.24, 0.66)
                elif ntype == "SECURITY_GROUP":
                    pos[n] = (0.72, 0.66)
                elif ntype == "IAM_ROLE":
                    pos[n] = (0.72, 0.40)
                elif ntype == "IAM_POLICY":
                    pos[n] = (0.72, 0.16)

        # Fallback for any unpositioned node
        for n in relevant_nodes:
            if n not in pos:
                pos[n] = (0.50, 0.50)

        fig, ax = plt.subplots(figsize=(10.5, 11), dpi=200)
        ax.set_facecolor("#ffffff")
        fig.patch.set_facecolor("#ffffff")

        # 3. Draw Directional Arrows and Short Meaningful Edge Labels
        for u, v, d in graph.edges(data=True):
            if u not in pos or v not in pos or u not in relevant_nodes or v not in relevant_nodes:
                continue
            if d.get("relationship") == "ASSOCIATED_WITH" or not d.get("security_relevant", True):
                continue

            u_type = graph.nodes[u].get("type")
            v_type = graph.nodes[v].get("type")

            # Determine short edge label and arrow styling
            if u_type == "INTERNET" and v_type == "S3":
                edge_label = "PUBLIC ACCESS"
                is_red = True
            elif u_type == "INTERNET" and v_type == "SECURITY_GROUP":
                ports = d.get("ports", [])
                if ports:
                    ports_str = f"TCP {'/'.join(map(str, sorted(ports)))}"
                else:
                    ports_str = "TCP 22/80"
                cidr = d.get("source_cidr", "0.0.0.0/0")
                edge_label = f"{ports_str} • {cidr}"
                is_red = True
            elif u_type == "SECURITY_GROUP" and v_type == "EC2":
                edge_label = "ALLOWS TRAFFIC"
                is_red = True
            elif u_type == "EC2" and v_type == "IAM_ROLE":
                edge_label = "ASSUMES ROLE"
                is_red = False
            elif u_type == "IAM_ROLE" and v_type == "IAM_POLICY":
                edge_label = "GRANTS *:*" if (d.get("is_admin") or "AdministratorAccess" in v) else "GRANTS PERMISSION"
                is_red = False
            else:
                edge_label = d.get("relationship", "").replace("_", " ")
                is_red = d.get("security_relevant", False)

            arrow_color = "#e03131" if is_red else "#343a40"
            arrow_lw = 2.4 if is_red else 2.0

            # Draw directional arrow
            ax.annotate(
                "",
                xy=pos[v],
                xytext=pos[u],
                arrowprops=dict(
                    arrowstyle="-|>",
                    color=arrow_color,
                    lw=arrow_lw,
                    mutation_scale=20,
                    shrinkA=34,
                    shrinkB=34,
                    connectionstyle="arc3,rad=0.0",
                ),
                zorder=3,
            )

            # Draw short edge label
            mid_x = (pos[u][0] + pos[v][0]) / 2.0
            mid_y = (pos[u][1] + pos[v][1]) / 2.0

            ax.text(
                mid_x,
                mid_y,
                edge_label,
                ha="center",
                va="center",
                fontsize=8.5,
                fontweight="bold",
                color=arrow_color,
                bbox=dict(
                    boxstyle="round,pad=0.35,rounding_size=0.2",
                    facecolor="#ffffff",
                    edgecolor=arrow_color if is_red else "#ced4da",
                    linewidth=1.2,
                    alpha=0.98,
                ),
                zorder=5,
            )

        # 4. Draw Simple Rectangular Rounded Node Cards
        for n in relevant_nodes:
            if n not in pos:
                continue

            attrs = graph.nodes[n]
            header, title, badge, is_vuln = self._get_card_details(n, attrs)

            card_lines = [header, title]
            if badge:
                card_lines.append(badge)

            card_text = "\n".join(card_lines)

            border_color = "#e03131" if is_vuln else "#868e96"
            lw = 2.2 if is_vuln else 1.6

            ax.text(
                pos[n][0],
                pos[n][1],
                card_text,
                ha="center",
                va="center",
                fontsize=9.0,
                fontweight="medium",
                color="#212529",
                linespacing=1.35,
                bbox=dict(
                    boxstyle="round,pad=0.6,rounding_size=0.25",
                    facecolor="#ffffff",
                    edgecolor=border_color,
                    linewidth=lw,
                    alpha=0.98,
                ),
                zorder=4,
            )

        # 5. Header Title
        ax.text(
            0.50,
            0.965,
            "CloudSec-Copilot : Attack Dependency Graph",
            ha="center",
            va="center",
            fontsize=15,
            fontweight="bold",
            color="#1864ab",
        )

        ax.set_xlim(0.0, 1.0)
        ax.set_ylim(0.0, 1.0)
        ax.axis("off")

        plt.tight_layout(pad=1.0)
        plt.savefig(output_path, dpi=200, bbox_inches="tight")
        plt.close(fig)

        return output_path

