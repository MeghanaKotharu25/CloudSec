from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Set

import networkx as nx

from cloudsec_copilot.discovery.models import InfrastructureStateModel


class CloudGraphBuilder:
    """Creates graph relationships between cloud resources and computes blast radius."""

    @staticmethod
    def _normalize_iam_ref(value: str | None) -> str | None:
        if not value:
            return None
        if ":role/" in value:
            return value.split(":role/")[-1]
        if ":instance-profile/" in value:
            return value.split(":instance-profile/")[-1]
        return value.split("/")[-1] if "/" in value else value

    def build(self, inventory: InfrastructureStateModel) -> nx.DiGraph:
        graph = nx.DiGraph()
        resources = inventory.resources

        graph.add_node("INTERNET", type="Internet", resource="internet")

        for instance in resources.ec2_instances:
            node = f"EC2:{instance.instance_id}"
            graph.add_node(node, type="EC2", resource=instance.instance_id)
            for sg in instance.security_groups:
                sg_node = f"SG:{sg}"
                graph.add_node(sg_node, type="SecurityGroup", resource=sg)
                graph.add_edge(node, sg_node)

        for role in resources.iam_roles:
            role_node = f"IAM:{role.role_name}"
            graph.add_node(role_node, type="IAMRole", resource=role.role_name)
            for policy in role.attached_policies:
                policy_node = f"POLICY:{policy}"
                graph.add_node(policy_node, type="IAMPolicy", resource=policy)
                graph.add_edge(role_node, policy_node)

        for bucket in resources.s3_buckets:
            bucket_node = f"S3:{bucket.name}"
            graph.add_node(bucket_node, type="S3Bucket", resource=bucket.name)
            if bucket.is_public or bucket.acl_public or bucket.policy_public:
                graph.add_edge("INTERNET", bucket_node)

        for db in resources.rds_instances:
            db_node = f"RDS:{db.db_instance_identifier}"
            graph.add_node(db_node, type="RDS", resource=db.db_instance_identifier)

        for instance in resources.ec2_instances:
            resolved_profile = self._normalize_iam_ref(instance.iam_instance_profile)
            if not resolved_profile:
                continue
            role_node = f"IAM:{resolved_profile}"
            if role_node in graph:
                graph.add_edge(f"EC2:{instance.instance_id}", role_node)

        for sg in resources.security_groups:
            sg_node = f"SG:{sg.group_id}"
            graph.add_node(sg_node, type="SecurityGroup", resource=sg.group_id)
            if any(rule.cidr_ip == "0.0.0.0/0" for rule in sg.inbound_rules):
                graph.add_edge("INTERNET", sg_node)

        return graph

    def blast_radius(self, graph: nx.DiGraph, source: str) -> List[str]:
        if source not in graph:
            return []

        queue = deque([source])
        visited: Set[str] = {source}
        reachable: List[str] = []

        while queue:
            current = queue.popleft()
            for neighbor in graph.successors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    reachable.append(neighbor)

        return reachable

    def export_visualization(self, graph: nx.DiGraph, output_path: str) -> str:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        pos = nx.spring_layout(graph, seed=42)
        nx.draw(graph, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=1800)
        plt.savefig(output_path, dpi=150)
        plt.close()
        return output_path
