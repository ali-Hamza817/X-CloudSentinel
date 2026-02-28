import networkx as nx
import json
import os
import numpy as np
import hcl2

class SentinelGraphProcessor:
    """
    Converts Terraform HCL files into a Directed Graph representation.
    This is used as input for the Graph Neural Network (GNN).
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.resource_type_mapping = {}
        self.next_resource_type_id = 0
        self.exposure_nodes = []

    def parse_hcl(self, file_path):
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'r') as f:
            try:
                data = hcl2.load(f)
                return self._build_graph(data)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")
                return None

    def _build_graph(self, hcl_data):
        self.graph.clear()
        
        # 1. Add Resource Nodes
        if 'resource' in hcl_data:
            for resource_block in hcl_data['resource']:
                for res_type, res_details in resource_block.items():
                    for res_name, res_config in res_details.items():
                        node_id = f"{res_type}.{res_name}"
                        
                        # Get or assign resource type ID
                        if res_type not in self.resource_type_mapping:
                            self.resource_type_mapping[res_type] = self.next_resource_type_id
                            self.next_resource_type_id += 1
                        resource_type_id = self.resource_type_mapping[res_type]

                        # Extract features
                        features, is_exposed = self._extract_features(res_config)

                        self.graph.add_node(node_id, 
                                          type='resource', 
                                          resource_type=res_type,
                                          resource_type_id=resource_type_id,
                                          config=json.dumps(res_config),
                                          features=features,
                                          exposed=is_exposed)
                        
                        if is_exposed:
                            self.exposure_nodes.append(node_id)
                        
                        # 2. Extract Implicit Dependencies (References)
                        self._find_references(node_id, res_config)
                        
        return self.graph

    def _find_references(self, source_node, config):
        """Recursively find strings that look like resource references"""
        if isinstance(config, str):
            # Simple heuristic for references like aws_s3_bucket.name.id
            if '.' in config and not config.startswith('http'):
                self.graph.add_edge(source_node, config, label='REFS')
        elif isinstance(config, dict):
            for v in config.values():
                self._find_references(source_node, v)
        elif isinstance(config, list):
            for item in config:
                self._find_references(source_node, item)

        # Feature: Check for exposure to 0.0.0.0/0
        is_exposed = False
        config_str = json.dumps(config)
        if "0.0.0.0/0" in config_str:
            is_exposed = True
        
        features.append(1 if is_exposed else 0)
        
        return features, is_exposed

    def calculate_aps_metrics(self):
        """
        Calculates Attack Propagation Score (APS) and Configuration Entropy (CE).
        """
        metrics = {
            "exposure_distance": -1,
            "critical_hubs": [],
            "privilege_escalation_risk": "Low",
            "configuration_entropy": 0.0,
            "wildcard_findings": []
        }

        if self.graph.number_of_nodes() == 0:
            return metrics

        # 1. Exposure Distance & Wildcard Detection (Hybrid)
        wildcards = []
        for node, data in self.graph.nodes(data=True):
            config = data.get('config', '{}')
            if '"*"' in config or "'*'" in config:
                wildcards.append({"node": node, "type": "PrivilegeWildcard"})
        
        metrics["wildcard_findings"] = wildcards

        if self.exposure_nodes:
            # ... (existing exposure logic)
            distances = []
            for node in self.graph.nodes():
                min_dist = float('inf')
                for exp_node in self.exposure_nodes:
                    try:
                        dist = nx.shortest_path_length(self.graph, source=node, target=exp_node)
                        min_dist = min(min_dist, dist)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
                if min_dist != float('inf'):
                    distances.append(min_dist)
            
            if distances:
                metrics["exposure_distance"] = round(sum(distances) / len(distances), 2)

        # 2. Critical Hubs (Degree Centrality)
        # ... (existing centrality logic)
        try:
            centrality = nx.degree_centrality(self.graph)
            sorted_centrality = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            metrics["critical_hubs"] = [{"node": n, "score": round(s, 3)} for n, s in sorted_centrality[:3]]
        except:
            pass

        # 3. Configuration Entropy (CE) - Statistical Variance
        security_flags = []
        for node, data in self.graph.nodes(data=True):
            # Extract common security-relevant binary flags
            config = data.get('config', '').lower()
            flags = [
                'encryption' in config and 'true' in config,
                'public' in config and 'false' in config,
                'logging' in config and 'true' in config,
                'versioning' in config and 'true' in config
            ]
            security_flags.append(sum(flags))
        
        if security_flags:
            # Entropy = variance in security posture across the graph
            metrics["configuration_entropy"] = round(float(np.var(security_flags)), 3)

        # 4. Privilege Escalation Risk
        if any(self.graph.nodes[n].get('resource_type') in ['aws_iam_policy', 'aws_iam_role', 'aws_iam_user_policy'] for n in self.graph.nodes()):
            metrics["privilege_escalation_risk"] = "Moderate (IAM Present)"

        return metrics

    def prune_graph(self, max_nodes=50):
        """
        Reduces graph complexity for large projects by sampling critical nodes.
        Uses degree centrality to preserve the most impactful resources.
        """
        if self.graph.number_of_nodes() <= max_nodes:
            return self.graph

        # Calculate centrality
        centrality = nx.degree_centrality(self.graph)
        
        # Sort by importance and exposure
        # We always keep exposure nodes
        nodes_to_keep = set(self.exposure_nodes)
        
        # Add high-centrality nodes until we hit max_nodes
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        for node, score in sorted_nodes:
            if len(nodes_to_keep) >= max_nodes:
                break
            nodes_to_keep.add(node)
            
        # Create a subgraph
        self.graph = self.graph.subgraph(nodes_to_keep).copy()
        return self.graph

    def export_to_json(self):
        return nx.node_link_data(self.graph)

if __name__ == "__main__":
    # Test with a sample file if available
    processor = SentinelGraphProcessor()
    print("Graph Processor initialized.")
