import torch
import random
import networkx as nx
import json
import os
from torch_geometric.data import Data, Dataset

class SentinelGraphDataset(Dataset):
    """
    Synthetic dataset for training the SentinelGAT model.
    Generates graphs representing cloud infrastructure and labels them by security risk.
    """
    def __init__(self, root, transform=None, pre_transform=None, pre_filter=None, num_samples=1000):
        self.num_samples = num_samples
        super(SentinelGraphDataset, self).__init__(root, transform, pre_transform, pre_filter)
        self.data_list = []
        self._generate_synthetic_data()

    def _generate_synthetic_data(self):
        print(f"Generating {self.num_samples} synthetic graphs...")
        for i in range(self.num_samples):
            # 50/50 split Secure vs HighRisk
            is_secure = (i < self.num_samples // 2)
            graph_data = self._create_sample_graph(is_secure)
            self.data_list.append(graph_data)

    def _create_sample_graph(self, is_secure):
        G = nx.DiGraph()
        num_nodes = random.randint(3, 8)
        
        # Nodes: [TypeID (normalized), ConfigEntropy, FindingCount]
        # Label: 0 (Secure), 1 (HighRisk)
        label = 0 if is_secure else 1
        
        node_features = []
        for j in range(num_nodes):
            type_id = random.randint(1, 6)
            entropy = random.uniform(0, 5) if is_secure else random.uniform(5, 10)
            finding_count = 0 if is_secure else random.randint(1, 10)
            
            features = [
                float(type_id) / 6.0, 
                entropy / 10.0, 
                float(finding_count) / 10.0,
                random.uniform(0, 1) # Metadata diversity
            ]
            node_features.append(features)
            G.add_node(j)

        # Edges
        edges = []
        for j in range(num_nodes - 1):
            source = j
            target = random.randint(j + 1, num_nodes - 1)
            edges.append([source, target])
            edges.append([target, source]) # Bidirectional for simplicity

        x = torch.tensor(node_features, dtype=torch.float)
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        y = torch.tensor([label], dtype=torch.long)

        return Data(x=x, edge_index=edge_index, y=y)

    def len(self):
        return len(self.data_list)

    def get(self, idx):
        return self.data_list[idx]

if __name__ == "__main__":
    dataset = SentinelGraphDataset(root="f:/Fullbright Scholarship/X-CloudSentinel/backend/data/graph_data", num_samples=100)
    print(f"Dataset generated. Sample count: {len(dataset)}")
    sample = dataset[0]
    print(f"Sample node features shape: {sample.x.shape}")
    print(f"Sample edge index shape: {sample.edge_index.shape}")
    print(f"Sample label: {sample.y}")

