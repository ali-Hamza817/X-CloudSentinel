import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv, global_mean_pool

class SentinelGAT(torch.nn.Module):
    """
    Graph Attention Network (GAT) for Infrastructure-as-Code Security Analysis.
    This model classifies the overall security posture of a resource dependency graph.
    """
    def __init__(self, num_node_features, num_classes, hidden_channels=64, heads=4):
        super(SentinelGAT, self).__init__()
        # First GAT layer (Multi-head attention)
        self.conv1 = GATConv(num_node_features, hidden_channels, heads=heads)
        
        # Second GAT layer
        self.conv2 = GATConv(hidden_channels * heads, hidden_channels, heads=1)
        
        # Final fully connected layer for graph classification
        self.lin = torch.nn.Linear(hidden_channels, num_classes)

    def forward(self, x, edge_index, batch, return_attention=False):
        # 1. Obtain node embeddings
        x, (edge_index_1, alpha_1) = self.conv1(x, edge_index, return_attention_weights=True)
        x = x.relu()
        x, (edge_index_2, alpha_2) = self.conv2(x, edge_index_1, return_attention_weights=True)
        x = x.relu()

        # 2. Readout layer: Global pooling
        x_pool = global_mean_pool(x, batch)

        # 3. Final classifier
        x_out = F.dropout(x_pool, p=0.5, training=self.training)
        x_logits = self.lin(x_out)
        
        if return_attention:
            return x_logits, (edge_index_1, alpha_1)
        return x_logits

def save_model(model, path):
    torch.save(model.state_dict(), path)

def load_model(path, num_node_features, num_classes):
    model = SentinelGAT(num_node_features, num_classes)
    model.load_state_dict(torch.load(path))
    model.eval()
    return model
