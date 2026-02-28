import torch
from torch_geometric.loader import DataLoader
from gnn_engine import SentinelGAT
from generate_graph_data import SentinelGraphDataset
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score

def train_gnn():
    print("Setting up GNN Training...")
    
    # 1. Load Data
    dataset = SentinelGraphDataset(root="f:/Fullbright Scholarship/X-CloudSentinel/backend/data/graph_data", num_samples=500)
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_dataset, test_dataset = torch.utils.data.random_split(dataset, [train_size, test_size])
    
    loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

    # 2. Initialize Model
    # Features: [Type, Entropy, FindingCount, Metadata]
    model = SentinelGAT(num_node_features=4, num_classes=2, hidden_channels=32)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    criterion = torch.nn.CrossEntropyLoss()

    # 3. Training Loop
    model.train()
    print("Beginning epochs...")
    for epoch in range(1, 101):
        total_loss = 0
        for data in loader:
            optimizer.zero_grad()
            out = model(data.x, data.edge_index, data.batch)
            loss = criterion(out, data.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        if epoch % 10 == 0:
            print(f'Epoch {epoch:03d}, Loss: {total_loss/len(loader):.4f}')

    # 4. Evaluation
    model.eval()
    all_preds = []
    all_labels = []
    for data in test_loader:
        out = model(data.x, data.edge_index, data.batch)
        pred = out.argmax(dim=1)
        all_preds.extend(pred.tolist())
        all_labels.extend(data.y.tolist())

    acc = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds)
    
    print("\n--- Final GNN Metrics ---")
    print(f"Accuracy: {acc:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # 5. Save the weights
    save_path = "f:/Fullbright Scholarship/X-CloudSentinel/backend/models/X-CloudSentinel-gnn.pt"
    torch.save(model.state_dict(), save_path)
    print(f"Model weights saved to {save_path}")

if __name__ == "__main__":
    train_gnn()

