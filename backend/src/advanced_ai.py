import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from .gnn_engine import SentinelGAT
from .graph_processor import SentinelGraphProcessor
import json
import os
from .utils import calculate_shannon_entropy, get_mc_dropout_prediction
from .agentic_layers import (
    SentinelRiskPropagationAgent, 
    SentinelSelfReflectionAgent,
    SentinelAdversarialMutationAgent,
    SentinelResourceAdaptiveAgent
)

class SentinelNERClassifier:
    """Wrapper for the BERT-NER secret detection model."""
    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForTokenClassification.from_pretrained(model_path)
        
        # CPU Optimization: 8-bit Quantization
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        if self.device.type == 'cpu':
            self.model = torch.quantization.quantize_dynamic(
                self.model, {torch.nn.Linear}, dtype=torch.qint8
            )
            
        self.model.eval()
        self.label_list = ["O", "B-SECRET", "I-SECRET"]
        self.robustness_agent = SentinelAdversarialMutationAgent(self)

    def predict_secrets(self, text):
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = self.model(**inputs).logits
        
        predictions = torch.argmax(outputs, dim=2)
        tokens = self.tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])
        
        findings = []
        current_finding = []
        for token, prediction in zip(tokens, predictions[0]):
            label = self.label_list[prediction.item()]
            if label != "O" and token not in ["[CLS]", "[SEP]", "[PAD]"]:
                clean_token = token.replace("##", "")
                if label == "B-SECRET":
                    if current_finding:
                        findings.append("".join(current_finding))
                    current_finding = [clean_token]
                else:
                    current_finding.append(clean_token)
        
        if current_finding:
            findings.append("".join(current_finding))
            
        # Store findings with more detail
        detailed_findings = []
        current_finding_tokens = []
        current_finding_start_idx = -1
        current_finding_end_idx = -1
        current_finding_label_id = -1

        for i, (token, prediction) in enumerate(zip(tokens, predictions[0])):
            label_id = prediction.item()
            label = self.label_list[label_id]
            
            if token in ["[CLS]", "[SEP]", "[PAD]"]:
                continue

            clean_token = token.replace("##", "")

            if label == "B-SECRET":
                if current_finding_tokens: # If there was a previous finding, save it
                    secret_text = "".join(current_finding_tokens)
                    entropy = calculate_shannon_entropy(secret_text)
                    # Calculate confidence for the entire secret span
                    # This is a simplification; a more robust approach might average token confidences
                    confidence_span = probs[0, current_finding_start_idx:current_finding_end_idx+1, current_finding_label_id]
                    
                    detailed_findings.append({
                        "secret": secret_text,
                        "type": self.label_list[current_finding_label_id],
                        "confidence": float(confidence_span.mean()),
                        "shannon_entropy": round(entropy, 2)
                    })
                
                # Start a new finding
                current_finding_tokens = [clean_token]
                current_finding_start_idx = i
                current_finding_end_idx = i
                current_finding_label_id = label_id
            elif label == "I-SECRET" and current_finding_tokens:
                current_finding_tokens.append(clean_token)
                current_finding_end_idx = i
            else: # "O" label or "I-SECRET" without preceding "B-SECRET"
                if current_finding_tokens: # If a finding was in progress, save it
                    secret_text = "".join(current_finding_tokens)
                    entropy = calculate_shannon_entropy(secret_text)
                    confidence_span = probs[0, current_finding_start_idx:current_finding_end_idx+1, current_finding_label_id]
                    
                    detailed_findings.append({
                        "secret": secret_text,
                        "type": self.label_list[current_finding_label_id],
                        "confidence": float(confidence_span.mean()),
                        "shannon_entropy": round(entropy, 2)
                    })
                current_finding_tokens = []
                current_finding_start_idx = -1
                current_finding_end_idx = -1
                current_finding_label_id = -1
        
        # Save any remaining finding after the loop
        if current_finding_tokens:
            secret_text = "".join(current_finding_tokens)
            entropy = calculate_shannon_entropy(secret_text)
            confidence_span = probs[0, current_finding_start_idx:current_finding_end_idx+1, current_finding_label_id]
            
            detailed_findings.append({
                "secret": secret_text,
                "type": self.label_list[current_finding_label_id],
                "confidence": float(confidence_span.mean()),
                "shannon_entropy": round(entropy, 2)
            })
            
        # Agentic Layer 4: Adversarial Audit (ARI)
        for f in detailed_findings:
            f['robustness_audit'] = self.robustness_agent.calculate_ari(f['secret'])

        return detailed_findings

class SentinelGNNWrapper:
    """Wrapper for the Graph Neural Network (GNN) IaC analysis."""
    def __init__(self, model_path):
        self.processor = SentinelGraphProcessor()
        # Features: [Type, Entropy, FindingCount, Metadata]
        self.model = SentinelGAT(num_node_features=4, num_classes=2, hidden_channels=32)
        self.model.load_state_dict(torch.load(model_path))
        
        # CPU Optimization: 8-bit Quantization
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        if self.device.type == 'cpu':
            self.model = torch.quantization.quantize_dynamic(
                self.model, {torch.nn.Linear}, dtype=torch.qint8
            )
            self.model.eval()
        self.processor = SentinelGraphProcessor()
        self.propagation_agent = SentinelRiskPropagationAgent(self.processor)
        self.reflection_agent = SentinelSelfReflectionAgent()
        self.adaptive_agent = SentinelResourceAdaptiveAgent()

    def analyze_graph(self, file_path):
        graph = self.processor.parse_hcl(file_path)
        if not graph:
            return {"prediction": "Secure", "confidence": 1.0, "uncertainty": 0.0, "risk_propagation": {}, "reflection": {}}
        
        # Agentic Layer 5: Resource-Adaptive Inference
        strategy = self.adaptive_agent.get_inference_strategy(len(graph.nodes()))
        
        if strategy['pruning']:
            self.processor.prune_graph(max_nodes=50)
        
        node_list = list(graph.nodes())
        node_features = []
        for node, data in graph.nodes(data=True):
            node_features.append(data.get('features', [0.0, 0.0, 0.0, 0.0]))
        
        x = torch.tensor(node_features, dtype=torch.float)
        
        edges = []
        for u, v in graph.edges():
            edges.append([node_list.index(u), node_list.index(v)])
        
        if not edges: # Single node case
            edge_index = torch.empty((2, 0), dtype=torch.long)
        else:
            edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

        batch = torch.zeros(x.shape[0], dtype=torch.long)
        
        # MC Dropout for Uncertainty
        mean_probs, variance, predictive_entropy = get_mc_dropout_prediction(
            self.model, 
            {"x": x, "edge_index": edge_index, "batch": batch}, 
            num_samples=10
        )
        
        # Risk Heatmap: Extract Attention Weights
        self.model.eval()
        with torch.no_grad():
            _, (att_edge_index, att_alpha) = self.model(x, edge_index, batch, return_attention=True)
            # Average attention weights across heads
            if att_alpha.dim() > 1:
                att_alpha = att_alpha.mean(dim=1)
            
            # Map edge attention back to nodes (Heatmap)
            node_risks = torch.zeros(x.shape[0])
            for i in range(att_edge_index.shape[1]):
                target_node = att_edge_index[1, i].item()
                node_risks[target_node] += att_alpha[i].item()
            
            # Normalize risks
            if node_risks.max() > 0:
                node_risks = node_risks / node_risks.max()
        
        node_heatmap = {list(graph.nodes())[i]: round(node_risks[i].item(), 3) for i in range(len(node_list))}

        prediction_idx = np.argmax(mean_probs[0])
        prediction_label = "HighRisk" if prediction_idx == 1 else "Secure"
        confidence = float(mean_probs[0][prediction_idx])
        uncertainty = float(predictive_entropy[0])

        # Agentic Layer 1: Risk Propagation
        # Simulate base node predictions for propagation
        base_preds = {node_list[i]: ("HighRisk" if node_risks[i] > 0.7 else "Secure") for i in range(len(node_list))}
        propagated_risk = self.propagation_agent.propagate_risk(base_preds, node_heatmap)

        # Agentic Layer 3: Self-Reflection
        reflection = self.reflection_agent.reflect({
            "confidence": confidence,
            "uncertainty": uncertainty
        })

        # Calculate APS and Configuration Entropy Metrics
        aps_metrics = self.processor.calculate_aps_metrics()

        return {
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "uncertainty": round(uncertainty, 4),
            "node_count": x.shape[0],
            "edge_count": edge_index.shape[1],
            "risk_heatmap": node_heatmap,
            "risk_propagation": propagated_risk,
            "reflection": reflection,
            "aps": aps_metrics
        }
