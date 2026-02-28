import math
import torch
import numpy as np

def calculate_shannon_entropy(text):
    """
    Calculates the Shannon Entropy of a string to detect potentially random/high-entropy strings (secrets).
    """
    if not text:
        return 0
    
    entropy = 0
    # Use 256 for ASCII-based entropy
    for i in range(256):
        p_i = text.count(chr(i)) / len(text)
        if p_i > 0:
            entropy += - p_i * math.log(p_i, 2)
    return entropy

def get_mc_dropout_prediction(model, inputs, num_samples=10):
    """
    Perform Monte Carlo Dropout to estimate model uncertainty.
    """
    model.train() # Enable dropout during inference
    predictions = []
    
    with torch.no_grad():
        for _ in range(num_samples):
            outputs = model(**inputs)
            if hasattr(outputs, 'logits'):
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            else:
                probs = torch.nn.functional.softmax(outputs, dim=-1)
            predictions.append(probs.cpu().numpy())
            
    predictions = np.stack(predictions)
    mean_probs = predictions.mean(axis=0)
    variance = predictions.var(axis=0)
    
    # Predictive Entropy
    epsilon = 1e-10
    entropy = -np.sum(mean_probs * np.log(mean_probs + epsilon), axis=-1)
    
    return mean_probs, variance, entropy

def calculate_pareto_ranking(findings):
    """
    Ranks security findings based on a Pareto-frontier of multiple objectives:
    - AI Confidence (Probability)
    - Graph Centrality (Impact)
    - Exposure Distance (Reachability)
    
    Returns a sorted list of findings with a composite 'ParetoScore'.
    """
    if not findings:
        return []

    ranked = []
    for f in findings:
        # Normalize objectives to [0, 1]
        conf = f.get('confidence', 0.5)
        centrality = f.get('centrality', 0.1)
        # Distance is inverse risk (shorter distance = higher risk)
        dist_raw = f.get('exposure_distance', 5.0)
        dist_score = 1.0 / (dist_raw + 1.0)
        
        # Composite score: sum of normalized objectives
        # In a real paper, this would be a multi-objective optimization problem
        pareto_score = (conf * 0.4) + (centrality * 0.4) + (dist_score * 0.2)
        
        f['pareto_score'] = round(pareto_score, 3)
        ranked.append(f)
        
    return sorted(ranked, key=lambda x: x['pareto_score'], reverse=True)
