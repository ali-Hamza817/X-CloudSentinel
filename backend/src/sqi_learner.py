import numpy as np
from sklearn.linear_model import LinearRegression
import os

class SentinelSQILearner:
    """
    Learns optimal weights for the SQI formula using regression.
    Transforms SQI from a manual heuristic into a data-driven metric.
    """
    def __init__(self, model_path="f:/Fullbright Scholarship/X-CloudSentinel/backend/models/sqi_weights.npy"):
        self.model_path = model_path
        # Default weights (Heuristic fallback)
        self.weights = {
            "secret_leakage": 0.45,
            "misconfiguration": 0.25,
            "architectural_risk": 0.20,
            "config_entropy": 0.10
        }
        self.load_weights()

    def train_weights(self, features, targets):
        """
        Features: Matrix of [SL_Count, MC_Count, AR_Score, CE_Score]
        Targets: Global HighRisk Probability from GNN/DistilBERT
        """
        if len(features) < 5: # Need minimum data points
            return self.weights

        model = LinearRegression(positive=True) # Ensure security weights are positive
        model.fit(features, targets)
        
        # Normalize weights to sum to 1.0
        raw_weights = model.coef_
        normalized = raw_weights / np.sum(raw_weights)
        
        self.weights = {
            "secret_leakage": float(normalized[0]),
            "misconfiguration": float(normalized[1]),
            "architectural_risk": float(normalized[2]),
            "config_entropy": float(normalized[3])
        }
        self.save_weights()
        return self.weights

    def save_weights(self):
        np.save(self.model_path, self.weights)

    def load_weights(self):
        if os.path.exists(self.model_path):
            try:
                self.weights = np.load(self.model_path, allow_pickle=True).item()
            except:
                pass

    def get_weights(self):
        return self.weights

