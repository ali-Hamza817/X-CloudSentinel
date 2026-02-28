import numpy as np
import networkx as nx
import base64
import random
import os
import psutil

class SentinelRiskPropagationAgent:
    """
    Autonomously reasons over infrastructure graphs to detect transitive vulnerability paths.
    """
    def __init__(self, graph_processor):
        self.processor = graph_processor

    def propagate_risk(self, base_predictions, attention_heatmap):
        """
        Propagates risk from high-risk nodes (pred=HighRisk) through the graph
        using GAT attention weights as 'conductors'.
        """
        graph = self.processor.graph
        if graph.number_of_nodes() == 0:
            return {}

        propagated_scores = {node: 0.0 for node in graph.nodes()}
        
        # Initial 'Heat' from direct AI detection
        for node, heatmap_score in attention_heatmap.items():
            if node in base_predictions and base_predictions[node] == "HighRisk":
                propagated_scores[node] = 1.0 # Max heat for primary detection
            else:
                propagated_scores[node] = heatmap_score

        # Propagation Loop (2 steps of BFS-style decay)
        for _ in range(2):
            new_scores = propagated_scores.copy()
            for u, v in graph.edges():
                # Propagate from higher to lower
                # Weight by attention if available, else 0.5
                decay = 0.6
                new_scores[v] = max(new_scores[v], propagated_scores[u] * decay)
                new_scores[u] = max(new_scores[u], propagated_scores[v] * decay)
            propagated_scores = new_scores

        return {node: round(score, 3) for node, score in propagated_scores.items()}

class SentinelSQIMaximizationAgent:
    """
    Goal-oriented agent that prioritize fixes based on their objective impact on the SQI.
    """
    def calculate_remediation_ranking(self, current_sqi, findings, weights):
        """
        Performs an 'Ablation Simulation' to see how SQI improves if specific issues are fixed.
        """
        impact_ranking = []
        
        for finding in findings:
            # Simulate fix: reduce finding's contribution to zero
            # Delta SQI = Impact on the overall score
            severity_factor = finding.get('severity_score', 0.5)
            weight = weights.get(finding['type'], 0.1)
            
            delta_sqi = severity_factor * weight * 100 # Rough linear impact
            
            impact_ranking.append({
                "finding_id": finding.get('id', 'unknown'),
                "description": finding.get('description', ''),
                "delta_sqi": round(delta_sqi, 2),
                "priority": "High" if delta_sqi > 10 else "Medium"
            })
            
        # Rank by Delta SQI descending
        return sorted(impact_ranking, key=lambda x: x['delta_sqi'], reverse=True)

class SentinelSelfReflectionAgent:
    """
    Uncertainty-aware agent that monitors model stability and flags low-trust results.
    """
    def reflect(self, prediction_result):
        """
        Analyzes confidence and predictive entropy to decide if a 'Deep Scan' is required.
        """
        confidence = prediction_result.get('confidence', 0.0)
        uncertainty = prediction_result.get('uncertainty', 0.0)
        
        reflection = {
            "trust_level": "High",
            "action": "Proceed",
            "remark": "Model is confident in its assessment."
        }
        
        # Self-Reflection Logic: High Entropy or Low Confidence = Low Trust
        if uncertainty > 0.4 or confidence < 0.6:
            reflection["trust_level"] = "Low"
            reflection["action"] = "Trigger Deep Relational Scan"
            reflection["remark"] = "Model stability is low. Transitive analysis prioritized."
        elif uncertainty > 0.15:
            reflection["trust_level"] = "Moderate"
            reflection["action"] = "Alert User for Manual Review"
            reflection["remark"] = "Nuanced finding. Confidence is within bounds but stability is average."
            
        return reflection

class SentinelAdversarialMutationAgent:
    """
    Autonomously audits the robustness of security detectors (e.g., secrets).
    """
    def __init__(self, ner_classifier):
        self.ner_classifier = ner_classifier

    def calculate_ari(self, secret):
        """
        Calculates the Adversarial Robustness Index (ARI) by attempting to 
        obfuscate a detected secret and checking if the AI can still find it.
        """
        mutations = [
            ("Base64", base64.b64encode(secret.encode()).decode()),
            ("Concat", f"{secret[:len(secret)//2]}' + '{secret[len(secret)//2:]}"),
            ("Substitution", secret.replace('a', '4').replace('e', '3').replace('i', '1'))
        ]
        
        detections = 0
        for name, mutated in mutations:
            # Check if NER can detect the mutated version
            findings = self.ner_classifier.predict_secrets(mutated)
            if any(mutated in f.get('secret', '') or secret in f.get('secret', '') for f in findings):
                detections += 1
                
        ari_score = detections / len(mutations)
        return {
            "ari_score": round(ari_score, 2),
            "robustness": "High" if ari_score > 0.6 else "Low (Bypass Possible)",
            "mutations_tested": len(mutations)
        }

class SentinelResourceAdaptiveAgent:
    """
    Monitors system load and project scale to adapt inference complexity.
    Keep X-CloudSentinel lightweight and less resource intensive.
    """
    def get_inference_strategy(self, node_count):
        """
        Decides on the inference mode based on graph size and CPU usage.
        """
        cpu_usage = psutil.cpu_percent()
        
        # Adaptive Logic
        if node_count > 100 or cpu_usage > 70:
            return {
                "mode": "Efficient",
                "pruning": True,
                "attention_heads": 1,
                "reasoning_depth": "Shallow",
                "message": "Resource-Adaptive mode active: Pruning non-critical nodes."
            }
        
        return {
            "mode": "HighPrecision",
            "pruning": False,
            "attention_heads": 4,
            "reasoning_depth": "Full",
            "message": "System resources optimal: Full precision scan."
        }

