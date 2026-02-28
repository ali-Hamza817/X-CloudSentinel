from flask import Flask, request, jsonify
from flask_cors import CORS
from src.classifier import SentinelClassifier
from src.explainer import SentinelExplainer
from src.remediator import SentinelRemediator
from src.database import init_db, log_scan, get_history
from src.advanced_ai import SentinelGNNWrapper, SentinelNERClassifier
from src.network_security import SentinelNetworkScanner
from src.sqi_learner import SentinelSQILearner
from src.agentic_layers import SentinelSQIMaximizationAgent
import time
import os

from functools import wraps

app = Flask(__name__)
CORS(app)

# API Security Configuration
X_CLOUDSENTINEL_API_KEY = os.environ.get("X_CLOUDSENTINEL_API_KEY", "X-CloudSentinel-Research-2026")

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-API-KEY') != X_CLOUDSENTINEL_API_KEY:
            return jsonify({"error": "Unauthorized access. Invalid API Key."}), 401
        return f(*args, **kwargs)
    return decorated_function

# Initialize DB on startup
init_db()

# Load model and explainer
MODEL_PATH = "f:/Fullbright Scholarship/SentinelIQ/backend/models/x-cloudsentinel-distilbert"
classifier = SentinelClassifier(MODEL_PATH)
explainer = SentinelExplainer(classifier)
remediator = None # Initialize lazily to speed up startup

# Phase 6 Advanced Models
GNN_MODEL_PATH = "f:/Fullbright Scholarship/SentinelIQ/backend/models/x-cloudsentinel-gnn.pt"
NER_MODEL_PATH = "f:/Fullbright Scholarship/SentinelIQ/backend/models/x-cloudsentinel-ner"
gnn_analyzer = SentinelGNNWrapper(GNN_MODEL_PATH)
ner_analyzer = SentinelNERClassifier(NER_MODEL_PATH)
network_scanner = SentinelNetworkScanner()
sqi_learner = SentinelSQILearner()
sqi_agent = SentinelSQIMaximizationAgent()

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Welcome to X-CloudSentinel AI Backend (Secure Mode)",
        "version": "1.0.0",
        "endpoints": ["/health", "/analyze", "/explain", "/history", "/remediate"]
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": os.path.exists(MODEL_PATH),
        "timestamp": time.time()
    })

@app.route('/analyze', methods=['POST'])
@require_api_key
def analyze():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
    
    text = data['text']
    file_path = data.get('filePath', 'unknown')
    
    result = classifier.predict(text)
    
    # Log to history
    log_scan(
        file_path, 
        0, # SQI placeholder, will be updated from extension or calculated here
        0, # Finding count placeholder
        result['prediction'],
        result
    )
    
    return jsonify(result)

@app.route('/analyze-advanced', methods=['POST'])
@require_api_key
def analyze_advanced():
    """Phase 6: Advanced SOTA Analysis covering GNN and BERT-NER"""
    try:
        data = request.json
        if not data or 'text' not in data:
            return jsonify({"error": "No text provided"}), 400
        
        text = data['text']
        file_path = data.get('filePath', 'unknown')
        
        # 1. BERT-NER Secret Detection (Contextual)
        secrets_found = ner_analyzer.predict_secrets(text)
        
        # 2. GNN-IaC Risk Analysis (Relational)
        gnn_result = {"prediction": "Skipped (No file)", "confidence": 0.0}
        if os.path.exists(file_path) and file_path.endswith('.tf'):
            gnn_result = gnn_analyzer.analyze_graph(file_path)
        
        # 3. Network Security Analysis (Malicious URLs/Ports)
        network_result = network_scanner.scan(text)
        
        # 4. Standard DistilBERT classification
        baseline_result = classifier.predict(text)
        
        # 5. Agentic SQI Maximization (Prioritize fixes)
        weights = sqi_learner.get_weights()
        findings = []
        for s in secrets_found: findings.append({"type": "secret_leakage", "severity_score": 0.9, "id": s.get('token', 'secret')})
        if gnn_result['prediction'] == "HighRisk": findings.append({"type": "architectural_risk", "severity_score": 0.8, "id": "GNN_RISK"})
        
        remediation_ranking = sqi_agent.calculate_remediation_ranking(85.0, findings, weights)

        result = {
            "baseline": baseline_result,
            "advanced": {
                "secrets_ner": {
                    "count": len(secrets_found),
                    "findings": secrets_found
                },
                "gnn_iac": gnn_result,
                "network_security": network_result,
                "sqi_weights": weights,
                "agentic_remediation": remediation_ranking
            },
            "overall_risk": "High" if (
                baseline_result['prediction'] == "HighRisk" or 
                gnn_result['prediction'] == "HighRisk" or 
                len(secrets_found) > 0 or 
                len(network_result['vulnerable_ports']) > 0 or 
                len(network_result['suspicious_urls']) > 0
            ) else "Low"
        }
        
        return jsonify(result)
    except Exception as e:
        print(f"ERROR in analyze_advanced: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/history', methods=['GET'])
@require_api_key
def history():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_history(limit))

@app.route('/explain', methods=['POST'])
@require_api_key
def explain():
    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
    
    text = data['text']
    explanation = explainer.explain(text)
    
    return jsonify(explanation)

@app.route('/remediate', methods=['POST'])
@require_api_key
def remediate():
    global remediator
    data = request.json
    if not data or 'text' not in data or 'title' not in data:
        return jsonify({"error": "Missing text or title"}), 400
    
    if remediator is None:
        try:
            remediator = SentinelRemediator()
        except Exception as e:
            return jsonify({"error": f"Model loading failed: {str(e)}"}), 503
    
    result = remediator.suggest_fix(data['text'], data['title'])
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)

