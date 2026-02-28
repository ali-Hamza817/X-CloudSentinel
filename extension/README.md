# X-CloudSentinel 🛡️

**AI-Native Cloud Security Analysis through Graph Neural Networks and Contextual Transformers.**

X-CloudSentinel is a research-grade security extension for VS Code that elevates Infrastructure-as-Code (IaC) auditing to the state-of-the-art. Unlike traditional static analysis tools, X-CloudSentinel uses **Graph Neural Networks (GNN)** to understand relational risks and **BERT-based NER** to detect secrets in context.

---

## 🚀 Key Features

### 🕸️ Relational IaC Scan (GNN)
Analyze Terraform and Kubernetes manifests as a property graph. Detect "transitive" vulnerabilities where a misconfiguration in one resource exposes another.

### 🔑 Contextual Secret Detection (BERT-NER)
Move beyond regex. Our Transformer-based NER model understands the programmatic context of your code, distinguishing between random GUIDs and actual high-risk credentials.

### 📊 Security Quality Index (SQI)
A novel, all-in-one security metric (0-100) that summarizes your project's risk posture across Secret Leakage, Misconfigurations, Access Risks, and Configuration Entropy.

### 🤖 Autonomous Agentic Reasoning
- **Attack Propagation Agent**: Detects how deep a vulnerability spreads.
- **SQI Maximization Agent**: Ranks fixes by their objective impact on security.
- **Self-Reflection Agent**: Monitors AI confidence to ensure high-trust results.

### 🛡️ Privacy-First & Offline
All AI models run locally on your machine. X-CloudSentinel never sends your code to external servers (Zero-Trust AI).

---

## 🛠️ Commands & Shortcuts

- `Ctrl + Shift + A`: **[SOTA] Run Advanced Agentic Scan** — Generates a comprehensive, explainable security report in the Output channel.
- `X-CloudSentinel: Show Security Dashboard`: Opens the rich, visual dashboard with SQI gauges and SHAP explanations.
- `X-CloudSentinel: Scan Current File`: Performs a standard real-time check.

---

## 📦 Requirements

- **X-CloudSentinel Backend**: Requires the local Python backend to be running for AI features.
  - Clone: `https://github.com/X-CloudSentinel/X-CloudSentinel`
  - Run: `python app.py`

---

## 🎓 Research Credits
X-CloudSentinel is a product of advanced research into GNNs, Transformers, and Bayesian Uncertainty in Cloud Security. It represents a "Peak SOTA" implementation for AI-Native DevSecOps.

---
*Developed with ❤️ for the full-spectrum security researcher.*

