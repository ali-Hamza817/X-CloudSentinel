# 🛡️ X-CloudSentinel
### Explainable Cloud Soldier Guard: AI-Native Security for DevSecOps

**X-CloudSentinel** is a research-grade VS Code extension that provides SOTA AI-powered cloud security analysis, secret leakage detection, and IaC misconfiguration scanning.

[![GitHub Repo](https://img.shields.io/badge/GitHub-X--CloudSentinel-blue?logo=github)](https://github.com/ali-Hamza817/X-CloudSentinel)

---

## 🚀 Key Features
- **GNN-Powered Relational Scan**: Detects transitive vulnerabilities in Terraform/K8s graphs.
- **Contextual BERT-NER Secrets**: Distinguishes credentials from random tokens using usage context.
- **Explainable AI (SHAP)**: Provides mathematical justification for every risk classification.
- **Security Quality Index (SQI)**: A novel, data-driven metric for quantifying project risk.
- **Agentic Reasoning**: Autonomous risk propagation and remediation prioritization.
- **Real-time Diagnostics**: Get inline warnings with remediation steps as you type.
- **Interactive Dashboard**: A premium, dark-themed dashboard to visualize your overall security posture.

## 🛠️ Components

1. **Secret Detector**: Scans for AWS keys, GCP credentials, JWTs, and 10+ other secret types.
2. **IaC Scanner**: Validates Terraform resources (S3, RDS, EBS) and Kubernetes manifests.
3. **IAM Evaluator**: Checks for overly permissive AWS IAM policies (Wildcards, Admin access).
4. **Docker Analyzer**: Detects insecure Dockerfile practices (Root user, :latest tags).

## 📥 Installation

1. Install the extension from the VS Code Marketplace.
2. Ensure you have the [X-CloudSentinel Backend](https://github.com/username/X-CloudSentinel-Backend) running.
3. Extension settings:
   - `X-CloudSentinel.backendUrl`: URL of the Flask API (default: `http://localhost:5000`)
   - `X-CloudSentinel.enableAI`: Enable/Disable AI classification functionality.

## ⚙️ Configuration

| Setting | Type | Description |
|---|---|---|
| `X-CloudSentinel.backendUrl` | `string` | The URL of the X-CloudSentinel Flask Backend. |
| `X-CloudSentinel.enableAI` | `boolean` | Whether to use the AI model for additional classification. |
| `X-CloudSentinel.scanOnSave` | `boolean` | Automatically scan files when saved. |

## 📄 License

MIT © 2024 X-CloudSentinel Project. Part of the Fullbright Scholarship Cloud Security Research.

