# X-CloudSentinel — AI-Powered Cloud Security Extension

X-CloudSentinel is a powerful VS Code extension designed to bring the **Shift-Left** security paradigm to your DevSecOps workflow. It provides real-time analysis of Infrastructure-as-Code (IaC), secrets, and IAM policies using a combination of high-speed static analysis and advanced AI classification.

![Dashboard Preview](https://raw.githubusercontent.com/username/X-CloudSentinel/main/media/preview.png)

## 🚀 Key Features

- **Multi-Engine Static Analysis**: Detects over 50+ security patterns in Terraform, Kubernetes, Docker, and AWS IAM.
- **AI Classification**: Uses a fine-tuned **DistilBERT** model to categorize security risks into 4 severity classes.
- **Explainable AI (SHAP)**: Understand *why* a piece of code was flagged with token-level highlights.
- **Security Quality Index (SQI)**: A holistic security metric (0-100) that weights different risk factors automatically.
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

