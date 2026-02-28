/**
 * X-CloudSentinel - Secret Detector
 * Regex-based detection of hardcoded secrets, API keys, tokens, and credentials
 */

import { SecurityFinding, Severity, FindingCategory } from '../types';

/** A secret detection pattern */
interface SecretPattern {
    name: string;
    regex: RegExp;
    severity: Severity;
    description: string;
    remediation: string;
    cweId: string;
    ruleId: string;
}

/** All secret detection patterns */
const SECRET_PATTERNS: SecretPattern[] = [
    // ========== AWS ==========
    {
        name: 'AWS Access Key ID',
        regex: /(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])/g,
        severity: Severity.CRITICAL,
        description: 'AWS Access Key ID detected. Hardcoded AWS credentials can lead to unauthorized access to cloud resources, data breaches, and significant financial liability.',
        remediation: 'Remove the hardcoded key and use AWS IAM roles, environment variables, or AWS Secrets Manager instead.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-001'
    },
    {
        name: 'AWS Secret Access Key',
        regex: /(?:aws_secret_access_key|secret_key|secretkey|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
        severity: Severity.CRITICAL,
        description: 'AWS Secret Access Key detected. This credential paired with an Access Key ID provides full access to AWS services.',
        remediation: 'Remove the hardcoded secret key and use AWS IAM roles, environment variables, or AWS Secrets Manager.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-002'
    },

    // ========== Azure ==========
    {
        name: 'Azure Storage Account Key',
        regex: /AccountKey\s*=\s*([A-Za-z0-9+/=]{86,88})/g,
        severity: Severity.CRITICAL,
        description: 'Azure Storage Account Key detected. This key provides full access to Azure Storage resources.',
        remediation: 'Use Azure Managed Identities or store the key in Azure Key Vault.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-003'
    },
    {
        name: 'Azure Connection String',
        regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+/g,
        severity: Severity.CRITICAL,
        description: 'Azure Storage Connection String detected with embedded credentials.',
        remediation: 'Store connection strings in Azure Key Vault or use Managed Identities.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-004'
    },

    // ========== GCP ==========
    {
        name: 'GCP Service Account Key',
        regex: /"type"\s*:\s*"service_account"/g,
        severity: Severity.HIGH,
        description: 'GCP Service Account Key file detected. These JSON key files should never be committed to source control.',
        remediation: 'Use GCP Workload Identity Federation or store keys in Secret Manager. Add *.json key files to .gitignore.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-005'
    },
    {
        name: 'GCP API Key',
        regex: /AIza[0-9A-Za-z_-]{35}/g,
        severity: Severity.HIGH,
        description: 'Google Cloud API Key detected. Exposed API keys can be abused to consume cloud resources or access restricted APIs.',
        remediation: 'Restrict the API key by application, IP address, or API. Store in environment variables or Secret Manager.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-006'
    },

    // ========== Generic Secrets ==========
    {
        name: 'Generic API Key',
        regex: /(?:api[_-]?key|apikey|api_secret|api_token)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']/gi,
        severity: Severity.HIGH,
        description: 'Generic API key/token detected in code. Hardcoded API keys can be extracted from source code and abused.',
        remediation: 'Move API keys to environment variables, .env files (excluded from VCS), or a secrets management system.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-007'
    },
    {
        name: 'Password in Configuration',
        regex: /(?:password|passwd|pwd|secret|token|credential)\s*[=:]\s*["']([^\s"']{8,})["']/gi,
        severity: Severity.CRITICAL,
        description: 'Hardcoded password or secret detected. Credentials in source code can be easily compromised through repository access.',
        remediation: 'Use environment variables, a secrets vault (HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-008'
    },
    {
        name: 'Private Key (RSA/EC/DSA)',
        regex: /-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?(?:DSA\s+)?PRIVATE\s+KEY-----/g,
        severity: Severity.CRITICAL,
        description: 'Private cryptographic key detected. Exposed private keys compromise encryption, authentication, and data integrity.',
        remediation: 'Never store private keys in source code. Use key management services (AWS KMS, Azure Key Vault, GCP KMS) or secure file storage.',
        cweId: 'CWE-321',
        ruleId: 'SIQ-SEC-009'
    },
    {
        name: 'JWT Token',
        regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
        severity: Severity.HIGH,
        description: 'JSON Web Token (JWT) detected. Hardcoded JWTs can be stolen and used for unauthorized access.',
        remediation: 'Generate JWTs dynamically at runtime. Never hardcode tokens in source code.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-010'
    },
    {
        name: 'Bearer Token',
        regex: /(?:Authorization|Bearer)\s*[=:]\s*["']?Bearer\s+[A-Za-z0-9_\-.]{20,}["']?/gi,
        severity: Severity.HIGH,
        description: 'HTTP Bearer token detected. Hardcoded authorization tokens can be stolen from source code.',
        remediation: 'Use dynamic token generation and pass tokens via secure environment variables.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-011'
    },

    // ========== Database ==========
    {
        name: 'Database Connection String',
        regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
        severity: Severity.CRITICAL,
        description: 'Database connection string with embedded credentials detected. This exposes database access credentials.',
        remediation: 'Store database connection strings with credentials in environment variables or a secrets manager.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-012'
    },

    // ========== GitHub / SSH ==========
    {
        name: 'GitHub Personal Access Token',
        regex: /ghp_[A-Za-z0-9_]{36}/g,
        severity: Severity.CRITICAL,
        description: 'GitHub Personal Access Token detected. This token can be used to access repositories, create commits, and modify settings.',
        remediation: 'Revoke the token immediately and generate a new one. Store tokens in environment variables.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-013'
    },
    {
        name: 'Slack Webhook URL',
        regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
        severity: Severity.MEDIUM,
        description: 'Slack Webhook URL detected. Exposed webhooks can be used to send unauthorized messages to Slack channels.',
        remediation: 'Store webhook URLs in environment variables or a secrets manager.',
        cweId: 'CWE-798',
        ruleId: 'SIQ-SEC-014'
    }
];

/**
 * Scan text content for hardcoded secrets
 */
export function detectSecrets(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');
    let findingCount = 0;

    for (const pattern of SECRET_PATTERNS) {
        // Reset regex global state
        pattern.regex.lastIndex = 0;

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            // Skip comment lines
            const trimmedLine = line.trim();
            if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('*') || trimmedLine.startsWith('/*')) {
                // Allow GCP service account detection even in JSON-like files
                if (pattern.ruleId !== 'SIQ-SEC-005') {
                    continue;
                }
            }

            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(line)) !== null) {
                findingCount++;
                const snippet = match[0].length > 60
                    ? match[0].substring(0, 30) + '...' + match[0].substring(match[0].length - 10)
                    : match[0];

                findings.push({
                    id: `secret-${findingCount}`,
                    filePath,
                    line: lineIndex + 1,
                    column: match.index,
                    endColumn: match.index + match[0].length,
                    category: FindingCategory.SECRET_LEAKAGE,
                    severity: pattern.severity,
                    title: pattern.name,
                    description: pattern.description,
                    snippet: snippet,
                    remediation: pattern.remediation,
                    cweId: pattern.cweId,
                    ruleId: pattern.ruleId
                });
            }
        }
    }

    return findings;
}

