/**
 * X-CloudSentinel - IaC Scanner
 * Detects misconfigurations in Terraform (.tf) and Kubernetes YAML files
 */

import { SecurityFinding, Severity, FindingCategory } from '../types';

// ============================
// Terraform Misconfiguration Rules
// ============================

interface IaCRule {
    name: string;
    ruleId: string;
    severity: Severity;
    description: string;
    remediation: string;
    cweId: string;
    /** Function that checks a line and its context */
    check: (line: string, lineIndex: number, allLines: string[], context: BlockContext) => boolean;
}

interface BlockContext {
    currentBlock: string;      // e.g., "resource \"aws_s3_bucket\""
    currentBlockType: string;  // e.g., "resource"
    currentResourceType: string; // e.g., "aws_s3_bucket"
    blockStartLine: number;
    braceDepth: number;
}

/** Parse Terraform block context from lines */
function parseTerraformContext(lines: string[], currentLine: number): BlockContext {
    let braceDepth = 0;
    let currentBlock = '';
    let currentBlockType = '';
    let currentResourceType = '';
    let blockStartLine = 0;

    for (let i = 0; i <= currentLine; i++) {
        const line = lines[i].trim();

        // Detect block start
        const blockMatch = line.match(/^(resource|data|module|provider|variable|output|locals)\s+"([^"]+)"/);
        if (blockMatch && braceDepth === 0) {
            currentBlockType = blockMatch[1];
            currentResourceType = blockMatch[2];
            currentBlock = line;
            blockStartLine = i;
        }

        // Count braces
        for (const char of line) {
            if (char === '{') { braceDepth++; }
            if (char === '}') {
                braceDepth--;
                if (braceDepth <= 0) {
                    braceDepth = 0;
                    if (i < currentLine) {
                        currentBlock = '';
                        currentBlockType = '';
                        currentResourceType = '';
                    }
                }
            }
        }
    }

    return { currentBlock, currentBlockType, currentResourceType, blockStartLine, braceDepth };
}

const TERRAFORM_RULES: IaCRule[] = [
    // S3 Bucket Rules
    {
        name: 'S3 Bucket Without Encryption',
        ruleId: 'SIQ-IAC-001',
        severity: Severity.HIGH,
        description: 'S3 bucket resource found without server-side encryption configuration. Unencrypted storage can expose sensitive data at rest.',
        remediation: 'Add a "server_side_encryption_configuration" block with AES256 or aws:kms algorithm.',
        cweId: 'CWE-311',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_s3_bucket') { return false; }
            // Check if the line is the closing brace of the bucket block
            if (line.trim() === '}' && ctx.braceDepth === 0) {
                // Look back through the block for encryption config
                const blockContent = allLines.slice(ctx.blockStartLine, lineIndex + 1).join('\n');
                return !blockContent.includes('server_side_encryption_configuration') &&
                       !blockContent.includes('aws_s3_bucket_server_side_encryption');
            }
            return false;
        }
    },
    {
        name: 'S3 Bucket Public Access Not Blocked',
        ruleId: 'SIQ-IAC-002',
        severity: Severity.CRITICAL,
        description: 'S3 bucket has public access enabled or public access block is not configured. This can lead to unauthorized data exposure.',
        remediation: 'Add an "aws_s3_bucket_public_access_block" resource with all four settings set to true.',
        cweId: 'CWE-284',
        check: (line) => {
            return /block_public_acls\s*=\s*false/i.test(line) ||
                   /block_public_policy\s*=\s*false/i.test(line) ||
                   /restrict_public_buckets\s*=\s*false/i.test(line) ||
                   /ignore_public_acls\s*=\s*false/i.test(line);
        }
    },
    {
        name: 'S3 Bucket ACL Set to Public',
        ruleId: 'SIQ-IAC-003',
        severity: Severity.CRITICAL,
        description: 'S3 bucket ACL is set to a public access level. This makes the bucket contents accessible to anyone on the internet.',
        remediation: 'Set the ACL to "private" or use bucket policies with specific principals.',
        cweId: 'CWE-284',
        check: (line) => {
            return /acl\s*=\s*"(public-read|public-read-write|authenticated-read)"/.test(line);
        }
    },

    // Security Group Rules
    {
        name: 'Security Group Open to All Traffic (0.0.0.0/0)',
        ruleId: 'SIQ-IAC-004',
        severity: Severity.CRITICAL,
        description: 'Security group ingress rule allows traffic from all IP addresses (0.0.0.0/0). This exposes services to the entire internet.',
        remediation: 'Restrict CIDR blocks to specific IP ranges. Avoid 0.0.0.0/0 for ingress rules.',
        cweId: 'CWE-284',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_security_group' &&
                ctx.currentResourceType !== 'aws_security_group_rule') { return false; }
            return /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/.test(line);
        }
    },
    {
        name: 'Security Group Allows All Ports',
        ruleId: 'SIQ-IAC-005',
        severity: Severity.HIGH,
        description: 'Security group rule allows traffic on all ports (from_port=0, to_port=65535 or to_port=0). This vastly increases the attack surface.',
        remediation: 'Restrict port ranges to only the required ports for your application.',
        cweId: 'CWE-284',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_security_group' &&
                ctx.currentResourceType !== 'aws_security_group_rule') { return false; }
            return /to_port\s*=\s*(65535|0)/.test(line) && /from_port\s*=\s*0/.test(allLines.slice(Math.max(0, lineIndex - 5), lineIndex + 5).join('\n'));
        }
    },

    // RDS Rules
    {
        name: 'RDS Instance Without Encryption',
        ruleId: 'SIQ-IAC-006',
        severity: Severity.HIGH,
        description: 'RDS database instance does not have storage encryption enabled. Unencrypted databases expose sensitive data at rest.',
        remediation: 'Set "storage_encrypted = true" in the aws_db_instance resource.',
        cweId: 'CWE-311',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_db_instance') { return false; }
            return /storage_encrypted\s*=\s*false/.test(line);
        }
    },
    {
        name: 'RDS Instance Publicly Accessible',
        ruleId: 'SIQ-IAC-007',
        severity: Severity.CRITICAL,
        description: 'RDS database instance is set to be publicly accessible. This exposes the database directly to the internet.',
        remediation: 'Set "publicly_accessible = false" and access the database through a VPC.',
        cweId: 'CWE-284',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_db_instance') { return false; }
            return /publicly_accessible\s*=\s*true/.test(line);
        }
    },

    // EBS Rules
    {
        name: 'EBS Volume Without Encryption',
        ruleId: 'SIQ-IAC-008',
        severity: Severity.MEDIUM,
        description: 'EBS volume does not have encryption enabled. Unencrypted EBS volumes expose data at rest.',
        remediation: 'Set "encrypted = true" in the aws_ebs_volume resource.',
        cweId: 'CWE-311',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_ebs_volume') { return false; }
            return /encrypted\s*=\s*false/.test(line);
        }
    },

    // Logging Rules
    {
        name: 'CloudTrail Logging Disabled',
        ruleId: 'SIQ-IAC-009',
        severity: Severity.HIGH,
        description: 'CloudTrail logging is disabled or multi-region trail is not enabled. Without logging, security incidents cannot be audited.',
        remediation: 'Set "enable_logging = true" and "is_multi_region_trail = true".',
        cweId: 'CWE-778',
        check: (line, lineIndex, allLines, ctx) => {
            if (ctx.currentResourceType !== 'aws_cloudtrail') { return false; }
            return /enable_logging\s*=\s*false/.test(line);
        }
    },

    // General Terraform
    {
        name: 'Hardcoded Credentials in Terraform',
        ruleId: 'SIQ-IAC-010',
        severity: Severity.CRITICAL,
        description: 'Credentials appear to be hardcoded in Terraform configuration. This is a critical security risk.',
        remediation: 'Use Terraform variables, environment variables (TF_VAR_*), or a secrets manager for credentials.',
        cweId: 'CWE-798',
        check: (line) => {
            return /(?:access_key|secret_key)\s*=\s*"[^"]{10,}"/.test(line);
        }
    }
];

// ============================
// Kubernetes YAML Rules
// ============================

interface K8sRule {
    name: string;
    ruleId: string;
    severity: Severity;
    description: string;
    remediation: string;
    cweId: string;
    check: (line: string, lineIndex: number, allLines: string[]) => boolean;
}

const K8S_RULES: K8sRule[] = [
    {
        name: 'Container Running as Privileged',
        ruleId: 'SIQ-K8S-001',
        severity: Severity.CRITICAL,
        description: 'Container is running in privileged mode. This grants the container full access to the host system, effectively bypassing all security isolation.',
        remediation: 'Set "privileged: false" in the container security context. Only use privileged mode when absolutely necessary.',
        cweId: 'CWE-250',
        check: (line) => /privileged\s*:\s*true/i.test(line)
    },
    {
        name: 'Container Running as Root (UID 0)',
        ruleId: 'SIQ-K8S-002',
        severity: Severity.HIGH,
        description: 'Container is configured to run as root user (UID 0). Running as root inside containers increases the impact of container escape vulnerabilities.',
        remediation: 'Set "runAsUser" to a non-zero UID and "runAsNonRoot: true" in the security context.',
        cweId: 'CWE-250',
        check: (line) => /runAsUser\s*:\s*0/i.test(line)
    },
    {
        name: 'Host Network Enabled',
        ruleId: 'SIQ-K8S-003',
        severity: Severity.HIGH,
        description: 'Pod is using the host network namespace. This bypasses Kubernetes network policies and can expose sensitive host network interfaces.',
        remediation: 'Set "hostNetwork: false" or remove the setting. Use Kubernetes Services and Ingress for network access.',
        cweId: 'CWE-284',
        check: (line) => /hostNetwork\s*:\s*true/i.test(line)
    },
    {
        name: 'Host PID Namespace Enabled',
        ruleId: 'SIQ-K8S-004',
        severity: Severity.HIGH,
        description: 'Pod is sharing the host PID namespace. This allows the container to see and interact with all host processes.',
        remediation: 'Set "hostPID: false" or remove the setting.',
        cweId: 'CWE-284',
        check: (line) => /hostPID\s*:\s*true/i.test(line)
    },
    {
        name: 'Allow Privilege Escalation Enabled',
        ruleId: 'SIQ-K8S-005',
        severity: Severity.HIGH,
        description: 'Container allows privilege escalation. A process inside the container could gain more privileges than its parent process.',
        remediation: 'Set "allowPrivilegeEscalation: false" in the container security context.',
        cweId: 'CWE-250',
        check: (line) => /allowPrivilegeEscalation\s*:\s*true/i.test(line)
    },
    {
        name: 'Secrets Exposed in Environment Variables',
        ruleId: 'SIQ-K8S-006',
        severity: Severity.HIGH,
        description: 'Sensitive values appear to be hardcoded in environment variable definitions. Environment variables can be exposed through process listing and logs.',
        remediation: 'Use Kubernetes Secrets with secretKeyRef or mount secrets as volumes instead of hardcoding values.',
        cweId: 'CWE-798',
        check: (line, lineIndex, allLines) => {
            if (!/value\s*:/i.test(line)) { return false; }
            // Check if the name in a nearby line contains sensitive keywords
            const context = allLines.slice(Math.max(0, lineIndex - 3), lineIndex + 1).join('\n').toLowerCase();
            return /(password|secret|token|api[_-]?key|credential|database_url)/i.test(context) &&
                   /value\s*:\s*["']?[^\s"']{5,}/i.test(line);
        }
    },
    {
        name: 'Writable Root Filesystem',
        ruleId: 'SIQ-K8S-007',
        severity: Severity.MEDIUM,
        description: 'Container root filesystem is writable. This allows attackers to modify the container filesystem if compromised.',
        remediation: 'Set "readOnlyRootFilesystem: true" in the security context and use emptyDir volumes for writable directories.',
        cweId: 'CWE-732',
        check: (line) => /readOnlyRootFilesystem\s*:\s*false/i.test(line)
    },
    {
        name: 'Missing Resource Limits',
        ruleId: 'SIQ-K8S-008',
        severity: Severity.MEDIUM,
        description: 'Container does not define CPU/memory resource limits. Without limits, a compromised container could consume all node resources (DoS).',
        remediation: 'Add "resources.limits" for CPU and memory to the container spec.',
        cweId: 'CWE-770',
        check: (line, lineIndex, allLines) => {
            // Simple heuristic: if we see "image:" without nearby "limits:" in the container spec
            if (!/^\s*image\s*:/i.test(line)) { return false; }
            const contextRange = allLines.slice(lineIndex, Math.min(allLines.length, lineIndex + 20)).join('\n');
            return !contextRange.includes('limits:');
        }
    }
];

/**
 * Scan Terraform file for misconfigurations
 */
export function scanTerraform(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');
    let findingCount = 0;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        const trimmedLine = line.trim();

        // Skip comments
        if (trimmedLine.startsWith('#') || trimmedLine.startsWith('//')) { continue; }

        const ctx = parseTerraformContext(lines, lineIndex);

        for (const rule of TERRAFORM_RULES) {
            if (rule.check(line, lineIndex, lines, ctx)) {
                findingCount++;
                findings.push({
                    id: `iac-tf-${findingCount}`,
                    filePath,
                    line: lineIndex + 1,
                    category: FindingCategory.MISCONFIGURATION,
                    severity: rule.severity,
                    title: rule.name,
                    description: rule.description,
                    snippet: trimmedLine,
                    remediation: rule.remediation,
                    cweId: rule.cweId,
                    ruleId: rule.ruleId
                });
            }
        }
    }

    return findings;
}

/**
 * Scan Kubernetes YAML file for security issues
 */
export function scanKubernetesYaml(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');
    let findingCount = 0;

    // Quick check if this looks like a K8s manifest
    const isK8sManifest = content.includes('apiVersion:') || content.includes('kind:');
    if (!isK8sManifest) { return findings; }

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        const trimmedLine = line.trim();

        // Skip comments
        if (trimmedLine.startsWith('#')) { continue; }

        for (const rule of K8S_RULES) {
            if (rule.check(line, lineIndex, lines)) {
                findingCount++;
                findings.push({
                    id: `iac-k8s-${findingCount}`,
                    filePath,
                    line: lineIndex + 1,
                    category: FindingCategory.MISCONFIGURATION,
                    severity: rule.severity,
                    title: rule.name,
                    description: rule.description,
                    snippet: trimmedLine,
                    remediation: rule.remediation,
                    cweId: rule.cweId,
                    ruleId: rule.ruleId
                });
            }
        }
    }

    return findings;
}

/**
 * Scan IaC content - auto-detects file type
 */
export function scanIaC(content: string, filePath: string): SecurityFinding[] {
    const lowerPath = filePath.toLowerCase();

    if (lowerPath.endsWith('.tf')) {
        return scanTerraform(content, filePath);
    }

    if (lowerPath.endsWith('.yaml') || lowerPath.endsWith('.yml')) {
        return scanKubernetesYaml(content, filePath);
    }

    return [];
}

