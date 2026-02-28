/**
 * X-CloudSentinel - IAM Policy Evaluator
 * Analyzes AWS IAM policies (JSON) for overly permissive rules
 * Enforces the Principle of Least Privilege
 */

import { SecurityFinding, Severity, FindingCategory } from '../types';

interface IAMStatement {
    Sid?: string;
    Effect: string;
    Principal?: any;
    Action?: string | string[];
    NotAction?: string | string[];
    Resource?: string | string[];
    Condition?: any;
}

interface IAMPolicy {
    Version?: string;
    Statement?: IAMStatement[];
}

interface IAMRule {
    name: string;
    ruleId: string;
    severity: Severity;
    description: string;
    remediation: string;
    cweId: string;
    check: (statement: IAMStatement, statementIndex: number) => string | null;
}

const IAM_RULES: IAMRule[] = [
    {
        name: 'Wildcard Action (*)',
        ruleId: 'SIQ-IAM-001',
        severity: Severity.CRITICAL,
        description: 'IAM policy grants all actions ("Action": "*"). This violates the principle of least privilege and provides unrestricted access to all AWS services and operations.',
        remediation: 'Replace wildcard actions with specific actions required (e.g., "s3:GetObject", "ec2:DescribeInstances").',
        cweId: 'CWE-250',
        check: (stmt) => {
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            if (stmt.Effect === 'Allow' && actions.some(a => a === '*')) {
                return `Statement "${stmt.Sid || 'unnamed'}" grants Action: "*"`;
            }
            return null;
        }
    },
    {
        name: 'Wildcard Resource (*)',
        ruleId: 'SIQ-IAM-002',
        severity: Severity.HIGH,
        description: 'IAM policy applies to all resources ("Resource": "*"). This grants access to every resource in the AWS account rather than specific ARNs.',
        remediation: 'Replace wildcard resources with specific ARNs (e.g., "arn:aws:s3:::my-bucket/*").',
        cweId: 'CWE-250',
        check: (stmt) => {
            const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
            if (stmt.Effect === 'Allow' && resources.some(r => r === '*')) {
                return `Statement "${stmt.Sid || 'unnamed'}" grants Resource: "*"`;
            }
            return null;
        }
    },
    {
        name: 'Full Admin Access (Action:* + Resource:*)',
        ruleId: 'SIQ-IAM-003',
        severity: Severity.CRITICAL,
        description: 'IAM policy grants full administrator access with both Action:"*" and Resource:"*". This is equivalent to root access on the entire AWS account.',
        remediation: 'Never use full admin policies. Create role-specific policies with only the required permissions.',
        cweId: 'CWE-250',
        check: (stmt) => {
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
            if (stmt.Effect === 'Allow' &&
                actions.some(a => a === '*') &&
                resources.some(r => r === '*')) {
                return `Statement "${stmt.Sid || 'unnamed'}" grants full admin access (Action:* + Resource:*)`;
            }
            return null;
        }
    },
    {
        name: 'Missing Condition Block',
        ruleId: 'SIQ-IAM-004',
        severity: Severity.MEDIUM,
        description: 'IAM Allow statement has no Condition block. Conditions can restrict when a policy applies (e.g., MFA required, source IP, time-based).',
        remediation: 'Add appropriate conditions such as "aws:MultiFactorAuthPresent", "aws:SourceIp", or "aws:RequestedRegion".',
        cweId: 'CWE-862',
        check: (stmt) => {
            if (stmt.Effect === 'Allow' && !stmt.Condition) {
                // Only flag if the policy is broad (not single-action, single-resource)
                const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
                const hasBroadAction = actions.some(a => a?.includes('*'));
                const hasBroadResource = resources.some(r => r?.includes('*'));
                if (hasBroadAction || hasBroadResource) {
                    return `Allow statement "${stmt.Sid || 'unnamed'}" has broad permissions but no Condition`;
                }
            }
            return null;
        }
    },
    {
        name: 'Allow with NotAction (Inverse Allow)',
        ruleId: 'SIQ-IAM-005',
        severity: Severity.HIGH,
        description: 'Using "NotAction" with "Allow" creates an inverse permission — it allows ALL actions EXCEPT the listed ones. This is almost always overly permissive.',
        remediation: 'Replace NotAction with an explicit Action list. Only use NotAction with Deny statements.',
        cweId: 'CWE-250',
        check: (stmt) => {
            if (stmt.Effect === 'Allow' && stmt.NotAction) {
                return `Statement "${stmt.Sid || 'unnamed'}" uses Allow + NotAction (grants all except listed actions)`;
            }
            return null;
        }
    },
    {
        name: 'Open Principal (Public Access)',
        ruleId: 'SIQ-IAM-006',
        severity: Severity.CRITICAL,
        description: 'IAM policy grants access to everyone ("Principal": "*" or "Principal": {"AWS": "*"}). This makes the resource publicly accessible.',
        remediation: 'Restrict the Principal to specific AWS accounts, roles, or users. Never use "*" as Principal.',
        cweId: 'CWE-284',
        check: (stmt) => {
            if (stmt.Effect === 'Allow') {
                const principal = stmt.Principal;
                if (principal === '*') {
                    return `Statement "${stmt.Sid || 'unnamed'}" grants access to Principal: "*" (everyone)`;
                }
                if (typeof principal === 'object' && principal !== null) {
                    const awsPrincipal = principal.AWS;
                    if (awsPrincipal === '*' || (Array.isArray(awsPrincipal) && awsPrincipal.includes('*'))) {
                        return `Statement "${stmt.Sid || 'unnamed'}" grants access to AWS Principal: "*"`;
                    }
                }
            }
            return null;
        }
    },
    {
        name: 'Overly Broad Service Wildcards',
        ruleId: 'SIQ-IAM-007',
        severity: Severity.HIGH,
        description: 'IAM action uses a service-level wildcard (e.g., "s3:*", "ec2:*"). This grants all operations on the service rather than only required ones.',
        remediation: 'Replace service wildcards with specific actions (e.g., "s3:GetObject" instead of "s3:*").',
        cweId: 'CWE-250',
        check: (stmt) => {
            if (stmt.Effect !== 'Allow') { return null; }
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            const broadActions = actions.filter(a => a && a !== '*' && a.endsWith(':*'));
            if (broadActions.length > 0) {
                return `Statement "${stmt.Sid || 'unnamed'}" uses broad service wildcards: ${broadActions.join(', ')}`;
            }
            return null;
        }
    },
    {
        name: 'PassRole Without Restriction',
        ruleId: 'SIQ-IAM-008',
        severity: Severity.HIGH,
        description: 'iam:PassRole permission granted on all resources. PassRole allows an entity to assign IAM roles to other services, enabling potential privilege escalation.',
        remediation: 'Restrict iam:PassRole to specific role ARNs using the Resource field. Add iam:PassedToService condition.',
        cweId: 'CWE-269',
        check: (stmt) => {
            if (stmt.Effect !== 'Allow') { return null; }
            const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
            const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
            if (actions.some(a => a?.toLowerCase() === 'iam:passrole') &&
                resources.some(r => r === '*')) {
                return `Statement "${stmt.Sid || 'unnamed'}" grants iam:PassRole on all resources`;
            }
            return null;
        }
    }
];

/**
 * Evaluate an IAM policy JSON for security issues
 */
export function evaluateIAMPolicy(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    let findingCount = 0;

    // Try to parse as JSON
    let policy: IAMPolicy;
    try {
        policy = JSON.parse(content);
    } catch {
        // Not valid JSON, skip
        return findings;
    }

    // Check if this looks like an IAM policy
    if (!policy.Statement || !Array.isArray(policy.Statement)) {
        return findings;
    }

    // Find line numbers for each statement
    const lines = content.split('\n');

    for (let stmtIndex = 0; stmtIndex < policy.Statement.length; stmtIndex++) {
        const stmt = policy.Statement[stmtIndex];

        // Try to find the line where this statement starts
        let stmtLine = 1;
        const stmtSid = stmt.Sid;
        if (stmtSid) {
            const lineIdx = lines.findIndex(l => l.includes(`"${stmtSid}"`));
            if (lineIdx >= 0) { stmtLine = lineIdx + 1; }
        } else {
            // Try to find the Effect line for this statement
            let effectCount = 0;
            for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes('"Effect"')) {
                    effectCount++;
                    if (effectCount === stmtIndex + 1) {
                        stmtLine = i + 1;
                        break;
                    }
                }
            }
        }

        for (const rule of IAM_RULES) {
            const result = rule.check(stmt, stmtIndex);
            if (result) {
                findingCount++;
                findings.push({
                    id: `iam-${findingCount}`,
                    filePath,
                    line: stmtLine,
                    category: FindingCategory.IAM_RISK,
                    severity: rule.severity,
                    title: rule.name,
                    description: rule.description + '\n\nDetail: ' + result,
                    snippet: result,
                    remediation: rule.remediation,
                    cweId: rule.cweId,
                    ruleId: rule.ruleId
                });
            }
        }
    }

    return findings;
}

