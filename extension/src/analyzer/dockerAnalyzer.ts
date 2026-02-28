/**
 * X-CloudSentinel - Dockerfile Analyzer
 * Detects insecure practices in Dockerfiles
 */

import { SecurityFinding, Severity, FindingCategory } from '../types';

interface DockerRule {
    name: string;
    ruleId: string;
    severity: Severity;
    description: string;
    remediation: string;
    cweId: string;
    check: (line: string, lineIndex: number, allLines: string[]) => boolean;
}

const DOCKER_RULES: DockerRule[] = [
    {
        name: 'Running as Root User',
        ruleId: 'SIQ-DOC-001',
        severity: Severity.HIGH,
        description: 'Container is explicitly set to run as root. Running containers as root increases the impact of container escape vulnerabilities and grants unnecessary filesystem access.',
        remediation: 'Add "USER nonroot" or "USER 1000" instruction to run as a non-root user.',
        cweId: 'CWE-250',
        check: (line) => /^\s*USER\s+root\s*$/i.test(line)
    },
    {
        name: 'Using :latest Tag',
        ruleId: 'SIQ-DOC-002',
        severity: Severity.MEDIUM,
        description: 'Base image uses the ":latest" tag or no tag. This makes builds non-reproducible and may introduce unexpected vulnerabilities from newer image versions.',
        remediation: 'Pin the base image to a specific version tag or SHA256 digest (e.g., "FROM node:18.17.0-alpine").',
        cweId: 'CWE-829',
        check: (line) => {
            if (!/^\s*FROM\s+/i.test(line)) { return false; }
            const image = line.replace(/^\s*FROM\s+/i, '').trim().split(/\s+/)[0];
            // Flag if using :latest or no tag at all (and not a build stage alias)
            return image.endsWith(':latest') || (!image.includes(':') && !image.includes('@'));
        }
    },
    {
        name: 'Using ADD Instead of COPY',
        ruleId: 'SIQ-DOC-003',
        severity: Severity.LOW,
        description: 'ADD instruction used instead of COPY. ADD has extra functionality (auto-extraction, URL fetching) that can introduce unexpected behavior and security risks.',
        remediation: 'Use COPY instead of ADD for simple file copying. Only use ADD when you specifically need tar extraction or URL fetching.',
        cweId: 'CWE-829',
        check: (line) => /^\s*ADD\s+/i.test(line) && !/^\s*ADD\s+https?:\/\//i.test(line)
    },
    {
        name: 'Sensitive Information in ENV',
        ruleId: 'SIQ-DOC-004',
        severity: Severity.CRITICAL,
        description: 'Environment variable appears to contain sensitive information (password, secret, token, API key). ENV values are visible in image layers and can be extracted.',
        remediation: 'Use Docker secrets, build arguments with --secret flag, or mount secrets at runtime instead of ENV.',
        cweId: 'CWE-798',
        check: (line) => {
            if (!/^\s*ENV\s+/i.test(line)) { return false; }
            return /(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|DB_PASS)\s*[=\s]/i.test(line) &&
                   /=\s*["']?[^\s"'$]{4,}/i.test(line);
        }
    },
    {
        name: 'Sensitive Information in ARG',
        ruleId: 'SIQ-DOC-005',
        severity: Severity.HIGH,
        description: 'Build argument appears to contain sensitive default values. ARG values can be seen in image history via "docker history".',
        remediation: 'Do not set default values for sensitive ARGs. Pass them at build time with --build-arg and use multi-stage builds.',
        cweId: 'CWE-798',
        check: (line) => {
            if (!/^\s*ARG\s+/i.test(line)) { return false; }
            return /(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)\s*=/i.test(line) &&
                   /=\s*["']?[^\s"'$]{4,}/.test(line);
        }
    },
    {
        name: 'Missing HEALTHCHECK',
        ruleId: 'SIQ-DOC-006',
        severity: Severity.LOW,
        description: 'Dockerfile does not define a HEALTHCHECK instruction. Without health checks, orchestrators cannot detect unresponsive containers.',
        remediation: 'Add a HEALTHCHECK instruction (e.g., HEALTHCHECK CMD curl -f http://localhost/ || exit 1).',
        cweId: 'CWE-693',
        check: (_line, _lineIndex, allLines) => {
            // Only trigger on the last line of the Dockerfile
            if (_lineIndex !== allLines.length - 1) { return false; }
            const fullContent = allLines.join('\n');
            return !fullContent.includes('HEALTHCHECK');
        }
    },
    {
        name: 'Exposing Sensitive Port (SSH/RDP)',
        ruleId: 'SIQ-DOC-007',
        severity: Severity.MEDIUM,
        description: 'Container exposes a port commonly associated with remote access services (SSH:22, RDP:3389). These services should not typically run in containers.',
        remediation: 'Remove EXPOSE 22/3389. Use "docker exec" for debugging instead of SSH. Use kubectl exec for Kubernetes.',
        cweId: 'CWE-284',
        check: (line) => /^\s*EXPOSE\s+.*(22|3389)(\s|\/|$)/i.test(line)
    },
    {
        name: 'No USER Instruction (Running as Root by Default)',
        ruleId: 'SIQ-DOC-008',
        severity: Severity.MEDIUM,
        description: 'Dockerfile does not contain a USER instruction. By default, containers run as root, which is a security risk.',
        remediation: 'Add a USER instruction to set a non-root user (e.g., "RUN adduser --disabled-password appuser && USER appuser").',
        cweId: 'CWE-250',
        check: (_line, _lineIndex, allLines) => {
            if (_lineIndex !== allLines.length - 1) { return false; }
            const fullContent = allLines.join('\n');
            return !fullContent.match(/^\s*USER\s+/mi);
        }
    },
    {
        name: 'Using sudo in RUN Instruction',
        ruleId: 'SIQ-DOC-009',
        severity: Severity.MEDIUM,
        description: 'Using sudo inside a Dockerfile RUN instruction. If the container needs root access, it should be explicitly declared. sudo can mask privilege escalation.',
        remediation: 'Perform privileged operations before the USER instruction, then switch to a non-root user.',
        cweId: 'CWE-250',
        check: (line) => /^\s*RUN\s+.*sudo\s+/i.test(line)
    },
    {
        name: 'Curl Piping to Shell',
        ruleId: 'SIQ-DOC-010',
        severity: Severity.HIGH,
        description: 'Script is downloaded and piped directly to a shell (curl | sh). This executes unverified remote code and is a significant supply chain risk.',
        remediation: 'Download the script first, verify its checksum/signature, then execute it as a separate step.',
        cweId: 'CWE-829',
        check: (line) => /curl\s+.*\|\s*(sh|bash|zsh)/i.test(line) || /wget\s+.*\|\s*(sh|bash|zsh)/i.test(line)
    }
];

/**
 * Scan Dockerfile content for security issues
 */
export function analyzeDockerfile(content: string, filePath: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const lines = content.split('\n');
    let findingCount = 0;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        const trimmedLine = line.trim();

        // Skip empty lines and comments
        if (!trimmedLine || trimmedLine.startsWith('#')) { continue; }

        for (const rule of DOCKER_RULES) {
            if (rule.check(line, lineIndex, lines)) {
                findingCount++;
                findings.push({
                    id: `docker-${findingCount}`,
                    filePath,
                    line: lineIndex + 1,
                    category: FindingCategory.DOCKER_RISK,
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

