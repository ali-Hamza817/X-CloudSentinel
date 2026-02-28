/**
 * X-CloudSentinel - Diagnostics Provider
 * Maps SecurityFindings to VS Code DiagnosticCollection (inline squiggly lines)
 */

import * as vscode from 'vscode';
import { SecurityFinding, Severity } from '../types';

/** Map X-CloudSentinel severity to VS Code DiagnosticSeverity */
function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
        case Severity.CRITICAL:
            return vscode.DiagnosticSeverity.Error;
        case Severity.HIGH:
            return vscode.DiagnosticSeverity.Error;
        case Severity.MEDIUM:
            return vscode.DiagnosticSeverity.Warning;
        case Severity.LOW:
            return vscode.DiagnosticSeverity.Information;
        case Severity.INFO:
            return vscode.DiagnosticSeverity.Hint;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

/** Severity emoji for display */
function severityIcon(severity: Severity): string {
    switch (severity) {
        case Severity.CRITICAL: return '🔴';
        case Severity.HIGH: return '🟠';
        case Severity.MEDIUM: return '🟡';
        case Severity.LOW: return '🔵';
        case Severity.INFO: return 'ℹ️';
        default: return '⚪';
    }
}

/**
 * Convert SecurityFindings to VS Code Diagnostics and update the collection
 */
export function updateDiagnostics(
    diagnosticCollection: vscode.DiagnosticCollection,
    uri: vscode.Uri,
    findings: SecurityFinding[]
): void {
    const diagnostics: vscode.Diagnostic[] = findings.map(finding => {
        const startLine = Math.max(0, finding.line - 1);
        const endLine = finding.endLine ? Math.max(0, finding.endLine - 1) : startLine;
        const startCol = finding.column ?? 0;
        const endCol = finding.endColumn ?? 1000; // extend to end of line

        const range = new vscode.Range(
            new vscode.Position(startLine, startCol),
            new vscode.Position(endLine, endCol)
        );

        const severity = mapSeverity(finding.severity);
        const icon = severityIcon(finding.severity);

        const message = [
            `${icon} [${finding.severity.toUpperCase()}] ${finding.title}`,
            '',
            finding.description,
            '',
            `💡 Remediation: ${finding.remediation}`,
            '',
            `📋 Rule: ${finding.ruleId} | CWE: ${finding.cweId || 'N/A'}`
        ].join('\n');

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = 'X-CloudSentinel';
        diagnostic.code = finding.ruleId;

        return diagnostic;
    });

    diagnosticCollection.set(uri, diagnostics);
}

/**
 * Clear diagnostics for a specific URI
 */
export function clearDiagnostics(
    diagnosticCollection: vscode.DiagnosticCollection,
    uri: vscode.Uri
): void {
    diagnosticCollection.delete(uri);
}

