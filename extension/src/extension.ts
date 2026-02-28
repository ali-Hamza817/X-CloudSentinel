/**
 * X-CloudSentinel - VS Code Extension Entry Point
 * AI-powered cloud security analysis, secret leakage detection,
 * and IaC misconfiguration scanning
 */

import * as vscode from 'vscode';
import { SecurityFinding, ScanResult, SQIResult, SQIBreakdown, FindingCategory, Severity, AIClassification, SHAPExplanation } from './types';
import { detectSecrets } from './analyzer/secretDetector';
import { scanIaC } from './analyzer/iacScanner';
import { analyzeDockerfile } from './analyzer/dockerAnalyzer';
import { evaluateIAMPolicy } from './analyzer/iamEvaluator';
import { updateDiagnostics, clearDiagnostics } from './ui/diagnostics';
import { createStatusBar, updateStatusBar, showScanning, disposeStatusBar } from './ui/statusBar';
import { isSupportedFile, getFileType, registerOnSaveHandler } from './utils/fileWatcher';
import { getBackendClient } from './ai/backendClient';
import { calculateSQI } from './sqi/sqiEngine';
import { DashboardPanel } from './ui/webviewPanel';

/** Global state */
let diagnosticCollection: vscode.DiagnosticCollection;
let lastScanResults: Map<string, ScanResult> = new Map();
let outputChannel: vscode.OutputChannel;

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('X-CloudSentinel');
    outputChannel.appendLine('🛡️ X-CloudSentinel activated - Cloud Security Analysis Engine');
    outputChannel.appendLine(`   Version: 0.1.0`);
    outputChannel.appendLine(`   Timestamp: ${new Date().toISOString()}`);
    outputChannel.appendLine('');

    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('X-CloudSentinel');
    context.subscriptions.push(diagnosticCollection);

    // Create status bar
    const statusBar = createStatusBar();
    context.subscriptions.push(statusBar);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('X-CloudSentinel.scan', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanDocument(editor.document);
            } else {
                vscode.window.showWarningMessage('X-CloudSentinel: No active file to scan.');
            }
        }),
        vscode.commands.registerCommand('X-CloudSentinel.scanWorkspace', () => {
            scanWorkspace();
        }),
        vscode.commands.registerCommand('X-CloudSentinel.showDashboard', () => {
            showDashboard(context);
        }),
        vscode.commands.registerCommand('X-CloudSentinel.exportReport', () => {
            exportReport();
        }),
        vscode.commands.registerCommand('X-CloudSentinel.applyFix', async (original: string, suggested: string) => {
            // This allows applying fixes from the context menu if we add that later
            await DashboardPanel.applyFixDirectly(original, suggested);
        }),
        vscode.commands.registerCommand('X-CloudSentinel.advancedScan', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                runAdvancedResearchScan(editor.document);
            } else {
                vscode.window.showWarningMessage('X-CloudSentinel: No active file for Advanced Research Scan.');
            }
        })
    );

    // Register on-save handler
    const config = vscode.workspace.getConfiguration('X-CloudSentinel');
    if (config.get<boolean>('scanOnSave', true)) {
        const saveHandler = registerOnSaveHandler((document) => {
            scanDocument(document);
        });
        context.subscriptions.push(saveHandler);
    }

    // Scan the currently active file on activation
    if (vscode.window.activeTextEditor) {
        const doc = vscode.window.activeTextEditor.document;
        if (isSupportedFile(doc.fileName)) {
            scanDocument(doc);
        }
    }

    // Listen for active editor changes
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor((editor) => {
            if (editor && isSupportedFile(editor.document.fileName)) {
                // Show existing results if available, otherwise scan
                const existing = lastScanResults.get(editor.document.uri.toString());
                if (existing) {
                    updateStatusBar(existing.sqi || null, existing.findings.length);
                } else {
                    scanDocument(editor.document);
                }
            }
        })
    );

    outputChannel.appendLine('✅ All components initialized successfully');
    outputChannel.appendLine('   Analyzers: Secret Detector, IaC Scanner, Docker Analyzer, IAM Evaluator');
    outputChannel.appendLine('   UI: Status Bar, Inline Diagnostics, Dashboard');
    outputChannel.appendLine('');
}

/**
 * Scan a single document
 */
async function scanDocument(document: vscode.TextDocument): Promise<ScanResult> {
    const filePath = document.fileName;
    const content = document.getText();
    const fileType = getFileType(filePath);

    outputChannel.appendLine(`🔍 Scanning: ${filePath} (type: ${fileType})`);
    showScanning();

    const findings: SecurityFinding[] = [];

    try {
        // 1. Always run secret detection on all file types
        const secrets = detectSecrets(content, filePath);
        findings.push(...secrets);
        if (secrets.length > 0) {
            outputChannel.appendLine(`   🔑 Secret Detector: ${secrets.length} finding(s)`);
        }

        // 2. Run file-type-specific analyzers
        switch (fileType) {
            case 'terraform': {
                const iacFindings = scanIaC(content, filePath);
                findings.push(...iacFindings);
                if (iacFindings.length > 0) {
                    outputChannel.appendLine(`   📋 IaC Scanner (Terraform): ${iacFindings.length} finding(s)`);
                }
                break;
            }
            case 'yaml': {
                const yamlFindings = scanIaC(content, filePath);
                findings.push(...yamlFindings);
                if (yamlFindings.length > 0) {
                    outputChannel.appendLine(`   📋 IaC Scanner (K8s YAML): ${yamlFindings.length} finding(s)`);
                }
                break;
            }
            case 'dockerfile': {
                const dockerFindings = analyzeDockerfile(content, filePath);
                findings.push(...dockerFindings);
                if (dockerFindings.length > 0) {
                    outputChannel.appendLine(`   🐳 Docker Analyzer: ${dockerFindings.length} finding(s)`);
                }
                break;
            }
            case 'json': {
                const iamFindings = evaluateIAMPolicy(content, filePath);
                findings.push(...iamFindings);
                if (iamFindings.length > 0) {
                    outputChannel.appendLine(`   🔐 IAM Evaluator: ${iamFindings.length} finding(s)`);
                }
                break;
            }
        }

        // 3. AI Analysis (Optional, if backend available)
        let aiClassification: AIClassification | undefined;
        let shapExplanation: SHAPExplanation | undefined;

        const config = vscode.workspace.getConfiguration('X-CloudSentinel');
        if (config.get<boolean>('enableAI', true)) {
            const client = getBackendClient();
            if (await client.isBackendHealthy()) {
                outputChannel.appendLine(`   🤖 Running AI Analysis...`);
                aiClassification = await client.classifySnippet(content) || undefined;
                if (aiClassification) {
                    outputChannel.appendLine(`      Result: ${aiClassification.riskClass} (Conf: ${Math.round(aiClassification.confidence * 100)}%)`);
                    
                    // Only get explanation for risky findings
                    if (aiClassification.riskClass !== 'Secure') {
                        shapExplanation = await client.getExplanation(content) || undefined;
                    }
                }
            }
        }

        // 4. Calculate SQI
        const sqi = calculateSQI(findings, aiClassification?.confidence);

        // 5. Build scan result
        const scanResult: ScanResult = {
            filePath,
            timestamp: new Date().toISOString(),
            findings,
            aiClassification,
            shapExplanation,
            sqi
        };

        // 5. Store results
        lastScanResults.set(document.uri.toString(), scanResult);

        // 6. Update UI
        updateDiagnostics(diagnosticCollection, document.uri, findings);
        updateStatusBar(sqi, findings.length);

        // 7. Log summary
        const criticalCount = findings.filter(f => f.severity === Severity.CRITICAL).length;
        const highCount = findings.filter(f => f.severity === Severity.HIGH).length;
        const mediumCount = findings.filter(f => f.severity === Severity.MEDIUM).length;
        const lowCount = findings.filter(f => f.severity === Severity.LOW).length;

        outputChannel.appendLine(`   📊 SQI Score: ${Math.round(sqi.score)}/100 (Grade: ${sqi.grade})`);
        outputChannel.appendLine(`   📈 Findings: ${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium, ${lowCount} Low`);
        outputChannel.appendLine('');

        // Show notification for critical findings
        if (criticalCount > 0) {
            vscode.window.showWarningMessage(
                `X-CloudSentinel: ${criticalCount} critical security issue(s) found! SQI: ${Math.round(sqi.score)}/100`,
                'Show Dashboard'
            ).then(selection => {
                if (selection === 'Show Dashboard') {
                    vscode.commands.executeCommand('X-CloudSentinel.showDashboard');
                }
            });
        }

        return scanResult;

    } catch (error) {
        outputChannel.appendLine(`   ❌ Error scanning file: ${error}`);
        return {
            filePath,
            timestamp: new Date().toISOString(),
            findings: [],
        };
    }
}

/**
 * Scan entire workspace
 */
async function scanWorkspace(): Promise<void> {
    const files = await vscode.workspace.findFiles(
        '{**/*.tf,**/*.yaml,**/*.yml,**/Dockerfile,**/Dockerfile.*,**/*.json}',
        '{**/node_modules/**,**/.git/**,**/out/**,**/.vscode/**}',
        100
    );

    outputChannel.appendLine(`📂 Workspace scan: Found ${files.length} files to analyze`);

    let totalFindings = 0;
    for (const file of files) {
        try {
            const doc = await vscode.workspace.openTextDocument(file);
            if (isSupportedFile(doc.fileName)) {
                const result = await scanDocument(doc);
                totalFindings += result.findings.length;
            }
        } catch (error) {
            outputChannel.appendLine(`   ⚠️ Could not scan ${file.fsPath}: ${error}`);
        }
    }

    vscode.window.showInformationMessage(
        `X-CloudSentinel: Workspace scan complete. ${totalFindings} finding(s) across ${files.length} files.`
    );
}

/**
 * Show the security dashboard webview
 */
function showDashboard(context: vscode.ExtensionContext): void {
    DashboardPanel.createOrShow(context.extensionUri, Array.from(lastScanResults.values()));
}

/**
 * Export security report as JSON
 */
async function exportReport(): Promise<void> {
    const allFindings: SecurityFinding[] = [];
    const fileReports: any[] = [];

    lastScanResults.forEach((result) => {
        allFindings.push(...result.findings);
        fileReports.push({
            filePath: result.filePath,
            timestamp: result.timestamp,
            findingsCount: result.findings.length,
            sqi: result.sqi,
            findings: result.findings
        });
    });

    const aggregateSQI = calculateSQI(allFindings);

    const report = {
        tool: 'X-CloudSentinel',
        version: '0.1.0',
        timestamp: new Date().toISOString(),
        summary: {
            totalFiles: lastScanResults.size,
            totalFindings: allFindings.length,
            sqi: aggregateSQI,
            bySeverity: {
                critical: allFindings.filter(f => f.severity === Severity.CRITICAL).length,
                high: allFindings.filter(f => f.severity === Severity.HIGH).length,
                medium: allFindings.filter(f => f.severity === Severity.MEDIUM).length,
                low: allFindings.filter(f => f.severity === Severity.LOW).length
            },
            byCategory: {
                secretLeakage: allFindings.filter(f => f.category === FindingCategory.SECRET_LEAKAGE).length,
                misconfiguration: allFindings.filter(f => f.category === FindingCategory.MISCONFIGURATION).length,
                iamRisk: allFindings.filter(f => f.category === FindingCategory.IAM_RISK).length,
                dockerRisk: allFindings.filter(f => f.category === FindingCategory.DOCKER_RISK).length
            }
        },
        files: fileReports
    };

    const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('X-CloudSentinel-report.json'),
        filters: { 'JSON': ['json'] },
        title: 'Export X-CloudSentinel Security Report'
    });

    if (uri) {
        const content = JSON.stringify(report, null, 2);
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
        vscode.window.showInformationMessage(`X-CloudSentinel: Report exported to ${uri.fsPath}`);
        outputChannel.appendLine(`📄 Report exported to: ${uri.fsPath}`);
    }
}

/**
 * Perform a SOTA Advanced Research Scan (Phase 6 features)
 */
async function runAdvancedResearchScan(document: vscode.TextDocument): Promise<void> {
    const filePath = document.fileName;
    const content = document.getText();

    outputChannel.show();
    outputChannel.appendLine('🚀 [SOTA] Starting Advanced Research Scan (Phase 6)...');
    outputChannel.appendLine(`   Targets: GNN IaC Analysis, BERT-NER Secrets, Network Security Scans`);
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "X-CloudSentinel: Running Advanced SOTA Research Scan...",
        cancellable: false
    }, async (progress) => {
        try {
            const client = getBackendClient();
            const result = await client.getAdvancedAnalysis(content, filePath);

            if (!result) {
                vscode.window.showErrorMessage('X-CloudSentinel: Advanced Scan failed. Is the backend running?');
                return;
            }

            outputChannel.appendLine('\n--- 🧪 ADVANCED AGENTIC RESEARCH REPORT ---');
            outputChannel.appendLine(`[Global Risk Assessment] ${result.overall_risk}`);
            outputChannel.appendLine(`[Inference Strategy] ${result.advanced.gnn_iac.reflection.remark}`);
            
            // 1. Secrets (BERT-NER + Adversarial ARI)
            const ner = result.advanced.secrets_ner;
            outputChannel.appendLine(`\n[1] CONTEXTUAL SECRET DETECTION (BERT-NER)`);
            outputChannel.appendLine(`    Detected: ${ner.count}`);
            ner.findings.forEach(f => {
                outputChannel.appendLine(`    - Secret: ${f.secret.substring(0, 5)}*** (Conf: ${Math.round(f.confidence * 100)}%, Entropy: ${f.shannon_entropy})`);
                outputChannel.appendLine(`      ↳ [Adversarial Robustness Index]: ${f.robustness_audit.ari_score} (${f.robustness_audit.robustness})`);
            });

            // 2. GNN (IaC + Agentic Reflection)
            const gnn = result.advanced.gnn_iac;
            outputChannel.appendLine(`\n[2] RELATIONAL IaC ANALYSIS (GNN)`);
            outputChannel.appendLine(`    Prediction: ${gnn.prediction} (Conf: ${Math.round(gnn.confidence * 100)}%)`);
            outputChannel.appendLine(`    [Bayesian Uncertainty]: ${gnn.uncertainty.toFixed(4)} (Entropy-based)`);
            outputChannel.appendLine(`    [Self-Reflection]: ${gnn.reflection.trust_level} Trust - ${gnn.reflection.action}`);
            
            // 3. Attack Propagation (APS)
            const aps = gnn.aps;
            outputChannel.appendLine(`\n[3] ATTACK PROPAGATION SCORE (APS)`);
            outputChannel.appendLine(`    Exposure Distance: ${aps.exposure_distance}`);
            outputChannel.appendLine(`    Configuration Entropy: ${aps.configuration_entropy}`);
            outputChannel.appendLine(`    Critical Hubs: ${aps.critical_hubs.join(', ') || 'None'}`);
            outputChannel.appendLine(`    Privilege Escalation: ${aps.privilege_escalation_risk}`);
            
            // 4. Agentic Risk Propagation
            const prop = gnn.risk_propagation;
            const highPropNodes = Object.entries(prop).filter(([_, score]) => score > 0.6);
            if (highPropNodes.length > 0) {
                outputChannel.appendLine(`\n[4] AUTONOMOUS RISK PROPAGATION`);
                highPropNodes.forEach(([node, score]) => outputChannel.appendLine(`    - Transitive Risk at ${node}: ${score}`));
            }

            // 5. SQI Remediation Agent
            const remediation = result.advanced.agentic_remediation;
            outputChannel.appendLine(`\n[5] AGENTIC REMEDIATION PRIORITIZATION (SQI Max)`);
            remediation.forEach(r => {
                outputChannel.appendLine(`    - [${r.priority}] Fix ${r.finding_id}: +${r.delta_sqi} SQI Improvement`);
            });

            outputChannel.appendLine('\n-------------------------------------------');
            outputChannel.appendLine('🛡️ X-CloudSentinel SOTA Engine | Privacy-First Offline AI');
            outputChannel.appendLine('-------------------------------------------');
            
            vscode.window.showInformationMessage(
                `X-CloudSentinel: Advanced Agentic Scan Complete. Risk: ${result.overall_risk}.`,
                'Show Full Report'
            ).then(selection => {
                if (selection === 'Show Full Report') {
                    outputChannel.show();
                }
            });

        } catch (error) {
            outputChannel.appendLine(`   ❌ Advanced Scan Error: ${error}`);
            vscode.window.showErrorMessage('X-CloudSentinel: Error during advanced research scan.');
        }
    });
}

/**
 * Extension deactivation
 */
export function deactivate() {
    disposeStatusBar();
    lastScanResults.clear();
    outputChannel.appendLine('🛡️ X-CloudSentinel deactivated');
    outputChannel.dispose();
}

