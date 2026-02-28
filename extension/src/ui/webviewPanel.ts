import * as vscode from 'vscode';
import * as path from 'path';
import { ScanResult, SecurityFinding, SQIResult, Severity, FindingCategory } from '../types';
import { getBackendClient } from '../ai/backendClient';

/**
 * X-CloudSentinel - Webview Panel
 * Manages the security dashboard interface
 */
export class DashboardPanel {
    public static readonly viewType = 'X-CloudSentinelDashboard';
    public static currentPanel: DashboardPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _results: ScanResult[] = [];
    private _disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, results: ScanResult[]) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._results = results;

        // Listen for when the panel is disposed
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        // Handle messages from the webview
        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'alert':
                        vscode.window.showErrorMessage(message.text);
                        return;
                    case 'openFile':
                        this._openFile(message.filePath, message.line);
                        return;
                    case 'getRemediation':
                        this._handleRemediation(message.text, message.title);
                        return;
                    case 'applyFix':
                        this._applyFix(message.original, message.suggestedFix);
                        return;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri, results: ScanResult[]) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (DashboardPanel.currentPanel) {
            DashboardPanel.currentPanel._results = results; // Added this line
            DashboardPanel.currentPanel._update(results);
            DashboardPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            DashboardPanel.viewType, // Changed from 'X-CloudSentinelDashboard'
            '🛡️ X-CloudSentinel Security Dashboard', // Changed title slightly
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')] // Changed localResourceRoots
            }
        );

        DashboardPanel.currentPanel = new DashboardPanel(panel, extensionUri, results); // Modified constructor call
        DashboardPanel.currentPanel._update(results);
    }

    public static async applyFixDirectly(original: string, suggested: string) {
        if (DashboardPanel.currentPanel) {
            await DashboardPanel.currentPanel._applyFix(original, suggested);
        } else {
            // Fallback if panel isn't open
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const document = editor.document;
                const text = document.getText();
                const index = text.indexOf(original);
                if (index !== -1) {
                    const startPos = document.positionAt(index);
                    const endPos = document.positionAt(index + original.length);
                    await editor.edit(e => e.replace(new vscode.Range(startPos, endPos), suggested));
                    vscode.window.showInformationMessage('✅ AI Remediation applied!');
                }
            }
        }
    }

    public dispose() {
        DashboardPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private async _handleRemediation(text: string, title: string) {
        const client = getBackendClient();
        const remediation = await client.getRemediation(text, title);
        if (remediation) {
            this._panel.webview.postMessage({
                command: 'showRemediation',
                original: text,
                suggestedFix: remediation.suggestedFix,
                containerId: `fix-${title.replace(/\s+/g, '-')}` // Simplified, should match HTML
            });
        }
    }

    private async _applyFix(original: string, suggestedFix: string) {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor to apply fix.');
            return;
        }

        const document = editor.document;
        const text = document.getText();
        const index = text.indexOf(original);

        if (index === -1) {
            vscode.window.showErrorMessage('Could not find the original code snippet to replace.');
            return;
        }

        const startPos = document.positionAt(index);
        const endPos = document.positionAt(index + original.length);

        editor.edit(editBuilder => {
            editBuilder.replace(new vscode.Range(startPos, endPos), suggestedFix);
        }).then(success => {
            if (success) {
                vscode.window.showInformationMessage('✅ AI Remediation applied successfully!');
            }
        });
    }

    private async _updateHistory() {
        const client = getBackendClient();
        const history = await client.getScanHistory(10);
        this._panel.webview.postMessage({ command: 'updateHistory', history: history });
    }

    private _update(results: ScanResult[]) {
        this._panel.webview.html = this._getHtmlForWebview(results);
        this._updateHistory();
    }

    private _openFile(filePath: string, line: number) {
        const uri = vscode.Uri.file(filePath);
        vscode.workspace.openTextDocument(uri).then(doc => {
            vscode.window.showTextDocument(doc).then(editor => {
                const pos = new vscode.Position(line - 1, 0);
                editor.selection = new vscode.Selection(pos, pos);
                editor.revealRange(new vscode.Range(pos, pos));
            });
        });
    }

    private _getHtmlForWebview(results: ScanResult[]): string {
        const allFindings: SecurityFinding[] = [];
        results.forEach(r => allFindings.push(...r.findings));

        // Use the first result's SQI or calculate aggregate (simplified for aggregate)
        const primaryResult = results[0];
        const sqi = primaryResult?.sqi;

        if (!sqi) {
            return `<html><body style="background:#0a0a1a;color:#ccc;display:flex;justify-content:center;align-items:center;height:100vh">
                        <div>
                            <h1>🛡️ X-CloudSentinel</h1>
                            <p>No scan results found. Save a file to start analysis.</p>
                        </div>
                    </body></html>`;
        }

        const criticalCount = allFindings.filter(f => f.severity === Severity.CRITICAL).length;
        const highCount = allFindings.filter(f => f.severity === Severity.HIGH).length;
        const mediumCount = allFindings.filter(f => f.severity === Severity.MEDIUM).length;
        const lowCount = allFindings.filter(f => f.severity === Severity.LOW).length;

        const secretCount = allFindings.filter(f => f.category === FindingCategory.SECRET_LEAKAGE).length;
        const misconfigCount = allFindings.filter(f => f.category === FindingCategory.MISCONFIGURATION).length;
        const iamCount = allFindings.filter(f => f.category === FindingCategory.IAM_RISK).length;
        const dockerCount = allFindings.filter(f => f.category === FindingCategory.DOCKER_RISK).length;

        const sqiColor = sqi.score >= 80 ? '#00e676' : sqi.score >= 60 ? '#ffca28' : sqi.score >= 40 ? '#ff9100' : '#ff1744';

        const findingsHtml = allFindings.map(f => {
            const severityColor = f.severity === Severity.CRITICAL ? '#ff1744' :
                                  f.severity === Severity.HIGH ? '#ff9100' :
                                  f.severity === Severity.MEDIUM ? '#ffca28' : '#42a5f5';
            const severityBadge = `<span class="badge" style="background:${severityColor}22;color:${severityColor};border:1px solid ${severityColor}44">${f.severity.toUpperCase()}</span>`;
            const categoryBadge = `<span class="badge category-badge">${f.category}</span>`;

            return `
            <div class="finding-card" style="border-left:4px solid ${severityColor}">
                <div class="finding-header">
                    <div class="badges">
                        ${severityBadge} ${categoryBadge}
                    </div>
                    <span class="rule-id">${f.ruleId}</span>
                </div>
                <div class="finding-title">${this._escapeHtml(f.title)}</div>
                <div class="finding-description">${this._escapeHtml(f.description)}</div>
                ${f.snippet ? `<div class="code-snippet"><code>${this._escapeHtml(f.snippet)}</code></div>` : ''}
                <div class="remediation">💡 <span>Remediation:</span> ${this._escapeHtml(f.remediation || '')}</div>
                
                <div class="ai-fix-container">
                    <button class="fix-btn" onclick="onGetRemediation('${this._escapeHtml(f.snippet || '').replace(/'/g, "\\'")}', '${this._escapeHtml(f.title).replace(/'/g, "\\'")}', 'fix-${f.ruleId}-${f.line}')">
                        🪄 Suggest AI Fix
                    </button>
                    <div id="fix-${f.ruleId}-${f.line}" class="fix-result"></div>
                </div>

                <div class="finding-footer" onclick="onOpenFile('${f.filePath.replace(/\\/g, '\\\\')}', ${f.line})">
                    <span>📍 ${f.filePath.split(/[/\\]/).pop()} : Line ${f.line}</span>
                    <span class="link-btn">Go to Code →</span>
                </div>
            </div>`;
        }).join('');

        const fileListHtml = results.map(r => {
            const fSqi = r.sqi?.score || 100;
            const fileColor = fSqi >= 80 ? '#00e676' : fSqi >= 60 ? '#ffca28' : '#ff1744';
            return `<div class="file-item">
                <span class="file-path">${this._escapeHtml(r.filePath.split(/[/\\]/).pop() || '')}</span>
                <span class="file-stats" style="color:${fileColor}">${Math.round(fSqi)}% | ${r.findings.length} findings</span>
            </div>`;
        }).join('');

        const aiSection = primaryResult.aiClassification ? `
            <div class="ai-card">
                <div class="ai-header">
                    <span class="ai-icon">🤖</span>
                    <h3>AI Security Classification</h3>
                    <span class="ai-confidence">${Math.round(primaryResult.aiClassification.confidence * 100)}% Confidence</span>
                </div>
                <div class="ai-result">
                    <div class="ai-class ${primaryResult.aiClassification.riskClass}">${primaryResult.aiClassification.riskClass}</div>
                    <p>The AI model has categorized this code structure as <strong>${primaryResult.aiClassification.riskClass}</strong>.</p>
                </div>
                ${primaryResult.shapExplanation ? this._getShapHtml(primaryResult.shapExplanation) : ''}
            </div>
        ` : '';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --bg-dark: #0a0a1a;
            --bg-card: #14142b;
            --bg-input: #1b1b3a;
            --text-main: #e0e0e0;
            --text-dim: #999;
            --primary: #4fc3f7;
            --accent: #00e676;
            --border: #2a2a4e;
        }

        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Inter', -apple-system, system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text-main);
            padding: 32px;
            line-height: 1.6;
        }

        .container { max-width: 1000px; margin: 0 auto; }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding: 24px;
            background: linear-gradient(135deg, #1b1b3a 0%, #0a0a1a 100%);
            border-radius: 20px;
            border: 1px solid var(--border);
        }

        .title-group h1 { font-size: 24px; font-weight: 800; background: linear-gradient(90deg, #4fc3f7, #00e676); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .title-group p { font-size: 14px; color: var(--text-dim); }

        .sqi-hero {
            display: flex;
            gap: 24px;
            margin-bottom: 32px;
        }

        .sqi-card {
            flex: 1;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 32px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }

        .sqi-circle {
            width: 160px;
            height: 160px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            background: conic-gradient(${sqiColor} ${sqi.score * 3.6}deg, #1b1b3a 0deg);
        }

        .sqi-inner {
            width: 130px;
            height: 130px;
            border-radius: 50%;
            background: var(--bg-card);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .sqi-value { font-size: 48px; font-weight: 800; color: ${sqiColor}; line-height: 1; }
        .sqi-label { font-size: 12px; color: var(--text-dim); margin-top: 4px; }
        .sqi-grade { font-size: 20px; font-weight: 700; margin-top: 2px; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            flex: 1.5;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-4px); }
        .stat-val { font-size: 32px; font-weight: 800; margin-bottom: 4px; }
        .stat-label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }

        .section-header { font-size: 18px; font-weight: 700; margin: 32px 0 16px; display: flex; align-items: center; gap: 8px; color: var(--text-main); }
        .section-header::after { content:''; flex:1; height:1px; background: var(--border); }

        .breakdown-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }

        .breakdown-item {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
        }

        .breakdown-label { font-size: 13px; color: var(--text-dim); margin-bottom: 8px; display: flex; justify-content: space-between; }
        .breakdown-bar { height: 6px; background: #1b1b3a; border-radius: 3px; overflow: hidden; }
        .breakdown-fill { height: 100%; border-radius: 3px; }

        .finding-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 16px;
            transition: border-color 0.2s;
        }

        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .badges { display: flex; gap: 8px; }
        .badge { padding: 4px 12px; border-radius: 100px; font-size: 11px; font-weight: 700; }
        .category-badge { background: #1b1b3a; color: #888; border: 1px solid #2a2a4e; }
        .rule-id { font-size: 12px; color: var(--text-dim); font-family: monospace; }
        .finding-title { font-size: 17px; font-weight: 700; margin-bottom: 8px; }
        .finding-description { font-size: 14px; color: #b0b0cc; margin-bottom: 16px; }
        .code-snippet { background: #080815; padding: 12px; border-radius: 8px; margin-bottom: 16px; border: 1px solid #1a1a35; }
        .code-snippet code { font-family: 'Fira Code', monospace; font-size: 13px; color: #d1d1f0; }
        .remediation { background: #00e67611; color: #00e676; padding: 12px; border-radius: 8px; font-size: 13px; }
        .remediation span { font-weight: 700; margin-right: 4px; }
        .finding-footer { margin-top: 16px; font-size: 12px; color: var(--text-dim); display: flex; justify-content: space-between; cursor: pointer; padding-top: 12px; border-top: 1px solid #1a1a35; }
        .link-btn { color: var(--primary); font-weight: 600; }

        .ai-card {
            background: linear-gradient(135deg, #14142b 0%, #1e1e45 100%);
            border: 1px solid #4fc3f744;
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 32px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        .ai-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
        .ai-icon { font-size: 24px; }
        .ai-header h3 { font-size: 18px; color: #4fc3f7; }
        .ai-confidence { margin-left: auto; font-size: 12px; background: #4fc3f722; color: #4fc3f7; padding: 4px 12px; border-radius: 20px; }
        .ai-result { margin-bottom: 20px; }
        .ai-class { display: inline-block; font-size: 20px; font-weight: 800; margin-bottom: 8px; padding: 4px 16px; border-radius: 8px; }
        .ai-class.Secure { background: #00e67622; color: #00e676; }
        .ai-class.Misconfigured, .ai-class.SecretLeakage, .ai-class.HighRisk { background: #ff174422; color: #ff1744; }
        
        .shap-viz { display: flex; flex-wrap: wrap; gap: 4px; background: #080815; padding: 16px; border-radius: 12px; border: 1px solid #1a1a35; }
        .shap-token { padding: 2px 4px; border-radius: 3px; font-family: monospace; font-size: 13px; position: relative; }
        .shap-token .val { visibility: hidden; position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: #333; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; }
        .shap-token:hover .val { visibility: visible; }

        /* Phase 5 Styles */
        .history-list {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .history-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 20px;
            border-bottom: 1px solid #1a1a35;
            font-size: 13px;
        }
        .h-date { color: var(--text-dim); width: 140px; }
        .h-file { flex: 1; font-weight: 600; color: #ccc; }
        .h-sqi { font-weight: 800; width: 80px; text-align: right; }
        .h-class { width: 120px; text-align: right; font-weight: 700; color: var(--primary); }

        .ai-fix-container { margin-top: 16px; }
        .fix-btn {
            background: linear-gradient(90deg, #4fc3f7, #651fff);
            color: white; border: none; padding: 8px 16px; border-radius: 8px;
            font-weight: 700; cursor: pointer; transition: opacity 0.2s;
        }
        .fix-btn:hover { opacity: 0.9; }
        .ai-suggestion {
            background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
            margin-top: 12px; padding: 16px;
        }
        .ai-suggestion pre { margin: 12px 0; max-height: 200px; overflow: auto; }
        .apply-btn {
            background: #238636; color: white; border: none; padding: 8px 16px;
            border-radius: 8px; font-weight: 600; cursor: pointer;
        }
        .apply-btn:hover { background: #2ea043; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-group">
                <h1>🛡️ X-CloudSentinel Dashboard</h1>
                <p>Cloud Security Analysis & Explainable AI Reporting</p>
            </div>
            <div style="font-size: 12px; color: var(--text-dim); text-align: right;">
                V0.1.0 Prototype<br>${new Date().toLocaleDateString()}
            </div>
        </header>

        <div class="sqi-hero">
            <div class="sqi-card">
                <div class="sqi-circle">
                    <div class="sqi-inner">
                        <div class="sqi-value">${Math.round(sqi.score)}</div>
                        <div class="sqi-label">SCORE</div>
                        <div class="sqi-grade">${sqi.grade} GRADE</div>
                    </div>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-card" style="border-bottom: 4px solid #ff1744">
                    <div class="stat-val" style="color: #ff1744">${criticalCount}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card" style="border-bottom: 4px solid #ff9100">
                    <div class="stat-val" style="color: #ff9100">${highCount}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card" style="border-bottom: 4px solid #ffca28">
                    <div class="stat-val" style="color: #ffca28">${mediumCount}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card" style="border-bottom: 4px solid #42a5f5">
                    <div class="stat-val" style="color: #42a5f5">${lowCount}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>

        <div class="section-header">📈 Security Quality Index Breakdown</div>
        <div class="breakdown-grid">
            <div class="breakdown-item">
                <div class="breakdown-label"><span>Secret Leakage</span><span>${Math.round(sqi.breakdown.sl * 100)}%</span></div>
                <div class="breakdown-bar"><div class="breakdown-fill" style="width:${sqi.breakdown.sl * 100}%; background:#ff1744"></div></div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-label"><span>Misconfiguration</span><span>${Math.round(sqi.breakdown.mc * 100)}%</span></div>
                <div class="breakdown-bar"><div class="breakdown-fill" style="width:${sqi.breakdown.mc * 100}%; background:#ff9100"></div></div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-label"><span>IAM / Access Risk</span><span>${Math.round(sqi.breakdown.ar * 100)}%</span></div>
                <div class="breakdown-bar"><div class="breakdown-fill" style="width:${sqi.breakdown.ar * 100}%; background:#ff1744"></div></div>
            </div>
            <div class="breakdown-item">
                <div class="breakdown-label"><span>Docker Config</span><span>${Math.round(sqi.breakdown.ce * 100)}%</span></div>
                <div class="breakdown-bar"><div class="breakdown-fill" style="width:${sqi.breakdown.ce * 100}%; background:#42a5f5"></div></div>
            </div>
        </div>

        ${aiSection}

        <div class="section-header">📜 Activity History</div>
        <div id="history-container" class="history-list">
            <div class="loading-history">Loading history from backend...</div>
        </div>

        <div class="section-header">🔍 Current Findings (${allFindings.length})</div>
        <div class="findings-list">
            ${findingsHtml || '<p style="text-align:center; padding:40px; color:var(--text-dim)">No issues found. Great job! 🛡️</p>'}
        </div>

        <div style="text-align:center; padding:40px; color:var(--text-dim); font-size:12px;">
            X-CloudSentinel - AI-Powered DevSecOps Posture Management<br>
            Developed for Cloud Security Research 2024-2025
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function onOpenFile(path, line) {
            vscode.postMessage({ command: 'openFile', filePath: path, line: line });
        }
        function onGetRemediation(text, title, containerId) {
            const container = document.getElementById(containerId);
            container.querySelector('.fix-btn').disabled = true;
            container.querySelector('.fix-btn').innerText = '🤖 Thinking...';
            vscode.postMessage({ command: 'getRemediation', text: text, title: title, containerId: containerId });
        }
        function onApplyFix(original, suggested) {
            vscode.postMessage({ command: 'applyFix', original: original, suggestedFix: suggested });
        }

        // Listen for messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'showRemediation') {
                const container = document.getElementById(message.containerId);
                const resultDiv = container.querySelector('.fix-result');
                resultDiv.innerHTML = \`
                    <div class="ai-suggestion">
                        <h4>Suggested Code Change:</h4>
                        <pre><code>\${escape(message.suggestedFix)}</code></pre>
                        <button class="apply-btn" onclick="onApplyFix('\${escape(message.original)}', '\${escape(message.suggestedFix)}')">Apply Secure Fix</button>
                    </div>
                \`;
                container.querySelector('.fix-btn').style.display = 'none';
            }
            if (message.command === 'updateHistory') {
                const container = document.getElementById('history-container');
                if (message.history.length === 0) {
                    container.innerHTML = '<p style="color:#666; font-size:12px">No history records yet.</p>';
                    return;
                }
                container.innerHTML = message.history.map(h => \`
                    <div class="history-item">
                        <span class="h-date">\${new Date(h.timestamp).toLocaleString()}</span>
                        <span class="h-file">\${h.file_path.split(/[/\\]/).pop()}</span>
                        <span class="h-sqi" style="color:\${h.sqi_score > 80 ? '#00e676' : '#ff1744'}">SQI: \${h.sqi_score}</span>
                        <span class="h-class">\${h.ai_classification}</span>
                    </div>
                \`).join('');
            }
        });

        function escape(s) {
            return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }
    </script>
</body>
</html>`;
    }

    private _getShapHtml(shap: any): string {
        const tokens = shap.tokens;
        const values = shap.shapValues;
        
        const html = tokens.map((token: string, i: number) => {
            const val = values[i];
            const color = val > 0 ? `rgba(255, 23, 68, ${Math.min(0.8, val * 3)})` : `rgba(0, 230, 118, ${Math.min(0.8, Math.abs(val) * 3)})`;
            return `<span class="shap-token" style="background:${color}">${this._escapeHtml(token)}<span class="val">${val.toFixed(3)}</span></span>`;
        }).join('');

        return `
            <div style="margin-top:16px">
                <div style="font-size:12px; color:#4fc3f7; margin-bottom:8px; font-weight:700">SHAP EXPLAINABILITY (TOKEN CONTRIBUTIONS)</div>
                <div class="shap-viz">${html}</div>
                <div style="font-size:11px; color:var(--text-dim); margin-top:8px">
                    <span style="color:#ff1744">Red</span> indicates code that increased the risk score. 
                    <span style="color:#00e676">Green</span> indicates code that decreased it.
                </div>
            </div>
        `;
    }

    private _escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}

