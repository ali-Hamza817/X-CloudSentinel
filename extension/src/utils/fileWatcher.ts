/**
 * X-CloudSentinel - File Watcher
 * Watches for file changes in supported formats and triggers re-analysis
 */

import * as vscode from 'vscode';

/** Supported file patterns for X-CloudSentinel analysis */
const SUPPORTED_PATTERNS = [
    '**/*.tf',           // Terraform
    '**/*.yaml',         // YAML (Kubernetes, CloudFormation, etc.)
    '**/*.yml',          // YAML alternate extension
    '**/Dockerfile',     // Dockerfiles
    '**/Dockerfile.*',   // Dockerfile variants (Dockerfile.dev, etc.)
    '**/*.json',         // JSON (IAM policies, configs)
];

/** Check if a file is supported for analysis */
export function isSupportedFile(fileName: string): boolean {
    const lower = fileName.toLowerCase();
    return lower.endsWith('.tf') ||
           lower.endsWith('.yaml') ||
           lower.endsWith('.yml') ||
           lower.endsWith('.json') ||
           lower.includes('dockerfile');
}

/** Get the analysis type for a file */
export function getFileType(fileName: string): 'terraform' | 'yaml' | 'dockerfile' | 'json' | 'unknown' {
    const lower = fileName.toLowerCase();
    if (lower.endsWith('.tf')) { return 'terraform'; }
    if (lower.endsWith('.yaml') || lower.endsWith('.yml')) { return 'yaml'; }
    if (lower.includes('dockerfile')) { return 'dockerfile'; }
    if (lower.endsWith('.json')) { return 'json'; }
    return 'unknown';
}

/**
 * Create file watchers for all supported patterns
 */
export function createFileWatchers(
    onFileChange: (uri: vscode.Uri) => void
): vscode.Disposable[] {
    const disposables: vscode.Disposable[] = [];

    for (const pattern of SUPPORTED_PATTERNS) {
        const watcher = vscode.workspace.createFileSystemWatcher(pattern);

        watcher.onDidChange(uri => onFileChange(uri));
        watcher.onDidCreate(uri => onFileChange(uri));

        disposables.push(watcher);
    }

    return disposables;
}

/**
 * Register the on-save handler with debouncing
 */
export function registerOnSaveHandler(
    onSave: (document: vscode.TextDocument) => void,
    debounceMs: number = 500
): vscode.Disposable {
    let timeout: NodeJS.Timeout | undefined;

    return vscode.workspace.onDidSaveTextDocument((document) => {
        if (!isSupportedFile(document.fileName)) { return; }

        // Debounce rapid saves
        if (timeout) { clearTimeout(timeout); }
        timeout = setTimeout(() => {
            onSave(document);
        }, debounceMs);
    });
}

