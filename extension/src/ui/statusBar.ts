/**
 * X-CloudSentinel - Status Bar
 * Displays the SQI score in the VS Code status bar with color coding
 */

import * as vscode from 'vscode';
import { SQIResult } from '../types';

let statusBarItem: vscode.StatusBarItem;

/**
 * Initialize the status bar item
 */
export function createStatusBar(): vscode.StatusBarItem {
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left,
        100
    );
    statusBarItem.command = 'X-CloudSentinel.showDashboard';
    statusBarItem.tooltip = 'Click to open X-CloudSentinel Security Dashboard';
    statusBarItem.text = '$(shield) SQI: --';
    statusBarItem.show();
    return statusBarItem;
}

/**
 * Update the status bar with current SQI score
 */
export function updateStatusBar(sqi: SQIResult | null, findingsCount?: number): void {
    if (!statusBarItem) { return; }

    if (!sqi) {
        statusBarItem.text = '$(shield) SQI: --';
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = 'X-CloudSentinel: No scan results available. Save a file to trigger analysis.';
        return;
    }

    const score = Math.round(sqi.score);
    const grade = sqi.grade;
    const count = findingsCount ?? sqi.totalFindings;

    // Color coding based on score
    let icon: string;
    let bgColor: vscode.ThemeColor | undefined;

    if (score >= 80) {
        icon = '$(pass-filled)';
        bgColor = undefined; // default (good)
    } else if (score >= 60) {
        icon = '$(warning)';
        bgColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
        icon = '$(error)';
        bgColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    }

    statusBarItem.text = `${icon} SQI: ${score}/100 (${grade})`;
    statusBarItem.backgroundColor = bgColor;
    statusBarItem.tooltip = [
        `X-CloudSentinel Security Quality Index: ${score}/100`,
        `Grade: ${grade}`,
        `Total Findings: ${count}`,
        '',
        'Click to open the Security Dashboard'
    ].join('\n');
}

/**
 * Update status bar to show scanning state
 */
export function showScanning(): void {
    if (!statusBarItem) { return; }
    statusBarItem.text = '$(sync~spin) X-CloudSentinel: Scanning...';
    statusBarItem.backgroundColor = undefined;
}

/**
 * Dispose the status bar
 */
export function disposeStatusBar(): void {
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

