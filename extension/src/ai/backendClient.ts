import axios from 'axios';
import * as vscode from 'vscode';
import { AIClassification, SHAPExplanation, AdvancedScanResult } from '../types';

/**
 * X-CloudSentinel - Backend Client
 * Handles communication with the Flask AI backend
 */
export class BackendClient {
    private baseUrl: string;

    constructor() {
        const config = vscode.workspace.getConfiguration('X-CloudSentinel');
        this.baseUrl = config.get<string>('backendUrl', 'http://127.0.0.1:5000').replace(/\/$/, '');
    }

    /**
     * Update base URL from configuration
     */
    public updateBaseUrl(): void {
        const config = vscode.workspace.getConfiguration('X-CloudSentinel');
        this.baseUrl = config.get<string>('backendUrl', 'http://127.0.0.1:5000').replace(/\/$/, '');
    }

    /**
     * Check if backend is reachable
     */
    public async isBackendHealthy(): Promise<boolean> {
        try {
            const response = await axios.get(`${this.baseUrl}/health`, { timeout: 2000 });
            return response.status === 200;
        } catch (error) {
            return false;
        }
    }

    /**
     * Perform AI classification for a code snippet
     */
    public async classifySnippet(text: string): Promise<AIClassification | null> {
        try {
            const response = await axios.post(`${this.baseUrl}/analyze`, { text }, { timeout: 10000 });
            return {
                riskClass: response.data.prediction,
                confidence: response.data.confidence,
                probabilities: response.data.probabilities
            };
        } catch (error) {
            console.error('X-CloudSentinel: Error calling /analyze:', error);
            return null;
        }
    }

    /**
     * Get SHAP explanation for a code snippet
     */
    public async getExplanation(text: string): Promise<SHAPExplanation | null> {
        try {
            const response = await axios.post(`${this.baseUrl}/explain`, { text }, { timeout: 20000 });
            return response.data;
        } catch (error) {
            console.error('X-CloudSentinel: Error calling /explain:', error);
            return null;
        }
    }

    /**
     * Get scan history from the backend
     */
    public async getScanHistory(limit: number = 20): Promise<any[]> {
        try {
            const response = await axios.get(`${this.baseUrl}/history?limit=${limit}`);
            return response.data;
        } catch (error) {
            console.error('X-CloudSentinel: Error fetching history:', error);
            return [];
        }
    }

    /**
     * Get an AI-suggested remediation fix for a finding
     */
    public async getRemediation(text: string, title: string): Promise<any | null> {
        try {
            const response = await axios.post(`${this.baseUrl}/remediate`, { text, title }, { timeout: 30000 });
            return response.data;
        } catch (error) {
            console.error('X-CloudSentinel: Error fetching remediation:', error);
            return null;
        }
    }

    /**
     * Perform Advanced SOTA Analysis (GNN, BERT-NER, Network Security)
     */
    public async getAdvancedAnalysis(text: string, filePath: string): Promise<AdvancedScanResult | null> {
        try {
            const response = await axios.post(`${this.baseUrl}/analyze-advanced`, { text, filePath }, { timeout: 30000 });
            return response.data;
        } catch (error) {
            console.error('X-CloudSentinel: Error calling /analyze-advanced:', error);
            return null;
        }
    }
}

/** Global backend client instance */
let backendClient: BackendClient;

export function getBackendClient(): BackendClient {
    if (!backendClient) {
        backendClient = new BackendClient();
    }
    return backendClient;
}

