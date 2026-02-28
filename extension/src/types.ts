/**
 * X-CloudSentinel - Shared Types
 * Core type definitions for all analysis engines
 */

/** Severity levels for findings */
export enum Severity {
    CRITICAL = 'critical',
    HIGH = 'high',
    MEDIUM = 'medium',
    LOW = 'low',
    INFO = 'info'
}

/** Categories of security findings */
export enum FindingCategory {
    SECRET_LEAKAGE = 'Secret Leakage',
    MISCONFIGURATION = 'Misconfiguration',
    IAM_RISK = 'IAM / Access Risk',
    DOCKER_RISK = 'Docker Risk',
    GENERAL = 'General'
}

/** A single security finding from any analyzer */
export interface SecurityFinding {
    /** Unique identifier */
    id: string;
    /** File path where the finding was detected */
    filePath: string;
    /** Line number (1-indexed) */
    line: number;
    /** End line (inclusive), defaults to same as line */
    endLine?: number;
    /** Column start (0-indexed) */
    column?: number;
    /** Column end (0-indexed) */
    endColumn?: number;
    /** Category of the finding */
    category: FindingCategory;
    /** Severity level */
    severity: Severity;
    /** Short title of the finding */
    title: string;
    /** Detailed description / explanation */
    description: string;
    /** The matched/flagged code snippet */
    snippet?: string;
    /** Suggested remediation */
    remediation?: string;
    /** CWE ID if applicable */
    cweId?: string;
    /** Rule ID for reference */
    ruleId: string;
}

/** AI Classification result from the backend */
export interface AIClassification {
    /** Predicted risk class */
    riskClass: 'Secure' | 'Misconfigured' | 'SecretLeakage' | 'HighRisk';
    /** Confidence score (0-1) */
    confidence: number;
    /** Per-class probabilities */
    probabilities: {
        secure: number;
        misconfigured: number;
        secretLeakage: number;
        highRisk: number;
    };
}

/** SHAP explanation for a prediction */
export interface SHAPExplanation {
    /** Code tokens */
    tokens: string[];
    /** SHAP values per token for the predicted class */
    shapValues: number[];
    /** Base value */
    baseValue: number;
    /** Predicted class */
    predictedClass: string;
}

/** SQI sub-scores */
export interface SQIBreakdown {
    /** Secret Leakage risk (0-1) */
    sl: number;
    /** Misconfiguration risk (0-1) */
    mc: number;
    /** Access Risk (0-1) */
    ar: number;
    /** Configuration Entropy (0-1) */
    ce: number;
    /** AI-calibrated weights */
    weights: {
        w1: number;
        w2: number;
        w3: number;
        w4: number;
    };
}

/** Complete SQI result */
export interface SQIResult {
    /** Overall SQI score (0-100, higher = more secure) */
    score: number;
    /** Score breakdown */
    breakdown: SQIBreakdown;
    /** Grade label */
    grade: 'A' | 'B' | 'C' | 'D' | 'F';
    /** Color for UI */
    color: 'green' | 'yellow' | 'orange' | 'red';
    /** Total findings count */
    totalFindings: number;
}

/** Complete scan result for a file */
export interface ScanResult {
    /** File path */
    filePath: string;
    /** Timestamp of scan */
    timestamp: string;
    /** All findings */
    findings: SecurityFinding[];
    /** AI classification (if backend available) */
    aiClassification?: AIClassification;
    /** SHAP explanation (if backend available) */
    shapExplanation?: SHAPExplanation;
    /** SQI result */
    sqi?: SQIResult;
}

/** [SOTA] Advanced Agentic Scan Results */
export interface AdvancedScanResult {
    baseline: {
        prediction: string;
        confidence: number;
    };
    advanced: {
        secrets_ner: {
            count: number;
            findings: Array<{
                secret: string;
                type: string;
                confidence: number;
                shannon_entropy: number;
                robustness_audit: {
                    ari_score: number;
                    robustness: string;
                };
            }>;
        };
        gnn_iac: {
            prediction: string;
            confidence: number;
            uncertainty: number;
            node_count: number;
            edge_count: number;
            risk_heatmap: Record<string, number>;
            risk_propagation: Record<string, number>;
            reflection: {
                trust_level: string;
                action: string;
                remark: string;
            };
            aps: {
                exposure_distance: number | string;
                critical_hubs: string[];
                privilege_escalation_risk: string;
                configuration_entropy: number;
                wildcard_findings: string[];
            };
        };
        network_security: {
            vulnerable_ports: Array<{ port: number, service: string, risk: string }>;
            suspicious_urls: Array<{ url: string, risk: string }>;
            exposure_risks: Array<{ type: string, description: string }>;
        };
        sqi_weights: Record<string, number>;
        agentic_remediation: Array<{
            finding_id: string;
            description: string;
            delta_sqi: number;
            priority: string;
        }>;
    };
    overall_risk: string;
}

