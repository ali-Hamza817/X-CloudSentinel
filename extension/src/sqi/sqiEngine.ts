import { SecurityFinding, Severity, FindingCategory, SQIResult, SQIBreakdown } from '../types';

/**
 * X-CloudSentinel - SQI Engine
 * Calculates the Security Quality Index (SQI) based on static and AI findings
 */

/**
 * Calculate SQI score (0-100, higher is better)
 * Formula: SQI = 100 - (w1*SL + w2*MC + w3*AR + w4*CE) * 100
 */
export function calculateSQI(
    findings: SecurityFinding[],
    aiConfidence?: number
): SQIResult {
    // 1. Group findings by category
    const slFindings = findings.filter(f => f.category === FindingCategory.SECRET_LEAKAGE);
    const mcFindings = findings.filter(f => f.category === FindingCategory.MISCONFIGURATION);
    const arFindings = findings.filter(f => f.category === FindingCategory.IAM_RISK);
    const ceFindings = findings.filter(f => f.category === FindingCategory.DOCKER_RISK);

    // 2. Calculate dimension risk scores (0-1)
    // We use a non-linear scaling where the first critical finding adds significant risk
    const sl = calculateRiskScore(slFindings);
    const mc = calculateRiskScore(mcFindings);
    const ar = calculateRiskScore(arFindings);
    const ce = calculateRiskScore(ceFindings);

    // 3. Define weights
    // If AI confidence is high, we can shift weights, but for MVP we use stable weights
    const weights = {
        w1: 0.35, // Secret Leakage (Highest impact)
        w2: 0.25, // Misconfiguration
        w3: 0.25, // Access Risk
        w4: 0.15  // Config Entropy
    };

    // 4. Calculate weighted risk
    const weightedRisk = (weights.w1 * sl) + (weights.w2 * mc) + (weights.w3 * ar) + (weights.w4 * ce);
    
    // 5. Convert to 0-100 score
    const rawScore = 100 - (weightedRisk * 100);
    const score = Math.round(Math.max(0, Math.min(100, rawScore)));

    // 6. Determine grade and color
    let grade: 'A' | 'B' | 'C' | 'D' | 'F';
    let color: 'green' | 'yellow' | 'orange' | 'red';

    if (score >= 90) {
        grade = 'A';
        color = 'green';
    } else if (score >= 75) {
        grade = 'B';
        color = 'green';
    } else if (score >= 60) {
        grade = 'C';
        color = 'yellow';
    } else if (score >= 40) {
        grade = 'D';
        color = 'orange';
    } else {
        grade = 'F';
        color = 'red';
    }

    return {
        score,
        breakdown: { sl, mc, ar, ce, weights },
        grade,
        color,
        totalFindings: findings.length
    };
}

/**
 * Calculate a normalized risk score (0-1) for a specific category
 */
function calculateRiskScore(findings: SecurityFinding[]): number {
    if (findings.length === 0) {
        return 0;
    }

    // Weight severity
    // Critical = 1.0, High = 0.7, Medium = 0.4, Low = 0.1
    let totalWeight = 0;
    for (const f of findings) {
        switch (f.severity) {
            case Severity.CRITICAL: totalWeight += 1.0; break;
            case Severity.HIGH: totalWeight += 0.7; break;
            case Severity.MEDIUM: totalWeight += 0.4; break;
            case Severity.LOW: totalWeight += 0.1; break;
            default: totalWeight += 0.05;
        }
    }

    // Sigmoid-like saturation: 1 critical finding should result in ~0.5 risk, 
    // multiple critical findings saturate towards 1.0
    // formula: 1 - exp(-k * totalWeight)
    const k = 0.7; // Sensitivity constant
    const risk = 1 - Math.exp(-k * totalWeight);

    return Math.min(1.0, risk);
}

