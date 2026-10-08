/**
 * Risk scoring (design doc §11). Likelihood (1–4) × Impact (1–4) = inherent risk (1–16).
 *   Low × Low → Low · Medium × High → High · High × Critical → Critical
 * Residual risk is lowered ONLY by remediation state (done / verified). Configuration
 * presence is never treated as proven control effectiveness — that belongs to MGC/RMF.
 */
import { DataClassification, RiskLevel, TrAsset, RemediationStatus } from './types';

const CLASS_SCORE: Record<DataClassification, number> = { public: 1, internal: 2, sensitive: 3, cui: 4 };

export const impactOf = (a: Pick<TrAsset, 'criticality' | 'data_classification'>): number =>
  Math.max(1, Math.min(4, Math.max(a.criticality, CLASS_SCORE[a.data_classification] || 2)));

export const riskLevel = (score: number): RiskLevel =>
  score >= 12 ? 'critical' : score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low';

export const RESOLVED: RemediationStatus[] = ['done', 'verified'];

/** Residual likelihood after remediation progress (fraction of remediations resolved). */
export const residualLikelihood = (likelihood: number, statuses: RemediationStatus[]): number => {
  if (!statuses.length) return likelihood;
  const resolved = statuses.filter(s => RESOLVED.includes(s)).length / statuses.length;
  return Math.max(1, likelihood - Math.round(resolved * (likelihood - 1)));
};

/** 0–100 roll-up weighted toward the worst risks (top 10 residual scores). */
export const overallRiskScore = (residualScores: number[]): number => {
  if (!residualScores.length) return 0;
  const top = [...residualScores].sort((a, b) => b - a).slice(0, 10);
  const max = top[0];
  const avg = top.reduce((s, x) => s + x, 0) / top.length;
  return Math.round((100 * (0.6 * max + 0.4 * avg)) / 16);
};
