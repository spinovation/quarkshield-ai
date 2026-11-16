/**
 * Compliance verdict: algorithm axis (A1) x module axis (A2)
 * (docs/CMVP_AND_FIPS_COMPLIANCE_MAPPING.md §4.2, Stage 5).
 *
 * A small fixed table, nothing else. The honesty of the result rests on its inputs:
 *  - A1 comes from fipsAlgorithmStatus (a versioned table);
 *  - A2 is `active` / `historical` / `revoked` only for a provider-reported certificate
 *    (Stage 3) or a host module whose identity matched exactly AND whose FIPS-approved mode
 *    was confirmed from host facts (Stage 5). Everything else arrives here as `none`,
 *    `unverified` or `not-assessed` and can never produce `compliant`.
 *
 * `compliant` means: approved algorithm, performed by a module whose current CMVP
 * certificate was matched as above. It is a statement about that pairing as observed, not a
 * certification of the system, and exports carry the evidence and table versions beside it.
 */
import type { FipsStatus } from './fipsAlgorithmStatus';
import type { CmvpStatus } from './cmvpModules';

export type ComplianceVerdict =
  | 'compliant'              // approved algorithm + module with a current certificate
  | 'compliant_until'        // same, but the algorithm has a published sunset
  | 'validated_sunsetting'   // module certificate is Historical
  | 'validated_revoked'      // module certificate is Revoked
  | 'approved_unvalidated'   // approved algorithm, validated module not confirmed
  | 'restricted_use'         // legacy / verification-only algorithm
  | 'noncompliant'           // disallowed or non-FIPS algorithm, whatever the module
  | 'not_determined'         // algorithm could not be classified
  | 'not_applicable';        // not an algorithm instance (package / module row)

export const VERDICT_ORDER: ComplianceVerdict[] = [
  'noncompliant', 'validated_revoked', 'restricted_use', 'approved_unvalidated',
  'validated_sunsetting', 'compliant_until', 'compliant', 'not_determined', 'not_applicable',
];

export const complianceVerdict = (fips: FipsStatus | string | undefined, cmvp: CmvpStatus | string | undefined): ComplianceVerdict => {
  switch (fips) {
    case 'disallowed':
    case 'non_fips':
      return 'noncompliant';
    case 'restricted':
      return 'restricted_use';
    case 'not_applicable':
      return 'not_applicable';
    case 'approved':
    case 'pq_approved':
    case 'acceptable':
      if (cmvp === 'active') return fips === 'acceptable' ? 'compliant_until' : 'compliant';
      if (cmvp === 'historical') return 'validated_sunsetting';
      if (cmvp === 'revoked') return 'validated_revoked';
      // none / unverified / not-assessed / anything unexpected
      return 'approved_unvalidated';
    default:
      return 'not_determined';
  }
};

export const emptyVerdictCounts = (): Record<ComplianceVerdict, number> =>
  Object.fromEntries(VERDICT_ORDER.map(v => [v, 0])) as Record<ComplianceVerdict, number>;
