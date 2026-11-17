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
 *
 * Stage 6 adds one refinement: when the module's certificate has an approved-algorithm list
 * and the asset's algorithm is NOT on it, `compliant` / `compliant_until` become
 * `compliant_module_algo_unverified`. A coverage of `covered` or `unknown` changes nothing:
 * missing CAVP data is never turned into a worse verdict.
 *
 * Host system-module attribution: a key or certificate file tied to the host's system module by
 * assumption (hostCryptoModules.systemModuleDetailFor) gets `compliant_assumed_module` where an
 * observed link would have given `compliant` / `compliant_until`. It is counted apart.
 */
import type { FipsStatus } from './fipsAlgorithmStatus';
import type { CmvpStatus } from './cmvpModules';
import type { CavpState } from './cavpCoverage';

export type ComplianceVerdict =
  | 'compliant'              // approved algorithm + module with a current certificate
  | 'compliant_until'        // same, but the algorithm has a published sunset
  | 'compliant_module_algo_unverified' // current module certificate, but this algorithm is not on its CAVP list
  | 'compliant_assumed_module' // approved algorithm; the host's system module has a current certificate and approved mode, but that this asset uses it is assumed
  | 'validated_sunsetting'   // module certificate is Historical
  | 'validated_revoked'      // module certificate is Revoked
  | 'approved_unvalidated'   // approved algorithm, validated module not confirmed
  | 'restricted_use'         // legacy / verification-only algorithm
  | 'noncompliant'           // disallowed or non-FIPS algorithm, whatever the module
  | 'not_determined'         // algorithm could not be classified
  | 'not_applicable';        // not an algorithm instance (package / module row)

export const VERDICT_ORDER: ComplianceVerdict[] = [
  'noncompliant', 'validated_revoked', 'restricted_use', 'approved_unvalidated',
  'compliant_module_algo_unverified', 'compliant_assumed_module', 'validated_sunsetting', 'compliant_until', 'compliant', 'not_determined', 'not_applicable',
];

export const complianceVerdict = (
  fips: FipsStatus | string | undefined,
  cmvp: CmvpStatus | string | undefined,
  cavp?: CavpState | string,
  /** The module was tied to the asset by assumption (host system module), not by observation. */
  assumedModule?: boolean,
): ComplianceVerdict => {
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
      if (cmvp === 'active') {
        if (cavp === 'not_covered') return 'compliant_module_algo_unverified';
        // An assumption can never produce `compliant`.
        if (assumedModule) return 'compliant_assumed_module';
        return fips === 'acceptable' ? 'compliant_until' : 'compliant';
      }
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
