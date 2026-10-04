/**
 * Region grouping (DEF-40). Maps an ISO country code (from public-IP geolocation)
 * to a coarse operating region: AMER / EMEA / APAC. An admin can override a
 * machine's region manually (fleet_machines.region); the "effective region" is the
 * manual override when set, otherwise the geo-derived value, otherwise UNKNOWN.
 *
 * The same mapping must drive the SQL filters and the UI, so it lives here once and
 * is emitted both as a SQL CASE snippet and as a JS function.
 */

export const REGIONS = ['AMER', 'EMEA', 'APAC'] as const;
export type Region = (typeof REGIONS)[number] | 'UNKNOWN';

// Country code → region. Not exhaustive, but covers the common markets; anything
// unlisted falls through to UNKNOWN and can be fixed with a manual override.
const AMER = ['US', 'CA', 'MX', 'BR', 'AR', 'CL', 'CO', 'PE', 'VE', 'EC', 'UY', 'PY', 'BO', 'CR', 'PA', 'GT', 'DO', 'PR'];
const EMEA = ['GB', 'IE', 'FR', 'DE', 'NL', 'BE', 'LU', 'ES', 'PT', 'IT', 'CH', 'AT', 'SE', 'NO', 'DK', 'FI', 'IS',
  'PL', 'CZ', 'SK', 'HU', 'RO', 'BG', 'GR', 'HR', 'SI', 'RS', 'UA', 'EE', 'LV', 'LT',
  'AE', 'SA', 'QA', 'KW', 'BH', 'OM', 'IL', 'TR', 'EG', 'ZA', 'NG', 'KE', 'MA', 'JO', 'LB'];
const APAC = ['IN', 'CN', 'JP', 'KR', 'SG', 'HK', 'TW', 'AU', 'NZ', 'ID', 'MY', 'TH', 'PH', 'VN', 'BD', 'PK', 'LK', 'NP', 'KH', 'MM'];

export const countryToRegion = (cc?: string | null): Region => {
  const c = (cc || '').toUpperCase();
  if (!c) return 'UNKNOWN';
  if (AMER.includes(c)) return 'AMER';
  if (EMEA.includes(c)) return 'EMEA';
  if (APAC.includes(c)) return 'APAC';
  return 'UNKNOWN';
};

/**
 * SQL snippet that resolves a machine's geo country column to a region literal.
 * Pass the fully-qualified column (e.g. "m.geo_country"). Returns an expression
 * usable anywhere in a query. Keep in sync with countryToRegion above.
 */
export const regionFromCountrySql = (col: string): string => {
  const list = (arr: string[]) => arr.map((c) => `'${c}'`).join(',');
  return `CASE
    WHEN UPPER(COALESCE(${col},'')) IN (${list(AMER)}) THEN 'AMER'
    WHEN UPPER(COALESCE(${col},'')) IN (${list(EMEA)}) THEN 'EMEA'
    WHEN UPPER(COALESCE(${col},'')) IN (${list(APAC)}) THEN 'APAC'
    ELSE 'UNKNOWN'
  END`;
};

/**
 * Effective region: manual override column when non-empty, else geo-derived.
 * e.g. effectiveRegionSql("m.region", "m.geo_country").
 */
export const effectiveRegionSql = (regionCol: string, countryCol: string): string =>
  `COALESCE(NULLIF(UPPER(${regionCol}), ''), ${regionFromCountrySql(countryCol)})`;
