-- Remove fabricated ENTERPRISE_TENANT_SBOM_TEMPLATE rows and normalize the
-- spinovationcorp tenant-name casing split.
--
-- Context (verified against the live DB 2026-10-22):
--   * Real agent-collected SBOM rows have source = 'endpoint' (actual hosts:
--     web01, qs-demo-1, AWS instances, Ganapatis-MBP).
--   * The hardcoded demo template seeds rows with source IN
--     ('endpoint_os','endpoint_agent','repository') and invented hosts/repos
--     ("Desktop Agent (<tenant> Endpoint)", "repo: auth-service (package.json)").
--   * algomeld has ZERO fleet_machines (no agent) yet showed 11 template rows as
--     if real — pure fiction. SPINOVATIONCORP (uppercase) carried 11 template rows
--     mixed in with its 14 real Mac rows.
--   * The authoritative tenant key in tenant_users is lowercase 'spinovationcorp';
--     fleet_machines / tenant_settings / sbom_components drifted to mixed casing.
--
-- This script: (1) deletes the fabricated template rows, (2) normalizes the
-- spinovation casing to lowercase. Real agent data (source='endpoint') is never
-- touched. SAFE to re-run (idempotent). One transaction.
--   docker exec -i pqc-scanner-db psql -U postgres -d quarkshield_scanner < cleanup-fabricated-sbom.sql

\set ON_ERROR_STOP on
BEGIN;

-- ---- Preview: what is about to be deleted ----
SELECT '== FABRICATED ROWS TO DELETE ==' AS preview;
SELECT tenant_name, source, source_ref, name, version
FROM sbom_components
WHERE source IN ('endpoint_os','endpoint_agent','repository')
ORDER BY tenant_name, source, name;

SELECT '== counts before =='  AS stage;
SELECT tenant_name, COUNT(*) AS total,
       COUNT(*) FILTER (WHERE source IN ('endpoint_os','endpoint_agent','repository')) AS fabricated
FROM sbom_components GROUP BY tenant_name ORDER BY tenant_name;

-- ---- 1) Delete fabricated template SBOM rows (never source='endpoint') ----
DELETE FROM sbom_components
WHERE source IN ('endpoint_os','endpoint_agent','repository');

-- ---- 2) Normalize spinovationcorp casing to the authoritative lowercase key ----
-- sbom_components: lowercase any remaining spinovation rows.
UPDATE sbom_components SET tenant_name = 'spinovationcorp'
WHERE tenant_name <> 'spinovationcorp' AND LOWER(tenant_name) = 'spinovationcorp';

-- fleet_machines: lowercase (id is PK, tenant_name is not — no conflict).
UPDATE fleet_machines SET tenant_name = 'spinovationcorp'
WHERE tenant_name <> 'spinovationcorp' AND LOWER(tenant_name) = 'spinovationcorp';

-- tenant_settings: lowercase only when it would not collide with an existing
-- lowercase row (fold into the canonical row if both exist, else rename).
DELETE FROM tenant_settings ts
WHERE ts.tenant_name <> 'spinovationcorp'
  AND LOWER(ts.tenant_name) = 'spinovationcorp'
  AND EXISTS (SELECT 1 FROM tenant_settings k WHERE k.tenant_name = 'spinovationcorp'
              AND k.key = ts.key);
UPDATE tenant_settings SET tenant_name = 'spinovationcorp'
WHERE tenant_name <> 'spinovationcorp' AND LOWER(tenant_name) = 'spinovationcorp';

-- ---- Verify ----
SELECT '== counts after =='  AS stage;
SELECT tenant_name, COUNT(*) AS total,
       STRING_AGG(DISTINCT source, ',') AS sources
FROM sbom_components GROUP BY tenant_name ORDER BY tenant_name;

SELECT '== spinovation casing after =='  AS stage;
SELECT 'sbom_components' AS tbl, STRING_AGG(DISTINCT tenant_name, ' | ') FROM sbom_components WHERE tenant_name ILIKE 'spinovation%'
UNION ALL SELECT 'fleet_machines', STRING_AGG(DISTINCT tenant_name, ' | ') FROM fleet_machines WHERE tenant_name ILIKE 'spinovation%'
UNION ALL SELECT 'tenant_settings', STRING_AGG(DISTINCT tenant_name, ' | ') FROM tenant_settings WHERE tenant_name ILIKE 'spinovation%';

COMMIT;
