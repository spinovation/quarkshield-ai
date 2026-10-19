-- Collapse the existing OS / public CA trust-store explosion in the assets table.
-- Mirrors the ingest-side fix (fleetController getFleetCBOM / sync): every certificate
-- inside OS CA trust bundles (ca-bundle.crt, ca-certificates.crt, *-ca-bundle.pem ...) and
-- every individual public root ("Linux Trust Store: <CA>") was stored as its own row --
-- hundreds of indistinguishable public trust anchors per host, inflating asset counts ~9x.
-- This keeps ONE informational trust-anchor row per trust SOURCE and removes the rest.
--
-- SAFE to re-run (idempotent). Runs in ONE transaction. Only collapses groups of >= 5
-- (never a one-off private CA). Run against the central DB:
--   docker exec -i pqc-scanner-db psql -U postgres -d quarkshield_scanner < collapse-trust-store-assets.sql

\set ON_ERROR_STOP on
BEGIN;

SELECT COUNT(*) AS assets_before FROM assets;

-- ===== 1) Collapse OS CA trust BUNDLE FILES, per (machine_id, name) =====
CREATE TEMP TABLE _bundle ON COMMIT DROP AS
  SELECT machine_id, name,
         (array_agg(id ORDER BY id))[1] AS keep_id,
         COUNT(*)::int AS cnt,
         COALESCE(NULLIF(string_agg(DISTINCT NULLIF(algorithm,''), ' / '), ''), 'RSA/ECC') AS algos
  FROM assets
  WHERE type ILIKE '%cert%'
    AND name ~* '(ca-bundle|ca-certificates|tls-ca-bundle|objsign-ca-bundle|email-ca-bundle|-ca-bundle\.pem|cacert)'
  GROUP BY machine_id, name
  HAVING COUNT(*) >= 5;

UPDATE assets a SET
  is_vulnerable  = false,
  risk_level     = 'informational',
  status         = 'Trust Anchor (OS / public CA store)',
  algorithm      = b.algos,
  description    = 'OS CA trust bundle "'||a.name||'" — '||b.cnt||' public CA certificates (trust anchors, not tenant-owned keys). Algorithms: '||b.algos||'.',
  recommendation = 'Public trust anchors are managed via OS / trust-store updates, not PQC key migration.'
FROM _bundle b WHERE a.id = b.keep_id;

DELETE FROM assets a USING _bundle b
WHERE a.machine_id IS NOT DISTINCT FROM b.machine_id
  AND a.name = b.name
  AND a.id <> b.keep_id
  AND a.type ILIKE '%cert%'
  AND a.name ~* '(ca-bundle|ca-certificates|tls-ca-bundle|objsign-ca-bundle|email-ca-bundle|-ca-bundle\.pem|cacert)';

-- ===== 2) Collapse individual public roots per machine into one row =====
-- (exclude the bundle-file names handled by pass 1)
CREATE TEMP TABLE _roots ON COMMIT DROP AS
  SELECT machine_id,
         (array_agg(id ORDER BY id))[1] AS keep_id,
         COUNT(*)::int AS cnt,
         COALESCE(NULLIF(string_agg(DISTINCT NULLIF(algorithm,''), ' / '), ''), 'RSA/ECC') AS algos
  FROM assets
  WHERE type ILIKE '%cert%'
    AND name !~* '(ca-bundle|ca-certificates|tls-ca-bundle|objsign-ca-bundle|email-ca-bundle|-ca-bundle\.pem|cacert)'
    AND (name ~* '^Linux Trust Store:' OR COALESCE(path,'') ~* '(/etc/ssl/certs|/etc/pki/|/usr/share/ca-certificates)')
  GROUP BY machine_id
  HAVING COUNT(*) >= 5;

UPDATE assets a SET
  name           = 'OS Public CA Trust Store (roots)',
  is_vulnerable  = false,
  risk_level     = 'informational',
  status         = 'Trust Anchor (OS / public CA store)',
  algorithm      = r.algos,
  description    = 'System public CA trust store — '||r.cnt||' public CA certificates (trust anchors, not tenant-owned keys). Algorithms: '||r.algos||'.',
  recommendation = 'Public trust anchors are managed via OS / trust-store updates, not PQC key migration.'
FROM _roots r WHERE a.id = r.keep_id;

DELETE FROM assets a USING _roots r
WHERE a.machine_id IS NOT DISTINCT FROM r.machine_id
  AND a.id <> r.keep_id
  AND a.type ILIKE '%cert%'
  AND a.name !~* '(ca-bundle|ca-certificates|tls-ca-bundle|objsign-ca-bundle|email-ca-bundle|-ca-bundle\.pem|cacert)'
  AND (a.name ~* '^Linux Trust Store:' OR COALESCE(a.path,'') ~* '(/etc/ssl/certs|/etc/pki/|/usr/share/ca-certificates)');

-- ===== 3) Refresh per-machine asset / vulnerable counts =====
UPDATE fleet_machines m SET
  asset_count      = s.cnt,
  vulnerable_count = s.vuln
FROM (SELECT machine_id, COUNT(*)::int AS cnt, COUNT(*) FILTER (WHERE is_vulnerable)::int AS vuln
      FROM assets GROUP BY machine_id) s
WHERE m.id = s.machine_id;

SELECT COUNT(*) AS assets_after FROM assets;

COMMIT;
