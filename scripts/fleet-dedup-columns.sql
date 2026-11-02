-- DEF-48: Reconcile the agent's RAW artifact count with the console's de-noised inventory.
-- The fleet ingest collapses OS / public-CA trust-store cert explosions (>=5 certs per
-- bundle/store) into single "Trust Anchor" rows, so the console asset count is lower than
-- the agent's raw total. These columns let the UI show the bridge instead of looking lossy.
--
-- Idempotent: safe to run on every deploy.

ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS raw_asset_count   INTEGER;
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS deduped_cert_count INTEGER;

-- One-time backfill for machines synced BEFORE this change (so the reconciliation line
-- appears without waiting for the next pull). Derives the folded-cert count from the
-- existing "Trust Anchor" rows' own descriptions ("... — N public CA certificates ...").
-- Only fills rows still NULL, so it never clobbers values written by a fresh ingest.
WITH ta AS (
  SELECT
    machine_id,
    COUNT(*)                                                                   AS trust_anchor_rows,
    COALESCE(SUM((substring(description from '([0-9]+) public CA certificate'))::int), 0) AS collapsed_certs
  FROM assets
  WHERE status ILIKE 'Trust Anchor%'
  GROUP BY machine_id
)
UPDATE fleet_machines m
SET deduped_cert_count = ta.collapsed_certs,
    raw_asset_count    = m.asset_count - ta.trust_anchor_rows + ta.collapsed_certs
FROM ta
WHERE m.id = ta.machine_id
  AND ta.collapsed_certs > 0
  AND (m.deduped_cert_count IS NULL OR m.raw_asset_count IS NULL);
