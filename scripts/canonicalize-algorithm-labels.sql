-- Canonicalize the agent's descriptive prose "algorithm" labels in existing rows.
-- Mirrors the ingest-side fix (server/src/lib/algorithmLabel.ts, applied in
-- fleetController). The ingest normalizer only touches NEW scans; this cleans the
-- rows already stored. Vulnerability/risk fields are NOT changed — only the
-- algorithm display/grouping label.
--
-- SAFE to re-run (idempotent). One transaction. Run against the central DB:
--   docker exec -i pqc-scanner-db psql -U postgres -d quarkshield_scanner < canonicalize-algorithm-labels.sql

\set ON_ERROR_STOP on
BEGIN;

SELECT COUNT(*) AS prose_labels_before
FROM assets
WHERE algorithm IN (
  'Classical TLS / KEX Protocol','TLS 1.3 / HTTPS Network Transport','HTTPS Client / TLS 1.3 Transport',
  'Diffie-Hellman (Classical KEX)','AES-128 / Symmetric Cipher','Symmetric/Protocol Config',
  'PyCA / OpenSSL Backend / Classical & Hybrid','PyCA / OpenSSL Primitives','Go Cryptography / SSH / OpenPGP',
  'OS Package / Security Runtime','OpenSSL Security Level','Legacy SSH Cipher/KEX','Legacy TLS Protocol (TLS 1.0/1.1)'
) OR algorithm ~* '^legacy(?: tls)? protocol \(.+\)$'
  OR algorithm ~* '^legacy kernel cipher \(.+\)$'
  OR algorithm ~* '^system crypto policy \(.+\)$';

-- ===== 1) Exact-match prose → canonical =====
UPDATE assets SET algorithm = CASE algorithm
  WHEN 'Classical TLS / KEX Protocol'                 THEN 'TLS key exchange (classical)'
  WHEN 'TLS 1.3 / HTTPS Network Transport'            THEN 'TLS 1.3'
  WHEN 'HTTPS Client / TLS 1.3 Transport'             THEN 'TLS 1.3'
  WHEN 'Diffie-Hellman (Classical KEX)'               THEN 'Diffie-Hellman'
  WHEN 'AES-128 / Symmetric Cipher'                   THEN 'AES-128'
  WHEN 'Symmetric/Protocol Config'                    THEN 'Symmetric/protocol config'
  WHEN 'PyCA / OpenSSL Backend / Classical & Hybrid'  THEN 'OpenSSL/PyCA crypto backend'
  WHEN 'PyCA / OpenSSL Primitives'                    THEN 'OpenSSL/PyCA crypto backend'
  WHEN 'Go Cryptography / SSH / OpenPGP'              THEN 'Go crypto library'
  WHEN 'OS Package / Security Runtime'                THEN 'Security runtime (OS package)'
  WHEN 'OpenSSL Security Level'                        THEN 'OpenSSL security level'
  WHEN 'Legacy SSH Cipher/KEX'                         THEN 'Legacy SSH cipher/KEX'
  WHEN 'Legacy TLS Protocol (TLS 1.0/1.1)'            THEN 'TLS 1.0/1.1'
  ELSE algorithm
END
WHERE algorithm IN (
  'Classical TLS / KEX Protocol','TLS 1.3 / HTTPS Network Transport','HTTPS Client / TLS 1.3 Transport',
  'Diffie-Hellman (Classical KEX)','AES-128 / Symmetric Cipher','Symmetric/Protocol Config',
  'PyCA / OpenSSL Backend / Classical & Hybrid','PyCA / OpenSSL Primitives','Go Cryptography / SSH / OpenPGP',
  'OS Package / Security Runtime','OpenSSL Security Level','Legacy SSH Cipher/KEX','Legacy TLS Protocol (TLS 1.0/1.1)'
);

-- ===== 2) Parenthetical wrappers → surface the embedded identity =====
-- "Legacy Protocol (SSL 2.0)" / "Legacy TLS Protocol (X)" → the protocol itself
UPDATE assets SET algorithm = regexp_replace(algorithm, '^legacy(?: tls)? protocol \((.+)\)$', '\1', 'i')
WHERE algorithm ~* '^legacy(?: tls)? protocol \(.+\)$';

-- "Legacy Kernel Cipher (des_cbc)" → "des_cbc (kernel cipher)"
UPDATE assets SET algorithm = regexp_replace(algorithm, '^legacy kernel cipher \((.+)\)$', '\1 (kernel cipher)', 'i')
WHERE algorithm ~* '^legacy kernel cipher \(.+\)$';

-- "System Crypto Policy (LEGACY)" → "System crypto policy: LEGACY"
UPDATE assets SET algorithm = regexp_replace(algorithm, '^system crypto policy \((.+)\)$', 'System crypto policy: \1', 'i')
WHERE algorithm ~* '^system crypto policy \(.+\)$';

SELECT COUNT(*) AS prose_labels_after
FROM assets
WHERE algorithm ~* '(classical tls / kex|/ https network transport|/ tls 1.3 transport|\(classical kex\)|/ symmetric cipher|openssl backend / classical|openssl primitives|cryptography / ssh / openpgp|os package / security runtime|^legacy(?: tls)? protocol \(|^legacy kernel cipher \(|^system crypto policy \()';

COMMIT;
