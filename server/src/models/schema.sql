-- QuarkShield Desktop & Host PQC Vulnerability Scanner Database Schema

CREATE TABLE IF NOT EXISTS fleet_tokens (
  id VARCHAR(100) PRIMARY KEY,
  name VARCHAR(255) UNIQUE NOT NULL,
  token VARCHAR(255) UNIQUE NOT NULL,
  status VARCHAR(50) DEFAULT 'active',
  last_sync TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fleet_machines (
  id VARCHAR(100) PRIMARY KEY,
  token_id VARCHAR(100) REFERENCES fleet_tokens(id) ON DELETE SET NULL,
  hostname VARCHAR(255) NOT NULL,
  os VARCHAR(100) NOT NULL,
  arch VARCHAR(50),
  ip VARCHAR(100),
  agent_version VARCHAR(50) DEFAULT '2.0.0',
  status VARCHAR(50) DEFAULT 'online',
  risk_level VARCHAR(50) DEFAULT 'medium',
  quantum_risk_score INTEGER DEFAULT 0,
  asset_count INTEGER DEFAULT 0,
  vulnerable_count INTEGER DEFAULT 0,
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assets (
  id VARCHAR(100) PRIMARY KEY,
  machine_id VARCHAR(100) REFERENCES fleet_machines(id) ON DELETE CASCADE,
  type VARCHAR(50) NOT NULL,
  name VARCHAR(255) NOT NULL,
  algorithm VARCHAR(100) NOT NULL,
  key_size INTEGER,
  hash_algorithm VARCHAR(50),
  is_vulnerable BOOLEAN DEFAULT true,
  risk_level VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL,
  description TEXT,
  recommendation TEXT,
  explainer TEXT,
  compliance_violations TEXT[],
  path TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Ensure migration on existing tables
ALTER TABLE assets ADD COLUMN IF NOT EXISTS path TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS source VARCHAR(100) DEFAULT 'endpoint';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS source_ref VARCHAR(500);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE git_scans ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) DEFAULT 'SPINOVATIONCORP';
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS hardware_uuid VARCHAR(100);
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS computer_name VARCHAR(255);
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS last_sync TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Fleet Daily Snapshots for Historical Posture Tracking (Without Polluting Seats)
CREATE TABLE IF NOT EXISTS fleet_daily_snapshots (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL,
  snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
  active_workstations INTEGER DEFAULT 0,
  total_assets INTEGER DEFAULT 0,
  vulnerable_assets INTEGER DEFAULT 0,
  shor_count INTEGER DEFAULT 0,
  grover_count INTEGER DEFAULT 0,
  config_violation_count INTEGER DEFAULT 0,
  average_risk_score INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tenant_name, snapshot_date)
);

-- Fleet Commands for On-Demand Pull Requests from Central Console
CREATE TABLE IF NOT EXISTS fleet_commands (
  id VARCHAR(100) PRIMARY KEY,
  machine_id VARCHAR(100) REFERENCES fleet_machines(id) ON DELETE CASCADE,
  command VARCHAR(50) NOT NULL,
  status VARCHAR(50) DEFAULT 'pending',
  details TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP WITH TIME ZONE
);

-- ==========================================
-- ADMIN PANEL SCHEMAS (QUARKSHIELD REPLICA)
-- ==========================================

CREATE TABLE IF NOT EXISTS admin_users (
  id VARCHAR(100) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255),
  salt VARCHAR(255),
  role VARCHAR(50) DEFAULT 'user',
  email_verified BOOLEAN DEFAULT true,
  two_factor_enabled BOOLEAN DEFAULT false,
  two_factor_secret VARCHAR(255),
  cmdb_enabled BOOLEAN DEFAULT true,
  playbook_enabled BOOLEAN DEFAULT true,
  web3_enabled BOOLEAN DEFAULT true,
  row_locked BOOLEAN DEFAULT false,
  company VARCHAR(255),
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_clients (
  id VARCHAR(100) PRIMARY KEY,
  name VARCHAR(255) UNIQUE NOT NULL,
  display_name VARCHAR(255),
  app_port INTEGER DEFAULT 5050,
  db_port INTEGER DEFAULT 5432,
  status VARCHAR(50) DEFAULT 'active',
  subscription_tier VARCHAR(50) DEFAULT 'growth',
  mca_limit INTEGER DEFAULT 250,
  two_factor_policy VARCHAR(50) DEFAULT 'optional',
  user_count INTEGER DEFAULT 1,
  asset_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Idempotent schema migrations for existing databases
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS two_factor_policy VARCHAR(50) DEFAULT 'optional';
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS contact_name VARCHAR(255);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS admin_email VARCHAR(255);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS address VARCHAR(255);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS city VARCHAR(100);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS state VARCHAR(100);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS country VARCHAR(100);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS postal_code VARCHAR(50);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS account_type VARCHAR(50) DEFAULT 'corporate';
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS stripe_payment_link VARCHAR(500);
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS stripe_payment_status VARCHAR(50) DEFAULT 'unpaid';
ALTER TABLE admin_clients ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS contact_name VARCHAR(255);
ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS salt VARCHAR(255);

ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS salt VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT false;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false;

CREATE TABLE IF NOT EXISTS tenant_users (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  role VARCHAR(50) DEFAULT 'secops',
  two_factor_enabled BOOLEAN DEFAULT false,
  two_factor_secret VARCHAR(255),
  status VARCHAR(50) DEFAULT 'active',
  must_change_password BOOLEAN DEFAULT false,
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tenant_name, email)
);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false;

CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_name VARCHAR(255) NOT NULL,
  key VARCHAR(100) NOT NULL,
  value TEXT NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_name, key)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id VARCHAR(100) PRIMARY KEY,
  action VARCHAR(100) NOT NULL,
  actor VARCHAR(255) NOT NULL,
  details TEXT,
  ip_address VARCHAR(100),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_licenses (
  id VARCHAR(100) PRIMARY KEY,
  license_key VARCHAR(255) UNIQUE NOT NULL,
  tenant_name VARCHAR(255) NOT NULL,
  tier VARCHAR(50) NOT NULL,
  duration_days INTEGER NOT NULL,
  seats INTEGER DEFAULT 100,
  status VARCHAR(50) DEFAULT 'active',
  created_by VARCHAR(255) DEFAULT 'admin',
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed initial admin users for quarkshield.ai (Completely separate from quarkshield.services)
INSERT INTO admin_users (id, email, password_hash, salt, role, email_verified, cmdb_enabled, playbook_enabled, web3_enabled, row_locked, company, last_login)
VALUES 
  ('usr-super', 'superadmin@quarkshield.ai', '46700cb75574341aa57053e1476d0e372f2766e4170e28e16f88255748259a4f', 'a1b2c3d4e5f6', 'superadmin', true, true, true, true, false, 'QuarkShield Core', CURRENT_TIMESTAMP),
  ('usr-sridhar', 'sridhargs@gmail.com', '46700cb75574341aa57053e1476d0e372f2766e4170e28e16f88255748259a4f', 'a1b2c3d4e5f6', 'superadmin', true, true, true, true, false, 'QuarkShield Security', CURRENT_TIMESTAMP),
  ('usr-admin', 'admin@quarkshield.ai', '46700cb75574341aa57053e1476d0e372f2766e4170e28e16f88255748259a4f', 'a1b2c3d4e5f6', 'superadmin', true, true, true, true, false, 'QuarkShield Operations', CURRENT_TIMESTAMP),
  ('usr-demo', 'democlient@example.com', NULL, NULL, 'user', true, true, false, false, false, 'Demo Client Workspace', CURRENT_TIMESTAMP - INTERVAL '12 minutes'),
  ('usr-locked', 'locked_client@example.com', NULL, NULL, 'user', true, false, false, false, true, 'Locked Security Node', CURRENT_TIMESTAMP - INTERVAL '24 minutes'),
  ('usr-pending', 'pending_client@example.com', NULL, NULL, 'user', true, false, false, false, false, 'Pending Evaluation Node', NULL)
ON CONFLICT (email) DO NOTHING;  -- seed only; do not overwrite admin edits on restart (DEF-18)

-- Seed initial client organizations / tenants for quarkshield.ai
INSERT INTO admin_clients (id, name, display_name, app_port, db_port, status, subscription_tier, mca_limit, two_factor_policy, user_count, asset_count, account_type, customer_id, admin_email, contact_name)
VALUES 
  ('client-demo', 'democlient', 'Demo Client Workspace', 5001, 5433, 'active', 'growth', 250, 'optional', 1, 6, 'corporate', 'CORP-5120', 'democlient@example.com', 'Demo Administrator'),
  ('client-090e8814', 'spinovationcorp', 'Spinovation Corp', 5002, 5434, 'active', 'growth', 100, 'optional', 1, 10, 'corporate', 'CORP-9812', 'sridhargs@spinovation.com', 'GS Sridhar'),
  ('client-vanguard-corp', 'vanguard-logistics', 'Vanguard Global Logistics', 5003, 5435, 'active', 'growth', 500, 'optional', 1, 8, 'corporate', 'CORP-4821', 's.jenkins@vanguardlogistics.com', 'Sarah Jenkins'),
  ('client-apex-msp', 'apex-cyber', 'Apex Cyber Defense MSP', 5050, 5436, 'active', 'growth', 300, 'optional', 1, 12, 'partner', 'PART-9148', 'm.vance@apexcyberdefense.io', 'Marcus Vance'),
  ('client-cyber-shield', 'cybershield-partners', 'CyberShield Managed Security', 5051, 5437, 'active', 'growth', 50, 'optional', 1, 4, 'partner', 'PART-8830', 'd.chen@cybershieldsec.com', 'David Chen')
ON CONFLICT (name) DO NOTHING;  -- seed only; do not overwrite tenant edits on restart (DEF-18)

INSERT INTO admin_licenses (id, license_key, tenant_name, customer_id, tier, duration_days, seats, status, expires_at, contact_name, contact_email)
VALUES
  ('lic-corp-spinovation', 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8', 'SPINOVATIONCORP', 'CORP-9812', 'corporate', 365, 100, 'active', CURRENT_TIMESTAMP + INTERVAL '365 days', 'GS Sridhar', 'sridhargs@spinovation.com'),
  ('lic-corp-apexlabs', 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E', 'APEXDEFENSELABS', 'CORP-4821', 'corporate', 365, 500, 'active', CURRENT_TIMESTAMP + INTERVAL '365 days', 'Sarah Jenkins', 's.jenkins@vanguardlogistics.com'),
  ('lic-corp-demo', 'QS-CORP-DEMOCLIENT-6C8A00AF-E49AB1C1', 'DEMOCLIENT', 'CORP-5120', 'corporate', 365, 250, 'active', CURRENT_TIMESTAMP + INTERVAL '365 days', 'Demo Administrator', 'democlient@example.com'),
  ('lic-apex-sub-1', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF8523-56AAF752', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 30, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-apex-sub-2', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF8540-E2611017', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 30, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-apex-sub-3', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF87F9-B61B99FC', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 30, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-apex-sub-4', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6AF7E81F-457D9F5B', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 60, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '60 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-apex-sub-5', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B05175B-D5CF3CE4', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 60, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '60 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-apex-sub-6', 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B124697-74B82994', 'APEXCYBERDEFENSEMSP', 'PART-9148', 'partner', 90, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '90 days', 'Marcus Vance', 'm.vance@apexcyberdefense.io'),
  ('lic-part-test', 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296', 'PARTNERTEST', 'PART-8830', 'partner', 30, 50, 'active', CURRENT_TIMESTAMP + INTERVAL '30 days', 'David Chen', 'd.chen@cybershieldsec.com')
ON CONFLICT (license_key) DO NOTHING;

-- Remote Git Repository Security & PQC Audit Logs
CREATE TABLE IF NOT EXISTS git_scans (
  id VARCHAR(100) PRIMARY KEY,
  provider VARCHAR(50) NOT NULL,
  repo_url VARCHAR(500) NOT NULL,
  repo_name VARCHAR(255) NOT NULL,
  branch VARCHAR(100) DEFAULT 'main',
  commit_hash VARCHAR(100),
  quantum_risk_score INTEGER DEFAULT 0,
  total_assets INTEGER DEFAULT 0,
  vulnerable_count INTEGER DEFAULT 0,
  pqc_count INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  summary_text TEXT,
  findings JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================================
-- IDEMPOTENT WORKSTATION DEDUPLICATION MIGRATION
-- Purge duplicate enrollment rows and keep strictly the latest sync per machine
-- =========================================================================

-- (Removed) Developer-specific machine dedup/rename migrations that ran on
-- every boot: they deleted machines by hostname and renamed EVERY darwin
-- machine to one name with a fixed hardware_uuid, corrupting multi-Mac
-- tenants (DEF-18/35). One-time cleanups do not belong in the boot schema.

-- 4. Ensure computer_name is populated for other known physical machines
UPDATE fleet_machines 
SET computer_name = hostname 
WHERE computer_name IS NULL OR computer_name = '';

-- 5. Sync client asset count for Spinovation Corp
UPDATE admin_clients
SET asset_count = (
  SELECT COALESCE(SUM(asset_count), 0) 
  FROM fleet_machines 
  WHERE LOWER(tenant_name) LIKE '%spinovation%'
)
WHERE LOWER(name) IN ('spinovation', 'spinovationcorp');

-- 6. Initialize initial daily snapshot for Spinovation Corp
INSERT INTO fleet_daily_snapshots (
  id, tenant_name, snapshot_date, active_workstations, total_assets, vulnerable_assets, average_risk_score
)
SELECT 
  'snap-spinovation-' || TO_CHAR(CURRENT_DATE, 'YYYYMMDD'),
  'SPINOVATIONCORP',
  CURRENT_DATE,
  COUNT(DISTINCT id),
  COALESCE(SUM(asset_count), 0),
  COALESCE(SUM(vulnerable_count), 0),
  COALESCE(ROUND(AVG(quantum_risk_score)), 0)
FROM fleet_machines 
WHERE LOWER(tenant_name) LIKE '%spinovation%'
ON CONFLICT (tenant_name, snapshot_date) DO NOTHING;

-- Backfill existing assets with tenant_name, source, and source_ref from fleet_machines
UPDATE assets 
SET 
  tenant_name = COALESCE(assets.tenant_name, m.tenant_name, 'SPINOVATIONCORP'),
  source = COALESCE(assets.source, 'endpoint_deploy'),
  source_ref = COALESCE(assets.source_ref, m.hostname, 'workstation')
FROM fleet_machines m
WHERE assets.machine_id = m.id AND (assets.tenant_name IS NULL OR assets.source IS NULL);

-- =========================================================================
-- 7. CI/CD PIPELINE CBOM SECURITY GATES
-- =========================================================================

CREATE TABLE IF NOT EXISTS ci_security_gates (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL DEFAULT 'SPINOVATIONCORP',
  provider VARCHAR(50) NOT NULL, -- 'github', 'gitlab', 'bitbucket', 'cli'
  repo_name VARCHAR(255) NOT NULL,
  repo_url VARCHAR(500),
  branch VARCHAR(100) DEFAULT 'main',
  pr_number VARCHAR(50),
  commit_hash VARCHAR(100),
  commit_author VARCHAR(255),
  commit_message TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'PASSED', -- 'PASSED', 'BLOCKED', 'WARNING'
  violations_count INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  quantum_risk_score INTEGER DEFAULT 0,
  policy_name VARCHAR(100) DEFAULT 'CNSA 2.0 Strict Gate',
  findings JSONB DEFAULT '[]'::jsonb,
  markdown_report TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ci_gate_policies (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  block_on_rsa BOOLEAN DEFAULT true,
  block_on_ecc BOOLEAN DEFAULT true,
  block_on_deprecated_hash BOOLEAN DEFAULT true, -- MD5, SHA1
  block_on_hardcoded_keys BOOLEAN DEFAULT true,
  max_quantum_risk_score INTEGER DEFAULT 45,
  enforce_cnsa_2026 BOOLEAN DEFAULT true,
  is_default BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tenant_name, name)
);

-- =========================================================================
-- 8. ENTERPRISE PKI & CLOUD VAULT CONNECTORS
-- =========================================================================

CREATE TABLE IF NOT EXISTS pki_connectors (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL DEFAULT 'SPINOVATIONCORP',
  name VARCHAR(255) NOT NULL,
  provider VARCHAR(50) NOT NULL, -- 'aws_kms', 'azure_keyvault', 'hashicorp_vault', 'ad_cs'
  endpoint_url VARCHAR(500),
  auth_type VARCHAR(50) DEFAULT 'token', -- 'iam_role', 'service_principal', 'token', 'kerberos'
  config_summary JSONB DEFAULT '{}'::jsonb,
  sync_status VARCHAR(50) DEFAULT 'active', -- 'active', 'syncing', 'error', 'idle'
  total_keys_discovered INTEGER DEFAULT 0,
  vulnerable_keys_count INTEGER DEFAULT 0,
  pqc_ready_count INTEGER DEFAULT 0,
  last_sync_at TIMESTAMP WITH TIME ZONE,
  last_error TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pki_synced_assets (
  id VARCHAR(100) PRIMARY KEY,
  connector_id VARCHAR(100) REFERENCES pki_connectors(id) ON DELETE CASCADE,
  tenant_name VARCHAR(255) NOT NULL,
  asset_name VARCHAR(255) NOT NULL,
  asset_type VARCHAR(50) NOT NULL, -- 'asymmetric_key', 'symmetric_key', 'certificate', 'ca_root', 'template'
  algorithm VARCHAR(100) NOT NULL,
  key_size INTEGER,
  curve VARCHAR(50),
  is_vulnerable BOOLEAN DEFAULT true,
  risk_level VARCHAR(50) NOT NULL DEFAULT 'critical',
  quantum_threat VARCHAR(255),
  status VARCHAR(100) DEFAULT 'Active',
  rotation_enabled BOOLEAN DEFAULT false,
  expires_at TIMESTAMP WITH TIME ZONE,
  raw_metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================================
-- 9. HYBRID QUANTUM TLS REVERSE PROXIES
-- =========================================================================

CREATE TABLE IF NOT EXISTS pqc_proxies (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL DEFAULT 'SPINOVATIONCORP',
  name VARCHAR(255) NOT NULL,
  listen_port INTEGER NOT NULL,
  upstream_url VARCHAR(500) NOT NULL,
  tls_curve VARCHAR(100) DEFAULT 'X25519MLKEM768',
  status VARCHAR(50) DEFAULT 'running', -- 'running', 'stopped', 'error'
  handshake_count INTEGER DEFAULT 0,
  active_connections INTEGER DEFAULT 0,
  cert_expiry TIMESTAMP WITH TIME ZONE,
  last_active_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================================
-- SEED INITIAL MOCK DATA FOR DEMONSTRATION & ENTERPRISE TESTING
-- =========================================================================

-- Seed sample CI/CD gates
INSERT INTO ci_security_gates (id, tenant_name, provider, repo_name, repo_url, branch, pr_number, commit_hash, commit_author, commit_message, status, violations_count, critical_count, high_count, quantum_risk_score, policy_name, markdown_report)
VALUES 
  ('gate-pr-104', 'SPINOVATIONCORP', 'github', 'spinovation/payments-microservice', 'https://github.com/spinovation/payments-microservice', 'feature/stripe-v2', 'PR #104', 'e3a180b', 'alex.mercer@spinovation.com', 'feat: update payment signing and auth keys', 'BLOCKED', 3, 2, 1, 88, 'CNSA 2.0 Strict Gate', '### QuarkShield CI/CD Gate: FAILED\n\n**3 Quantum-Vulnerable Cryptographic Assets Detected**\n\n- **CRITICAL**: Hardcoded RSA-2048 private key in `src/auth/signer.ts:42`\n- **HIGH**: Deprecated SHA-1 signature algorithm in `config/token.json:12`\n- **CRITICAL**: Classical ECDSA secp256k1 signature without PQC ML-DSA fallback.\n\n*Please migrate keys to NIST FIPS 204 (ML-DSA) or hybrid X25519MLKEM768.*'),
  ('gate-pr-105', 'SPINOVATIONCORP', 'github', 'spinovation/auth-service', 'https://github.com/spinovation/auth-service', 'fix/session-tokens', 'PR #105', '9bc231a', 'elena.rostova@spinovation.com', 'fix: migrate JWT to ML-DSA hybrid signature', 'PASSED', 0, 0, 0, 10, 'CNSA 2.0 Strict Gate', '### QuarkShield CI/CD Gate: PASSED\n\nAll commits verified compliant with NIST FIPS 203/204 and NSA CNSA 2.0 requirements. Zero classical vulnerabilities detected.'),
  ('gate-pr-42', 'SPINOVATIONCORP', 'gitlab', 'spinovation/core-api-gateway', 'https://gitlab.com/spinovation/core-api-gateway', 'main', 'MR #42', 'f88219c', 'devops@spinovation.com', 'chore: update TLS ingress ciphers', 'PASSED', 0, 0, 0, 12, 'CNSA 2.0 Strict Gate', '### QuarkShield CI/CD Gate: PASSED\n\nTLS 1.3 hybrid curve X25519MLKEM768 enabled on all ingress listeners.'),
  ('gate-pr-88', 'AMBEROON', 'github', 'amberoon/aml-risk-engine', 'https://github.com/amberoon/aml-risk-engine', 'feat/financial-tx-signer', 'PR #88', '2c4180d', 'shirish.netke@amberoon.com', 'feat: add transaction verification pipeline', 'BLOCKED', 2, 1, 1, 78, 'CNSA 2.0 Strict Gate', '### QuarkShield CI/CD Gate: FAILED\n\n- **CRITICAL**: RSA 2048 encryption key discovered in `services/encryptor.py:19`\n- **HIGH**: 3DES legacy encryption cipher in legacy adapter.\n\n*Action Required: Replace with AES-256-GCM and NIST FIPS 203 ML-KEM-768.*')
ON CONFLICT (id) DO NOTHING;

-- Seed default CI Gate policies
INSERT INTO ci_gate_policies (id, tenant_name, name, block_on_rsa, block_on_ecc, block_on_deprecated_hash, block_on_hardcoded_keys, max_quantum_risk_score, enforce_cnsa_2026, is_default)
VALUES 
  ('policy-cnsa-strict', 'global', 'CNSA 2.0 Strict Security Gate', true, true, true, true, 30, true, true),
  ('policy-standard-migration', 'global', 'NIST PQC Transition Balanced Gate', true, false, true, true, 60, false, false),
  ('policy-fips-zero-tolerance', 'global', 'Zero-Tolerance Quantum Resistant Gate', true, true, true, true, 10, true, false)
ON CONFLICT (tenant_name, name) DO NOTHING;

-- Seed sample PKI connectors
INSERT INTO pki_connectors (id, tenant_name, name, provider, endpoint_url, auth_type, config_summary, sync_status, total_keys_discovered, vulnerable_keys_count, pqc_ready_count, last_sync_at)
VALUES
  ('conn-aws-kms', 'SPINOVATIONCORP', 'AWS KMS Production (us-east-1)', 'aws_kms', 'https://kms.us-east-1.amazonaws.com', 'iam_role', '{"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/QuarkShieldDiscoveryRole", "key_count": 28}'::jsonb, 'active', 28, 22, 6, CURRENT_TIMESTAMP - INTERVAL '14 minutes'),
  ('conn-azure-kv', 'SPINOVATIONCORP', 'Azure Key Vault (East US)', 'azure_keyvault', 'https://spin-prod-vault.vault.azure.net', 'service_principal', '{"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "e8910d-prod-sp", "vault_name": "spin-prod-vault"}'::jsonb, 'active', 19, 15, 4, CURRENT_TIMESTAMP - INTERVAL '32 minutes'),
  ('conn-hashi-vault', 'SPINOVATIONCORP', 'HashiCorp Vault Enterprise (Datacenter A)', 'hashicorp_vault', 'https://vault.internal.spinovation.com:8200', 'token', '{"pki_engine_mount": "pki_v1", "transit_engine_mount": "transit", "auth_method": "approle"}'::jsonb, 'active', 44, 38, 6, CURRENT_TIMESTAMP - INTERVAL '1 hour'),
  ('conn-ad-cs', 'SPINOVATIONCORP', 'Active Directory Certificate Services (AD CS)', 'ad_cs', 'ldap://ca01.corp.spinovation.local:389', 'kerberos', '{"ca_name": "Spinovation-Enterprise-Root-CA", "base_dn": "DC=corp,DC=spinovation,DC=local", "template_count": 14}'::jsonb, 'active', 62, 58, 4, CURRENT_TIMESTAMP - INTERVAL '2 hours'),
  ('conn-amb-aws', 'AMBEROON', 'Amberoon AWS KMS (us-west-2)', 'aws_kms', 'https://kms.us-west-2.amazonaws.com', 'iam_role', '{"region": "us-west-2", "role_arn": "arn:aws:iam::987654321098:role/AmberoonQuarkShieldKmsRole"}'::jsonb, 'active', 16, 12, 4, CURRENT_TIMESTAMP - INTERVAL '40 minutes')
ON CONFLICT (id) DO NOTHING;

-- Seed sample PKI assets
INSERT INTO pki_synced_assets (id, connector_id, tenant_name, asset_name, asset_type, algorithm, key_size, is_vulnerable, risk_level, quantum_threat, status, rotation_enabled, expires_at)
VALUES
  ('pki-ast-01', 'conn-aws-kms', 'SPINOVATIONCORP', 'spin-payment-master-key', 'asymmetric_key', 'RSA-2048', 2048, true, 'critical', 'Shor''s Algorithm factorization risk. HNDL exposure.', 'Active', false, CURRENT_TIMESTAMP + INTERVAL '300 days'),
  ('pki-ast-02', 'conn-aws-kms', 'SPINOVATIONCORP', 'spin-pqc-kem-hybrid', 'asymmetric_key', 'ML-KEM-768 + X25519', 768, false, 'secure', 'NIST FIPS 203 Post-Quantum Resilient.', 'Active', true, CURRENT_TIMESTAMP + INTERVAL '365 days'),
  ('pki-ast-03', 'conn-azure-kv', 'SPINOVATIONCORP', 'ssl-wildcard-spinovation-com', 'certificate', 'ECDSA-P256', 256, true, 'critical', 'Discrete log vulnerability via Shor''s algorithm on CRQC.', 'Active', true, CURRENT_TIMESTAMP + INTERVAL '120 days'),
  ('pki-ast-04', 'conn-hashi-vault', 'SPINOVATIONCORP', 'transit/keys/customer-pii-cipher', 'symmetric_key', 'AES-256-GCM', 256, false, 'secure', 'Grover resistant (128-bit quantum security strength).', 'Active', true, CURRENT_TIMESTAMP + INTERVAL '700 days'),
  ('pki-ast-05', 'conn-ad-cs', 'SPINOVATIONCORP', 'Spinovation Enterprise Root CA', 'ca_root', 'RSA-4096', 4096, true, 'critical', 'Root of trust vulnerable to quantum factorization. Subordinate CAs compromised.', 'Active', false, CURRENT_TIMESTAMP + INTERVAL '1800 days'),
  ('pki-ast-06', 'conn-ad-cs', 'SPINOVATIONCORP', 'Smartcard Logon Certificate Template', 'template', 'RSA-2048', 2048, true, 'critical', 'Workstation logon signatures vulnerable to identity forgery by CRQC.', 'Active', false, CURRENT_TIMESTAMP + INTERVAL '365 days')
ON CONFLICT (id) DO NOTHING;

-- Seed sample PQC Proxy
INSERT INTO pqc_proxies (id, tenant_name, name, listen_port, upstream_url, tls_curve, status, handshake_count, active_connections)
VALUES
  ('prx-api-ingress', 'SPINOVATIONCORP', 'API Ingress Quantum Hybrid Proxy', 5443, 'http://127.0.0.1:5050', 'X25519MLKEM768', 'running', 1420, 8),
  ('prx-legacy-crm', 'SPINOVATIONCORP', 'Legacy Core Banking Gateway Proxy', 8443, 'http://127.0.0.1:8080', 'X25519MLKEM768', 'running', 389, 2),
  ('prx-amb-gateway', 'AMBEROON', 'Amberoon Hybrid PQC Gateway', 9443, 'http://127.0.0.1:3000', 'X25519MLKEM768', 'running', 215, 3)
ON CONFLICT (id) DO NOTHING;

-- =========================================================================
-- SOFTWARE BILL OF MATERIALS (SBOM) & VULNERABILITY CATALOG SCHEMA
-- =========================================================================

CREATE TABLE IF NOT EXISTS sbom_components (
  id VARCHAR(100) PRIMARY KEY,
  tenant_name VARCHAR(255) NOT NULL,
  source VARCHAR(100) DEFAULT 'git_repo', -- 'git_repo', 'endpoint', 'ci_cd', 'container'
  source_ref VARCHAR(500),                -- repo URL or hostname
  file_path VARCHAR(500),                 -- package.json, requirements.txt, go.mod, etc.
  name VARCHAR(255) NOT NULL,
  version VARCHAR(100) NOT NULL,
  ecosystem VARCHAR(50) NOT NULL,         -- 'npm', 'pypi', 'golang', 'maven', 'os_pkg'
  purl VARCHAR(500),
  license VARCHAR(100),
  has_vulnerabilities BOOLEAN DEFAULT false,
  vuln_count INTEGER DEFAULT 0,
  max_severity VARCHAR(50) DEFAULT 'none', -- 'critical', 'high', 'medium', 'low', 'none'
  vulnerabilities JSONB DEFAULT '[]'::jsonb, -- array of { cveId, title, cvssScore, severity, fixedVersion, remediationCmd, description }
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sbom_tenant_name ON sbom_components(tenant_name);
CREATE INDEX IF NOT EXISTS idx_sbom_source ON sbom_components(source);
CREATE INDEX IF NOT EXISTS idx_sbom_max_severity ON sbom_components(max_severity);
CREATE INDEX IF NOT EXISTS idx_sbom_ecosystem ON sbom_components(ecosystem);

-- Seed initial SBOM components for QuarkShield Platform Stack (Super Admin Only)
INSERT INTO sbom_components (id, tenant_name, source, source_ref, file_path, name, version, ecosystem, purl, license, has_vulnerabilities, vuln_count, max_severity, vulnerabilities)
VALUES
  -- QuarkShield.ai Platform Stack SBOM Components
  ('qs-plat-01', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package.json', 'express', '4.19.2', 'npm', 'pkg:npm/express@4.19.2', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install express@latest", "description": "High performance Express HTTP web application framework."}]'::jsonb),
  ('qs-plat-02', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package.json', 'pg', '8.11.5', 'npm', 'pkg:npm/pg@8.11.5', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install pg@latest", "description": "Non-blocking PostgreSQL client pool for Node.js."}]'::jsonb),
  ('qs-plat-03', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package.json', 'cors', '2.8.5', 'npm', 'pkg:npm/cors@2.8.5', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install cors@latest", "description": "Cross-origin resource sharing middleware with preflight handling."}]'::jsonb),
  ('qs-plat-04', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package.json', 'dotenv', '16.4.5', 'npm', 'pkg:npm/dotenv@16.4.5', 'BSD-2-Clause', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install dotenv@latest", "description": "Zero-dependency module that loads environment variables from .env."}]'::jsonb),
  ('qs-plat-05', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package.json', 'typescript', '5.4.5', 'npm', 'pkg:npm/typescript@5.4.5', 'Apache-2.0', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install -D typescript@latest", "description": "Static type checker and compiler for scalable JavaScript applications."}]'::jsonb),
  ('qs-plat-06', 'quarkshield.ai', 'platform_backend', 'https://github.com/spinovation/quarkshield-ai/server', 'server/package-lock.json', 'qs', '6.15.4', 'npm', 'pkg:npm/qs@6.15.4', 'BSD-3-Clause', false, 0, 'none', '[{"cveId": "GHSA-x5fp-wj9c-mxmx", "title": "Array-limit bypass via bracket-key comma parsing [REMEDIATED]", "cvssScore": 7.5, "severity": "high", "fixedVersion": "^6.15.4", "remediationCmd": "npm audit fix", "description": "Previously affected v6.15.3. Successfully remediated and patched to v6.15.4 via npm audit fix. Current production version verified clean."}]'::jsonb),
  ('qs-plat-07', 'quarkshield.ai', 'platform_ui', 'https://github.com/spinovation/quarkshield-ai/ui', 'ui/package.json', 'react', '19.2.6', 'npm', 'pkg:npm/react@19.2.6', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install react@latest react-dom@latest", "description": "React core UI library for high-speed cyber threat visualization."}]'::jsonb),
  ('qs-plat-08', 'quarkshield.ai', 'platform_ui', 'https://github.com/spinovation/quarkshield-ai/ui', 'ui/package.json', 'react-dom', '19.2.6', 'npm', 'pkg:npm/react-dom@19.2.6', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install react-dom@latest", "description": "React package for working with the DOM."}]'::jsonb),
  ('qs-plat-09', 'quarkshield.ai', 'platform_ui', 'https://github.com/spinovation/quarkshield-ai/ui', 'ui/package.json', 'lucide-react', '1.17.0', 'npm', 'pkg:npm/lucide-react@1.17.0', 'ISC', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install lucide-react@latest", "description": "High performance clean SVG iconography suite."}]'::jsonb),
  ('qs-plat-10', 'quarkshield.ai', 'platform_ui', 'https://github.com/spinovation/quarkshield-ai/ui', 'ui/package.json', 'vite', '8.0.12', 'npm', 'pkg:npm/vite@8.0.12', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "Latest Stable", "remediationCmd": "npm install -D vite@latest", "description": "Next-generation frontend tooling and production builder."}]'::jsonb),
  ('qs-plat-11', 'quarkshield.ai', 'platform_agent', 'https://github.com/spinovation/quarkshield-ai/agent', 'agent/auditor.go', 'pqc-scanner-engine', '2.0.0', 'golang', 'pkg:golang/quarkshield.ai/scanner-engine@2.0.0', 'Proprietary', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Zero External Dependencies (Pure Go Standard Library)", "cvssScore": 0.0, "severity": "low", "fixedVersion": "v2.0.0 Stable", "remediationCmd": "cd agent && go build -ldflags=\"-s -w\" -o binaries/pqc-scanner auditor.go", "description": "Zero external dependencies. Compiled pure Go binary utilizing crypto/x509 and standard libraries for memory-safe execution."}]'::jsonb),
  ('qs-plat-12', 'quarkshield.ai', 'container_base', 'docker.io/library/node:22-alpine', 'Dockerfile', 'node', '22-alpine', 'os_pkg', 'pkg:docker/node@22-alpine', 'MIT', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "node:22-alpine", "remediationCmd": "docker pull node:22-alpine", "description": "Hardened minimal Alpine Linux Node.js 22 LTS container base."}]'::jsonb),
  ('qs-plat-13', 'quarkshield.ai', 'container_base', 'docker.io/library/postgres:15-alpine', 'docker-compose.yml', 'postgres', '15-alpine', 'os_pkg', 'pkg:docker/postgres@15-alpine', 'PostgreSQL', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "postgres:15-alpine", "remediationCmd": "docker pull postgres:15-alpine", "description": "Lightweight, secure PostgreSQL 15 ACID enterprise database container."}]'::jsonb),
  ('qs-plat-14', 'quarkshield.ai', 'os_runtime', 'Alpine Linux 3.22 (x86_64)', '/usr/bin/openssl', 'openssl', '3.5.8-r0', 'os_pkg', 'pkg:alpine/openssl@3.5.8-r0', 'Apache-2.0', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities (Patched OpenSSL 3.5)", "cvssScore": 0.0, "severity": "low", "fixedVersion": "3.5.8-r0+", "remediationCmd": "apk upgrade --no-cache openssl", "description": "Production SSL/TLS & post-quantum hybrid cryptographic protocol engine."}]'::jsonb),
  ('qs-plat-15', 'quarkshield.ai', 'os_runtime', 'Alpine Linux 3.22 (x86_64)', '/usr/bin/curl', 'curl', '8.22.0-r0', 'os_pkg', 'pkg:alpine/curl@8.22.0-r0', 'curl', false, 0, 'none', '[{"cveId": "CLEAN", "title": "Verified 0 Known Vulnerabilities", "cvssScore": 0.0, "severity": "low", "fixedVersion": "8.22.0-r0+", "remediationCmd": "apk upgrade --no-cache curl", "description": "Multiprotocol file and network transfer command-line tool."}]'::jsonb)
ON CONFLICT (id) DO NOTHING;


-- =========================================================================
-- FINAL CONSOLIDATED MIGRATIONS (run after all tables exist)
-- These re-apply ADD COLUMN IF NOT EXISTS for columns whose original ALTER
-- statements appear earlier in this file than the CREATE TABLE they target.
-- On a fresh database those early ALTERs are skipped (table not yet created);
-- repeating them here guarantees the columns exist. All are idempotent, so
-- existing databases are unaffected. Also adds columns used by the code that
-- were never defined anywhere (fleet_tokens/fleet_machines tenant_name,
-- license_key).
-- =========================================================================

-- git_scans (ALTER originally precedes its CREATE)
ALTER TABLE git_scans ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) DEFAULT 'SPINOVATIONCORP';

-- admin_licenses (ALTERs originally precede its CREATE)
ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS contact_name VARCHAR(255);
ALTER TABLE admin_licenses ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255);

-- tenant_users (auth columns; ALTERs originally precede its CREATE)
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS salt VARCHAR(255);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false;

-- fleet_tokens / fleet_machines columns referenced by code but never defined
ALTER TABLE fleet_tokens ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255);
ALTER TABLE fleet_tokens ADD COLUMN IF NOT EXISTS license_key VARCHAR(255);
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255);
ALTER TABLE fleet_machines ADD COLUMN IF NOT EXISTS license_key VARCHAR(255);
