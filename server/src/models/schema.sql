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

ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS salt VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT false;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(255);

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
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tenant_name, email)
);

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
ON CONFLICT (email) DO UPDATE SET 
  role = EXCLUDED.role,
  cmdb_enabled = EXCLUDED.cmdb_enabled,
  playbook_enabled = EXCLUDED.playbook_enabled,
  web3_enabled = EXCLUDED.web3_enabled,
  row_locked = EXCLUDED.row_locked,
  last_login = EXCLUDED.last_login;

-- Seed initial client organizations / tenants for quarkshield.ai
INSERT INTO admin_clients (id, name, display_name, app_port, db_port, status, subscription_tier, mca_limit, two_factor_policy, user_count, asset_count, account_type, customer_id, admin_email, contact_name)
VALUES 
  ('client-demo', 'democlient', 'Demo Client Workspace', 5001, 5433, 'active', 'growth', 250, 'optional', 1, 6, 'corporate', 'CORP-5120', 'democlient@example.com', 'Demo Administrator'),
  ('client-090e8814', 'spinovationcorp', 'Spinovation Corp', 5002, 5434, 'active', 'growth', 100, 'optional', 1, 10, 'corporate', 'CORP-9812', 'sridhargs@spinovation.com', 'GS Sridhar'),
  ('client-vanguard-corp', 'vanguard-logistics', 'Vanguard Global Logistics', 5003, 5435, 'active', 'growth', 500, 'optional', 1, 8, 'corporate', 'CORP-4821', 's.jenkins@vanguardlogistics.com', 'Sarah Jenkins'),
  ('client-apex-msp', 'apex-cyber', 'Apex Cyber Defense MSP', 5050, 5436, 'active', 'growth', 300, 'optional', 1, 12, 'partner', 'PART-9148', 'm.vance@apexcyberdefense.io', 'Marcus Vance'),
  ('client-cyber-shield', 'cybershield-partners', 'CyberShield Managed Security', 5051, 5437, 'active', 'growth', 50, 'optional', 1, 4, 'partner', 'PART-8830', 'd.chen@cybershieldsec.com', 'David Chen')
ON CONFLICT (name) DO UPDATE SET 
  display_name = EXCLUDED.display_name,
  app_port = EXCLUDED.app_port,
  db_port = EXCLUDED.db_port,
  status = EXCLUDED.status,
  subscription_tier = EXCLUDED.subscription_tier,
  mca_limit = EXCLUDED.mca_limit,
  user_count = EXCLUDED.user_count,
  asset_count = EXCLUDED.asset_count,
  account_type = EXCLUDED.account_type,
  customer_id = EXCLUDED.customer_id,
  admin_email = EXCLUDED.admin_email,
  contact_name = EXCLUDED.contact_name;

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

-- 1. Deduplicate DESKTOP-QFOTIIO (keep the row with highest asset_count/most recent scan)
DELETE FROM assets 
WHERE machine_id IN (
  SELECT id FROM fleet_machines 
  WHERE LOWER(hostname) LIKE '%desktop-qfotiio%' 
    AND asset_count < 100
);

DELETE FROM fleet_machines 
WHERE LOWER(hostname) LIKE '%desktop-qfotiio%' 
  AND asset_count < 100;

-- 2. Deduplicate Mac workstation (merge Ganapatis-MBP into Ganapatis-MacBook-Pro)
DELETE FROM assets 
WHERE machine_id IN (
  SELECT id FROM fleet_machines 
  WHERE LOWER(hostname) = 'ganapatis-mbp'
);

DELETE FROM fleet_machines 
WHERE LOWER(hostname) = 'ganapatis-mbp';

-- 3. Set friendly computer_name and hardware_uuid for remaining Mac workstation
UPDATE fleet_machines 
SET 
  computer_name = 'Ganapati’s MacBook Pro',
  hardware_uuid = COALESCE(hardware_uuid, 'CC509944-0DEA-5041-984A-C9319F82233F')
WHERE LOWER(hostname) LIKE '%ganapati%' OR os = 'darwin';

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


