import { Router } from 'express';
import {
  getFleetTokens,
  createFleetToken,
  revokeFleetToken,
  getFleetMachines,
  deleteFleetMachine,
  getFleetCBOM,
  getInstallerScript,
  getPowerShellInstallerScript,
  ingestTelemetry,
  enqueuePullCommand,
  getTenantDailySnapshots
} from '../controllers/fleetController';
import {
  getClients,
  getClientStats,
  updateSubscription,
  deployInlineClient,
  createClient,
  deleteClient,
  getUsers,
  toggleUserRole,
  toggleUserLock,
  toggleUserCMDB,
  toggleUserPlaybook,
  toggleUserWeb3,
  resetUserPassword,
  deleteUser,
  getSeoGeoAnalytics,
  getSystemHealth,
  generateLicense,
  getLicenses,
  revokeLicense,
  verifyLicenseKey,
  sendLicenseEmail,
  sendNextStepsEmail,
  getMailSettings,
  updateMailSettings,
  getTenantUsers,
  createTenantUser,
  updateTenantUser,
  deleteTenantUser,
  resetTenantUser2FA,
  getTenant2FAPolicy,
  updateTenant2FAPolicy,
  onboardPartnerTenant,
  onboardUser,
  probeEndpoint,
  unifiedLogin,
  getTenantPortalData
} from '../controllers/adminController';
import { getCnsaNews } from '../controllers/newsController';
import { submitSupportTicket } from '../controllers/supportController';
import {
  scanRemoteGitRepo,
  getGitScanHistory,
  exportGitCBOM
} from '../controllers/gitScanController';
import { getAIChatResponse } from '../controllers/aiController';
import {
  evaluateCIGate,
  getCIGateHistory,
  getCIGatePolicies,
  getCITemplate
} from '../controllers/ciGateController';
import {
  getPkiConnectors,
  createPkiConnector,
  testPkiConnector,
  syncPkiConnector,
  deletePkiConnector,
  getPkiSyncedAssets
} from '../controllers/pkiConnectorController';
import {
  getProxies,
  createProxy,
  toggleProxyState,
  deleteProxy,
  testProxyHandshake,
  getProxyTemplate
} from '../controllers/pqcProxyController';
import {
  getSbomComponents,
  getSbomStats,
  exportSbom,
  getFixScript,
  getSuperAdminGuide
} from '../controllers/sbomController';

const router = Router();

// Fleet Tokens
router.get('/fleet/tokens', getFleetTokens);
router.post('/fleet/tokens', createFleetToken);
router.delete('/fleet/tokens/:id', revokeFleetToken);

// Fleet Endpoints
router.get('/fleet/machines', getFleetMachines);
router.delete('/fleet/machines/:id', deleteFleetMachine);
router.post('/fleet/machines/:machineId/pull', enqueuePullCommand);
router.get('/tenant/:tenant/daily-snapshots', getTenantDailySnapshots);

// CycloneDX 1.6 CBOM
router.get('/fleet/cbom', getFleetCBOM);

// Agent Deployment Script & Ingestion
router.get('/scan/agent/install.sh', getInstallerScript);
router.get('/scan/agent/install.ps1', getPowerShellInstallerScript);
router.post('/scan/agent/ingest', ingestTelemetry);

// ==========================================
// ADMIN PANEL ROUTES (QUARKSHIELD REPLICA)
// ==========================================

// Client Tenant Registry
router.get('/admin/clients', getClients);
router.get('/admin/clients/:name/stats', getClientStats);
router.post('/admin/clients/deploy-inline', deployInlineClient);
router.post('/admin/clients/:name/subscription', updateSubscription);
router.post('/admin/clients', createClient);
router.delete('/admin/clients/:id', deleteClient);
router.delete('/admin/clients/:name', deleteClient);

// User & Access Management
router.get('/admin/users', getUsers);
router.post('/admin/users/:id/role', toggleUserRole);
router.post('/admin/users/:id/lock', toggleUserLock);
router.post('/admin/users/:id/cmdb', toggleUserCMDB);
router.post('/admin/users/:id/playbook', toggleUserPlaybook);
router.post('/admin/users/:id/web3', toggleUserWeb3);
router.post('/admin/users/:id/reset-password', resetUserPassword);
router.delete('/admin/users/:id', deleteUser);

// Analytics & SEO / Crawler Stats
router.get('/admin/seo-geo-analytics', getSeoGeoAnalytics);

// Database & Host Infrastructure Health
router.get('/admin/system-health', getSystemHealth);

// Corporate & Partner License Management
router.post('/admin/licenses/generate', generateLicense);
router.get('/admin/licenses', getLicenses);
router.delete('/admin/licenses/:id', revokeLicense);
router.post('/admin/licenses/send-email', sendLicenseEmail);
router.post('/admin/clients/send-next-steps-email', sendNextStepsEmail);
router.post('/scan/license/verify', verifyLicenseKey);
router.get('/admin/settings/mail', getMailSettings);
router.post('/admin/settings/mail', updateMailSettings);

// Corporate & Partner Tenant Onboarding
router.post('/admin/onboard-partner', onboardPartnerTenant);
router.post('/admin/onboard-user', onboardUser);

// In-Tenant User Management & 2FA Policy (RBAC)
router.get('/tenants/:tenant/users', getTenantUsers);
router.post('/tenants/:tenant/users', createTenantUser);
router.patch('/tenants/:tenant/users/:id', updateTenantUser);
router.delete('/tenants/:tenant/users/:id', deleteTenantUser);
router.post('/tenants/:tenant/users/:id/reset-2fa', resetTenantUser2FA);
router.get('/tenants/:tenant/2fa-policy', getTenant2FAPolicy);
router.put('/tenants/:tenant/2fa-policy', updateTenant2FAPolicy);
router.get('/tenant/:tenant/portal-data', getTenantPortalData);

// Active Outbound TLS Prober
router.post('/probe', probeEndpoint);

// Remote Git Repository Scanner (GitHub & Bitbucket)
router.post('/scan/remote-git', scanRemoteGitRepo);
router.get('/scan/remote-git/history', getGitScanHistory);
router.post('/scan/remote-git/export-cbom', exportGitCBOM);

// CNSA 2.0 & Post-Quantum Intelligence News Feed
router.get('/news/cnsa', getCnsaNews);

// Unified Authentication & Auto-Recognition (Tenant, Partner, Super Admin)
router.post('/auth/login', unifiedLogin);

// Help & Feedback / Support In-App Contact Submission
router.post('/support/contact', submitSupportTicket);

// PQC Copilot AI Assistant
router.post('/ai/chat', getAIChatResponse);

// ==========================================
// 1. CI/CD PIPELINE CBOM SECURITY GATES
// ==========================================
router.post('/git/ci-gate/evaluate', evaluateCIGate);
router.get('/git/ci-gate/history', getCIGateHistory);
router.get('/git/ci-gate/policies', getCIGatePolicies);
router.get('/git/ci-gate/templates/:provider', getCITemplate);
router.get('/git/ci-gate/template', (req, res) => {
  const provider = (req.query.provider as string) || 'github';
  return getCITemplate({ ...req, params: { provider } } as any, res);
});
router.get('/git/ci-gate/runner.sh', (req, res) => getCITemplate({ ...req, params: { provider: 'runner' } } as any, res));

// ==========================================
// 2. ENTERPRISE PKI & CLOUD VAULT CONNECTORS
// ==========================================
router.get('/pki/connectors', getPkiConnectors);
router.post('/pki/connectors', createPkiConnector);
router.post('/pki/connectors/:id/test', testPkiConnector);
router.post('/pki/connectors/:id/sync', syncPkiConnector);
router.delete('/pki/connectors/:id', deletePkiConnector);
router.get('/pki/assets', getPkiSyncedAssets);

// ==========================================
// 3. TRANSPARENT HYBRID QUANTUM TLS PROXY
// ==========================================
router.get('/proxy/instances', getProxies);
router.post('/proxy/instances', createProxy);
router.patch('/proxy/instances/:id/state', toggleProxyState);
router.delete('/proxy/instances/:id', deleteProxy);
router.post('/proxy/instances/:id/test', testProxyHandshake);
router.get('/proxy/templates/:format', getProxyTemplate);
router.get('/proxy/template', (req, res) => {
  const format = (req.query.format as string) || 'nginx';
  return getProxyTemplate({ ...req, params: { format } } as any, res);
});

// =========================================================================
// 4. SOFTWARE BILL OF MATERIALS (SBOM) & VULNERABILITY FIX ENGINE
// =========================================================================
router.get('/sbom/components', getSbomComponents);
router.get('/sbom/stats', getSbomStats);
router.get('/sbom/export', exportSbom);
router.get('/sbom/fix-script', getFixScript);
router.get('/sbom/superadmin-guide', getSuperAdminGuide);

export default router;


