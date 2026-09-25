import { Router } from 'express';
import { requireAuth, requireSuperAdmin, requireTenantAccess } from '../middleware/auth';
import { exportExecutiveReport } from '../controllers/reportController';
import { twoFactorStatus, twoFactorSetup, twoFactorVerify, twoFactorDisable } from '../controllers/twoFactorController';
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
  getTenantDailySnapshots,
  getFleetDrift,
  agentFetchCommands
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
  getTenantPortalData,
  getOperators,
  inviteOperator,
  resetOperatorPassword,
  resetTenantUserPassword,
  forgotPassword,
  resetPassword,
  changePassword,
  logout,
  getMe
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
  getPkiSyncedAssets,
  reportAdcs
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

// ==========================================
// AUTH (public) + session
// ==========================================
router.post('/auth/login', unifiedLogin);
router.post('/auth/forgot-password', forgotPassword);
router.post('/auth/reset-password', resetPassword);
router.post('/auth/change-password', changePassword);
router.post('/auth/logout', logout);
router.get('/auth/me', getMe);

// TOTP 2FA management (authenticated)
router.get('/reports/executive', requireAuth, requireTenantAccess, exportExecutiveReport);
router.get('/2fa/status', requireAuth, twoFactorStatus);
router.post('/2fa/setup', requireAuth, twoFactorSetup);
router.post('/2fa/verify', requireAuth, twoFactorVerify);
router.post('/2fa/disable', requireAuth, twoFactorDisable);

// ==========================================
// PUBLIC endpoints (no session required)
// ==========================================
// News feed (marketing), install scripts + ingest (agent authenticates with an
// enrollment token / license key inside ingestTelemetry), desktop license
// verify, landing-page TLS probe, support form, config templates.
router.get('/news/cnsa', getCnsaNews);
router.get('/scan/agent/install.sh', getInstallerScript);
router.get('/scan/agent/install.ps1', getPowerShellInstallerScript);
router.post('/scan/agent/ingest', ingestTelemetry);
router.post('/scan/agent/commands', agentFetchCommands);
router.post('/scan/adcs/report', reportAdcs);
router.post('/scan/license/verify', verifyLicenseKey);
router.post('/probe', probeEndpoint);
router.post('/support/contact', submitSupportTicket);

// ==========================================
// FLEET (authenticated, tenant-scoped)
// ==========================================
router.get('/fleet/tokens', requireAuth, requireTenantAccess, getFleetTokens);
router.post('/fleet/tokens', requireAuth, requireTenantAccess, createFleetToken);
router.delete('/fleet/tokens/:id', requireAuth, revokeFleetToken);
router.get('/fleet/machines', requireAuth, requireTenantAccess, getFleetMachines);
router.delete('/fleet/machines/:id', requireAuth, deleteFleetMachine);
router.post('/fleet/machines/:machineId/pull', requireAuth, enqueuePullCommand);
router.get('/tenant/:tenant/daily-snapshots', requireAuth, requireTenantAccess, getTenantDailySnapshots);
router.get('/fleet/drift', requireAuth, requireTenantAccess, getFleetDrift);
router.get('/fleet/cbom', requireAuth, requireTenantAccess, getFleetCBOM);

// ==========================================
// ADMIN PANEL ROUTES (super admin only)
// ==========================================
router.get('/admin/clients', requireSuperAdmin, getClients);
router.get('/admin/clients/:name/stats', requireSuperAdmin, getClientStats);
router.post('/admin/clients/deploy-inline', requireSuperAdmin, deployInlineClient);
router.post('/admin/clients/:name/subscription', requireSuperAdmin, updateSubscription);
router.post('/admin/clients', requireSuperAdmin, createClient);
router.delete('/admin/clients/:id', requireSuperAdmin, deleteClient);
router.delete('/admin/clients/:name', requireSuperAdmin, deleteClient);

router.get('/admin/users', requireSuperAdmin, getUsers);
router.get('/admin/operators', requireSuperAdmin, getOperators);
router.post('/admin/operators/invite', requireSuperAdmin, inviteOperator);
router.post('/admin/operators/:id/reset-password', requireSuperAdmin, resetOperatorPassword);
router.post('/admin/users/:id/role', requireSuperAdmin, toggleUserRole);
router.post('/admin/users/:id/lock', requireSuperAdmin, toggleUserLock);
router.post('/admin/users/:id/cmdb', requireSuperAdmin, toggleUserCMDB);
router.post('/admin/users/:id/playbook', requireSuperAdmin, toggleUserPlaybook);
router.post('/admin/users/:id/web3', requireSuperAdmin, toggleUserWeb3);
router.post('/admin/users/:id/reset-password', requireSuperAdmin, resetUserPassword);
router.delete('/admin/users/:id', requireSuperAdmin, deleteUser);

router.get('/admin/seo-geo-analytics', requireSuperAdmin, getSeoGeoAnalytics);
router.get('/admin/system-health', requireSuperAdmin, getSystemHealth);

router.post('/admin/licenses/generate', requireSuperAdmin, generateLicense);
router.get('/admin/licenses', requireSuperAdmin, getLicenses);
router.delete('/admin/licenses/:id', requireSuperAdmin, revokeLicense);
router.post('/admin/licenses/send-email', requireSuperAdmin, sendLicenseEmail);
router.post('/admin/clients/send-next-steps-email', requireSuperAdmin, sendNextStepsEmail);
router.get('/admin/settings/mail', requireSuperAdmin, getMailSettings);
router.post('/admin/settings/mail', requireSuperAdmin, updateMailSettings);

router.post('/admin/onboard-partner', requireSuperAdmin, onboardPartnerTenant);
router.post('/admin/onboard-user', requireSuperAdmin, onboardUser);

// ==========================================
// IN-TENANT USER MGMT & 2FA POLICY (authenticated, tenant-scoped)
// ==========================================
router.get('/tenants/:tenant/users', requireAuth, requireTenantAccess, getTenantUsers);
router.post('/tenants/:tenant/users', requireAuth, requireTenantAccess, createTenantUser);
router.patch('/tenants/:tenant/users/:id', requireAuth, requireTenantAccess, updateTenantUser);
router.delete('/tenants/:tenant/users/:id', requireAuth, requireTenantAccess, deleteTenantUser);
router.post('/tenants/:tenant/users/:id/reset-2fa', requireAuth, requireTenantAccess, resetTenantUser2FA);
router.post('/tenants/:tenant/users/:id/reset-password', requireAuth, requireTenantAccess, resetTenantUserPassword);
router.get('/tenants/:tenant/2fa-policy', requireAuth, requireTenantAccess, getTenant2FAPolicy);
router.put('/tenants/:tenant/2fa-policy', requireAuth, requireTenantAccess, updateTenant2FAPolicy);
router.get('/tenant/:tenant/portal-data', requireAuth, requireTenantAccess, getTenantPortalData);

// ==========================================
// GIT SCANNER (authenticated, tenant-scoped)
// ==========================================
router.post('/scan/remote-git', requireAuth, requireTenantAccess, scanRemoteGitRepo);
router.get('/scan/remote-git/history', requireAuth, requireTenantAccess, getGitScanHistory);
router.post('/scan/remote-git/export-cbom', requireAuth, requireTenantAccess, exportGitCBOM);

// ==========================================
// PQC Copilot AI Assistant (authenticated, tenant-scoped)
// ==========================================
router.post('/ai/chat', requireAuth, requireTenantAccess, getAIChatResponse);

// ==========================================
// CI/CD PIPELINE CBOM SECURITY GATES
// ==========================================
// Templates + runner script are public config text. evaluate/history/policies
// are authenticated + tenant-scoped.
// Public: CI runners authenticate with a fleet/CI token (resolved inside the
// handler), not a browser session.
router.post('/git/ci-gate/evaluate', evaluateCIGate);
router.get('/git/ci-gate/history', requireAuth, requireTenantAccess, getCIGateHistory);
router.get('/git/ci-gate/policies', requireAuth, requireTenantAccess, getCIGatePolicies);
router.get('/git/ci-gate/templates/:provider', getCITemplate);
router.get('/git/ci-gate/template', (req, res) => {
  const provider = (req.query.provider as string) || 'github';
  return getCITemplate({ ...req, params: { provider } } as any, res);
});
router.get('/git/ci-gate/runner.sh', (req, res) => getCITemplate({ ...req, params: { provider: 'runner' } } as any, res));

// ==========================================
// ENTERPRISE PKI & CLOUD VAULT CONNECTORS (authenticated, tenant-scoped)
// ==========================================
router.get('/pki/connectors', requireAuth, requireTenantAccess, getPkiConnectors);
router.post('/pki/connectors', requireAuth, requireTenantAccess, createPkiConnector);
router.post('/pki/connectors/:id/test', requireAuth, testPkiConnector);
router.post('/pki/connectors/:id/sync', requireAuth, syncPkiConnector);
router.delete('/pki/connectors/:id', requireAuth, deletePkiConnector);
router.get('/pki/assets', requireAuth, requireTenantAccess, getPkiSyncedAssets);

// ==========================================
// TRANSPARENT HYBRID QUANTUM TLS PROXY (authenticated, tenant-scoped)
// ==========================================
router.get('/proxy/instances', requireAuth, requireTenantAccess, getProxies);
router.post('/proxy/instances', requireAuth, requireTenantAccess, createProxy);
router.patch('/proxy/instances/:id/state', requireAuth, toggleProxyState);
router.delete('/proxy/instances/:id', requireAuth, deleteProxy);
router.post('/proxy/instances/:id/test', requireAuth, testProxyHandshake);
router.get('/proxy/templates/:format', getProxyTemplate);
router.get('/proxy/template', (req, res) => {
  const format = (req.query.format as string) || 'nginx';
  return getProxyTemplate({ ...req, params: { format } } as any, res);
});

// =========================================================================
// PLATFORM SBOM & VULNERABILITY FIX ENGINE (super admin only)
// =========================================================================
router.get('/sbom/components', requireSuperAdmin, getSbomComponents);
router.get('/sbom/stats', requireSuperAdmin, getSbomStats);
router.get('/sbom/export', requireSuperAdmin, exportSbom);
router.get('/sbom/fix-script', requireSuperAdmin, getFixScript);
router.get('/sbom/superadmin-guide', requireSuperAdmin, getSuperAdminGuide);

export default router;


