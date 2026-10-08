import { Router, Request, Response, NextFunction } from 'express';
import { requireAuth, requireSuperAdmin, requirePlatformAdmin, requireTenantAccess, requireTenantAdmin, requireIntegrationsEntitlement, requireRiskAssuranceEntitlement, getTenantEntitlement, localTenantEntitlement, isSuperRole, safeEqual, RISK_ASSURANCE_ADDON } from '../middleware/auth';
import {
  getThreatOverview, getThreatGraph, getRelationshipEvidence, listThreatScenarios, getThreatScenario,
  listRiskAssets, getAssetRiskDetail, updateRemediation, overrideAssetContext, rebuildThreatGraph,
  listRebuildRuns, getThreatGraphCatalog, scheduleRebuild, getThreatIntelStatus, syncThreatIntelNow,
} from '../controllers/threatGraphController';
import { exportExecutiveReport, getReportStakeholders, saveReportStakeholders, sendRoadmapReport } from '../controllers/reportController';
import { twoFactorStatusSafe as twoFactorStatus, twoFactorSetupSafe as twoFactorSetup, twoFactorVerifySafe as twoFactorVerify, twoFactorDisableSafe as twoFactorDisable } from '../controllers/twoFactorController';
import {
  getFleetTokens,
  createFleetToken,
  revokeFleetToken,
  getFleetMachines,
  deleteFleetMachine,
  getFleetCBOM,
  getPublicFleetPosture,
  getInstallerScript,
  getPowerShellInstallerScript,
  ingestTelemetry,
  enqueuePullCommand,
  enqueueBulkPullCommand,
  setMachineGroup,
  listFleetGroups,
  createFleetGroup,
  deleteFleetGroup,
  listPullSchedules,
  createPullSchedule,
  deletePullSchedule,
  togglePullSchedule,
  getTenantDailySnapshots,
  getFleetDrift,
  agentFetchCommands
} from '../controllers/fleetController';
import {
  getClients,
  getClientStats,
  updateSubscription,
  updateClientPlan,
  updateClientAddons,
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
  getDownloadAnalytics,
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
import { submitAssessment } from '../controllers/assessmentController';
import {
  scanRemoteGitRepo,
  getGitScanHistory,
  exportGitCBOM
} from '../controllers/gitScanController';
import {
  getFrameworks, listProjects, createProject, deleteProject,
  listControls, updateControl, reassessControls,
  exportProjectSSP, exportProjectPOAM, exportProjectPOAMExcel,
} from '../controllers/projectController';
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
import {
  createCheckoutSession,
  getRegistrationStatus,
  createCustomCheckoutSession,
  sendCustomCheckoutEmail,
  getCustomCheckoutInvites,
  createCustomerPortalSession,
  handleStripeWebhook,
  getRiskAssuranceOffer,
  createRiskAssuranceCheckout,
} from '../controllers/billingController';

const router = Router();

/**
 * After a successful write that changes graph inputs, schedule a debounced Threat & Risk
 * Graph rebuild for the tenant (only tenants on the Risk Assurance plan are rebuilt).
 */
const rebuildAfter = (trigger: string) => (req: Request, res: Response, next: NextFunction): void => {
  res.on('finish', () => {
    if (res.statusCode >= 400) return;
    scheduleRebuild(res.locals.tenant || (req.query.tenant as string) || req.body?.tenantName || req.user?.tenant, trigger);
  });
  next();
};

// ==========================================
// AUTH (public) + session
// ==========================================
router.post('/auth/login', unifiedLogin);
router.post('/auth/forgot-password', forgotPassword);
router.post('/auth/reset-password', resetPassword);
router.post('/auth/change-password', requireAuth, changePassword);
router.post('/auth/logout', logout);
router.get('/auth/me', getMe);

// TOTP 2FA management (authenticated)
router.get('/reports/executive', requireAuth, requireTenantAccess, exportExecutiveReport);
router.get('/reports/stakeholders', requireAuth, requireTenantAccess, getReportStakeholders);
// Emailing reports / editing the recipient list is an admin action (any role could
// otherwise use the platform as a relay to arbitrary addresses).
router.post('/reports/stakeholders', requireAuth, requireTenantAccess, requireTenantAdmin, saveReportStakeholders);
router.post('/reports/executive/send', requireAuth, requireTenantAccess, requireTenantAdmin, sendRoadmapReport);
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
router.post('/scan/agent/ingest', rebuildAfter('agent_ingest'), ingestTelemetry);
router.post('/scan/agent/commands', agentFetchCommands);
router.post('/scan/adcs/report', reportAdcs);
router.post('/scan/license/verify', verifyLicenseKey);
router.post('/probe', probeEndpoint);
router.post('/assessment', submitAssessment);
router.post('/support', submitSupportTicket);
router.post('/support/contact', submitSupportTicket);

// ==========================================
// FLEET (authenticated, tenant-scoped)
// ==========================================
// Enrollment tokens are bearer credentials: only tenant admins / platform roles may
// list, mint, or revoke them.
router.get('/fleet/tokens', requireAuth, requireTenantAccess, requireTenantAdmin, getFleetTokens);
router.post('/fleet/tokens', requireAuth, requireTenantAccess, requireTenantAdmin, createFleetToken);
router.delete('/fleet/tokens/:id', requireAuth, requireTenantAccess, requireTenantAdmin, revokeFleetToken);
router.get('/fleet/machines', requireAuth, requireTenantAccess, getFleetMachines);
router.delete('/fleet/machines/:id', requireAuth, requireTenantAccess, deleteFleetMachine);
router.post('/fleet/machines/:machineId/pull', requireAuth, requireTenantAccess, enqueuePullCommand);
router.post('/fleet/pull-bulk', requireAuth, requireTenantAccess, enqueueBulkPullCommand);
router.post('/fleet/machines/:machineId/group', requireAuth, requireTenantAccess, setMachineGroup);
router.get('/fleet/groups', requireAuth, requireTenantAccess, listFleetGroups);
router.post('/fleet/groups', requireAuth, requireTenantAccess, createFleetGroup);
router.delete('/fleet/groups/:name', requireAuth, requireTenantAccess, deleteFleetGroup);
router.get('/fleet/pull-schedules', requireAuth, requireTenantAccess, listPullSchedules);
router.post('/fleet/pull-schedules', requireAuth, requireTenantAccess, createPullSchedule);
router.delete('/fleet/pull-schedules/:id', requireAuth, requireTenantAccess, deletePullSchedule);
router.patch('/fleet/pull-schedules/:id', requireAuth, requireTenantAccess, togglePullSchedule);
router.get('/tenant/:tenant/daily-snapshots', requireAuth, requireTenantAccess, getTenantDailySnapshots);
router.get('/fleet/drift', requireAuth, requireTenantAccess, getFleetDrift);
router.get('/fleet/cbom', requireAuth, requireTenantAccess, getFleetCBOM);
router.get('/cbom/fleet', getPublicFleetPosture);

// ==========================================
// ADMIN PANEL ROUTES (super admin only)
// ==========================================
router.get('/admin/clients', requireSuperAdmin, getClients);
router.get('/admin/clients/:name/stats', requireSuperAdmin, getClientStats);
router.post('/admin/clients/deploy-inline', requirePlatformAdmin, deployInlineClient);
router.post('/admin/clients/:name/subscription', requirePlatformAdmin, updateSubscription);
router.post('/admin/clients/:name/plan', requirePlatformAdmin, updateClientPlan);
router.post('/admin/clients/:name/addons', requirePlatformAdmin, updateClientAddons);
router.post('/admin/clients', requirePlatformAdmin, createClient);
router.delete('/admin/clients/:id', requirePlatformAdmin, deleteClient);
router.delete('/admin/clients/:name', requirePlatformAdmin, deleteClient);

router.get('/admin/users', requireSuperAdmin, getUsers);
router.get('/admin/operators', requireSuperAdmin, getOperators);
router.post('/admin/operators/invite', requirePlatformAdmin, inviteOperator);
router.post('/admin/operators/:id/reset-password', requirePlatformAdmin, resetOperatorPassword);
router.post('/admin/users/:id/role', requirePlatformAdmin, toggleUserRole);
router.post('/admin/users/:id/lock', requirePlatformAdmin, toggleUserLock);
router.post('/admin/users/:id/cmdb', requirePlatformAdmin, toggleUserCMDB);
router.post('/admin/users/:id/playbook', requirePlatformAdmin, toggleUserPlaybook);
router.post('/admin/users/:id/web3', requirePlatformAdmin, toggleUserWeb3);
router.post('/admin/users/:id/reset-password', requirePlatformAdmin, resetUserPassword);
router.delete('/admin/users/:id', requirePlatformAdmin, deleteUser);

router.get('/admin/seo-geo-analytics', requireSuperAdmin, getSeoGeoAnalytics);
router.get('/admin/download-analytics', requireSuperAdmin, getDownloadAnalytics);
router.get('/admin/system-health', requireSuperAdmin, getSystemHealth);

router.post('/admin/licenses/generate', requirePlatformAdmin, generateLicense);
router.get('/admin/licenses', requireSuperAdmin, getLicenses);
router.delete('/admin/licenses/:id', requirePlatformAdmin, revokeLicense);
router.post('/admin/licenses/send-email', requirePlatformAdmin, sendLicenseEmail);
router.post('/admin/clients/send-next-steps-email', requirePlatformAdmin, sendNextStepsEmail);
router.get('/admin/settings/mail', requireSuperAdmin, getMailSettings);
router.post('/admin/settings/mail', requirePlatformAdmin, updateMailSettings);

router.post('/admin/onboard-partner', requirePlatformAdmin, onboardPartnerTenant);
router.post('/admin/onboard-user', requirePlatformAdmin, onboardUser);

// ==========================================
// IN-TENANT USER MGMT & 2FA POLICY (authenticated, tenant-scoped)
// ==========================================
router.get('/tenants/:tenant/users', requireAuth, requireTenantAccess, getTenantUsers);
router.post('/tenants/:tenant/users', requireAuth, requireTenantAccess, requireTenantAdmin, createTenantUser);
router.patch('/tenants/:tenant/users/:id', requireAuth, requireTenantAccess, requireTenantAdmin, updateTenantUser);
router.delete('/tenants/:tenant/users/:id', requireAuth, requireTenantAccess, requireTenantAdmin, deleteTenantUser);
router.post('/tenants/:tenant/users/:id/reset-2fa', requireAuth, requireTenantAccess, requireTenantAdmin, resetTenantUser2FA);
router.post('/tenants/:tenant/users/:id/reset-password', requireAuth, requireTenantAccess, requireTenantAdmin, resetTenantUserPassword);
router.get('/tenants/:tenant/2fa-policy', requireAuth, requireTenantAccess, getTenant2FAPolicy);
router.put('/tenants/:tenant/2fa-policy', requireAuth, requireTenantAccess, requireTenantAdmin, updateTenant2FAPolicy);
router.get('/tenant/:tenant/portal-data', requireAuth, requireTenantAccess, getTenantPortalData);

// ==========================================
// GIT SCANNER (authenticated, tenant-scoped)
// ==========================================
router.post('/scan/remote-git', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, rebuildAfter('git_scan'), scanRemoteGitRepo);
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
// Plan entitlements for the current session — the UI uses this to lock/unlock the
// Integrations & Gateways surface (BILL-2). Super roles always see it unlocked.
// On a tenant pod this resolves from the central plane (BILL-3), with a local fallback.
router.get('/entitlements', requireAuth, async (req, res) => {
  try {
    if (isSuperRole(req.user?.role)) {
      res.json({ integrations: true, tier: 'enterprise', seats: 250, addons: [RISK_ASSURANCE_ADDON], riskAssurance: true, riskAssuranceEligible: true, super: true });
      return;
    }
    const ent = await getTenantEntitlement(req.user?.tenant);
    res.json({ ...ent, super: false });
  } catch (e) {
    console.error('entitlements lookup failed:', e);
    res.status(500).json({ error: 'Entitlement lookup failed' });
  }
});

// BILL-3: the central plane is the single source of truth for tenant entitlement.
// Tenant pods call this server-to-server with a shared service token and cache the
// result. Answers from the LOCAL DB (on central that IS the source of truth); never
// re-delegates, so there is no cross-pod recursion.
router.get('/central/entitlement', async (req, res) => {
  const token = process.env.QS_CENTRAL_SERVICE_TOKEN || '';
  if (!token || !safeEqual(String(req.headers['x-qs-service-token'] || ''), token)) {
    res.status(401).json({ error: 'Invalid or missing service token' });
    return;
  }
  const tenant = (req.query.tenant as string) || '';
  res.json(await localTenantEntitlement(tenant));
});

// ==========================================
// THREAT & RISK GRAPH (Risk Assurance plan, authenticated, tenant-scoped)
// ==========================================
const tg = [requireAuth, requireTenantAccess, requireRiskAssuranceEntitlement];
router.get('/threat-graph/catalog', requireAuth, getThreatGraphCatalog);
router.get('/threat-graph/overview', ...tg, getThreatOverview);
router.get('/threat-graph/graph', ...tg, getThreatGraph);
router.get('/threat-graph/relationships/:id', ...tg, getRelationshipEvidence);
router.get('/threat-graph/scenarios', ...tg, listThreatScenarios);
router.get('/threat-graph/scenarios/:id', ...tg, getThreatScenario);
router.get('/threat-graph/assets', ...tg, listRiskAssets);
router.get('/threat-graph/assets/:id', ...tg, getAssetRiskDetail);
router.put('/threat-graph/assets/:id/context', ...tg, overrideAssetContext);
router.patch('/threat-graph/remediations/:id', ...tg, updateRemediation);
router.post('/threat-graph/rebuild', ...tg, rebuildThreatGraph);
router.get('/threat-graph/runs', ...tg, listRebuildRuns);
router.get('/threat-intel/status', requireAuth, getThreatIntelStatus);
router.post('/threat-intel/sync', requireSuperAdmin, syncThreatIntelNow);

// Projects (BILL-4 / BILL-4b) — framework-based authorization boundaries with per-control
// assessment; each yields its own OSCAL SSP/POA&M.
router.get('/compliance/frameworks', requireAuth, getFrameworks);
router.get('/projects', requireAuth, requireTenantAccess, listProjects);
router.post('/projects', requireAuth, requireTenantAccess, createProject);
router.delete('/projects/:id', requireAuth, requireTenantAccess, deleteProject);
router.get('/projects/:id/controls', requireAuth, requireTenantAccess, listControls);
router.patch('/projects/:id/controls/:controlKey', requireAuth, requireTenantAccess, updateControl);
router.post('/projects/:id/reassess', requireAuth, requireTenantAccess, reassessControls);
router.get('/projects/:id/oscal/ssp', requireAuth, requireTenantAccess, exportProjectSSP);
router.get('/projects/:id/oscal/poam', requireAuth, requireTenantAccess, exportProjectPOAM);
router.get('/projects/:id/poam.xlsx', requireAuth, requireTenantAccess, exportProjectPOAMExcel);

router.get('/pki/connectors', requireAuth, requireTenantAccess, getPkiConnectors);
router.post('/pki/connectors', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, createPkiConnector);
router.post('/pki/connectors/:id/test', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, testPkiConnector);
router.post('/pki/connectors/:id/sync', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, rebuildAfter('pki_sync'), syncPkiConnector);
router.delete('/pki/connectors/:id', requireAuth, requireTenantAccess, rebuildAfter('pki_change'), deletePkiConnector);
router.get('/pki/assets', requireAuth, requireTenantAccess, getPkiSyncedAssets);

// ==========================================
// TRANSPARENT HYBRID QUANTUM TLS PROXY (authenticated, tenant-scoped)
// ==========================================
router.get('/proxy/instances', requireAuth, requireTenantAccess, getProxies);
router.post('/proxy/instances', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, rebuildAfter('proxy_change'), createProxy);
router.patch('/proxy/instances/:id/state', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, toggleProxyState);
router.delete('/proxy/instances/:id', requireAuth, requireTenantAccess, rebuildAfter('proxy_change'), deleteProxy);
router.post('/proxy/instances/:id/test', requireAuth, requireTenantAccess, requireIntegrationsEntitlement, testProxyHandshake);
router.get('/proxy/templates/:format', getProxyTemplate);
router.get('/proxy/template', (req, res) => {
  const format = (req.query.format as string) || 'nginx';
  return getProxyTemplate({ ...req, params: { format } } as any, res);
});

// =========================================================================
// SOFTWARE BILL OF MATERIALS (SBOM) & VULNERABILITY FIX ENGINE
// =========================================================================
router.get('/sbom/components', requireAuth, requireTenantAccess, getSbomComponents);
router.get('/sbom/stats', requireAuth, requireTenantAccess, getSbomStats);
router.get('/sbom/export', requireAuth, requireTenantAccess, exportSbom);
router.get('/sbom/fix-script', requireAuth, requireTenantAccess, getFixScript);
router.get('/sbom/superadmin-guide', requireSuperAdmin, getSuperAdminGuide);

// =========================================================================
// STRIPE BILLING & COMMERCIAL PAYMENTS
// =========================================================================
router.post('/billing/checkout', createCheckoutSession);
router.get('/billing/registration-status/:sessionId', getRegistrationStatus);
router.post('/billing/webhook', handleStripeWebhook);
router.post('/billing/custom-checkout', requirePlatformAdmin, createCustomCheckoutSession);
router.post('/billing/custom-checkout/:id/send', requirePlatformAdmin, sendCustomCheckoutEmail);
router.get('/billing/custom-checkout/invites', requireSuperAdmin, getCustomCheckoutInvites);
router.post('/billing/portal-session', requireAuth, requireTenantAccess, createCustomerPortalSession);
router.get('/billing/risk-assurance', requireAuth, getRiskAssuranceOffer);
router.post('/billing/risk-assurance/checkout', requireAuth, createRiskAssuranceCheckout);

export default router;


