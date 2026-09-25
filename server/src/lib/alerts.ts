import pool from '../config/db';
import { sendSupportEmail } from '../controllers/adminController';

/**
 * Compliance alerting (DEF-54).
 *
 * On ingest, when newly-discovered quantum-vulnerable assets appear or a
 * machine's risk score crosses the tenant's threshold, notify via email (the
 * existing Resend/sendmail path) and a per-tenant webhook. Per-tenant config
 * lives in tenant_settings: alert_email, alert_webhook_url, alert_risk_threshold.
 * All delivery is best-effort and never blocks or fails ingest.
 */

export interface AlertContext {
  tenant: string;
  machineId: string;
  hostname: string;
  riskScore: number;
  newVulnerable: Array<{ name: string; algorithm: string }>;
}

interface AlertConfig { email?: string; webhookUrl?: string; riskThreshold: number }

const loadConfig = async (tenant: string): Promise<AlertConfig> => {
  const cfg: AlertConfig = { riskThreshold: 70 };
  try {
    const r = await pool.query(
      "SELECT key, value FROM tenant_settings WHERE LOWER(tenant_name) = LOWER($1) AND key IN ('alert_email','alert_webhook_url','alert_risk_threshold')",
      [tenant]
    );
    for (const row of r.rows) {
      if (row.key === 'alert_email') cfg.email = row.value;
      else if (row.key === 'alert_webhook_url') cfg.webhookUrl = row.value;
      else if (row.key === 'alert_risk_threshold') {
        const n = parseInt(row.value, 10);
        if (Number.isFinite(n)) cfg.riskThreshold = n;
      }
    }
  } catch { /* no settings table row -> defaults */ }
  return cfg;
};

export const maybeSendAlert = async (ctx: AlertContext): Promise<void> => {
  try {
    const cfg = await loadConfig(ctx.tenant);
    if (!cfg.email && !cfg.webhookUrl) return; // alerting not configured for this tenant

    const crossedThreshold = ctx.riskScore >= cfg.riskThreshold;
    const hasNewVuln = ctx.newVulnerable.length > 0;
    if (!crossedThreshold && !hasNewVuln) return;

    const reasons: string[] = [];
    if (hasNewVuln) reasons.push(`${ctx.newVulnerable.length} new quantum-vulnerable asset(s) discovered`);
    if (crossedThreshold) reasons.push(`quantum risk score ${ctx.riskScore} >= threshold ${cfg.riskThreshold}`);
    const summary = reasons.join('; ');
    const assetList = ctx.newVulnerable.slice(0, 20).map(a => `- ${a.name} (${a.algorithm})`).join('\n');

    // Webhook (best-effort). Only http(s), admin-configured.
    if (cfg.webhookUrl && /^https?:\/\//i.test(cfg.webhookUrl)) {
      const payload = {
        type: 'quarkshield.compliance_alert',
        tenant: ctx.tenant,
        machineId: ctx.machineId,
        hostname: ctx.hostname,
        riskScore: ctx.riskScore,
        reasons,
        newVulnerableAssets: ctx.newVulnerable,
        timestamp: new Date().toISOString(),
      };
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 8000);
      fetch(cfg.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      }).catch(e => console.warn('Alert webhook failed:', e?.message)).finally(() => clearTimeout(t));
    }

    // Email (best-effort).
    if (cfg.email) {
      sendSupportEmail({
        to: cfg.email,
        subject: `[QuarkShield Alert] ${ctx.hostname}: ${hasNewVuln ? 'new vulnerable crypto' : 'risk threshold crossed'}`,
        text: `QuarkShield compliance alert for tenant ${ctx.tenant}\nHost: ${ctx.hostname} (${ctx.machineId})\nTrigger: ${summary}\n\nNew vulnerable assets:\n${assetList || '(none)'}\n`,
        html: `<p><b>QuarkShield compliance alert</b> — tenant ${ctx.tenant}</p><p>Host: ${ctx.hostname}<br>Trigger: ${summary}</p><pre style="white-space:pre-wrap">${(assetList || '(none)').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c] || c))}</pre>`,
      }).catch(e => console.warn('Alert email failed:', e?.message));
    }
  } catch (e: any) {
    console.warn('Alerting failed (non-fatal):', e?.message);
  }
};
