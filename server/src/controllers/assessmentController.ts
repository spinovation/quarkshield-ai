import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import { sendSupportEmail } from './adminController';

const PQCA_INBOX = process.env.PQCA_INBOX || 'PQCA@quarkshield.ai';

const FREE_EMAIL_PROVIDERS = [
  'gmail.com',
  'yahoo.com',
  'ymail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'proton.me',
  'protonmail.com',
  'gmx.com',
  'gmx.net',
  'zoho.com',
  'mail.com',
  'fastmail.com'
];

const isEmail = (s: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

export const isBusinessEmail = (email: string): boolean => {
  if (!isEmail(email)) return false;
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return false;
  return !FREE_EMAIL_PROVIDERS.includes(domain);
};

export const submitAssessment = async (req: Request, res: Response) => {
  try {
    const {
      name,
      email,
      company,
      role,
      environmentSize,
      interests,
      tier,
      utmSource,
      utmMedium,
      utmCampaign,
      honeypot
    } = req.body || {};

    // Anti-spam honeypot
    if (honeypot && String(honeypot).trim().length > 0) {
      console.warn('[ASSESSMENT] Honeypot triggered, dropping submission quietly.');
      return res.status(200).json({ ok: true, message: 'Assessment request received.' });
    }

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Full name is required.' });
    }

    if (!email || !String(email).trim()) {
      return res.status(400).json({ error: 'Work email address is required.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    if (!isBusinessEmail(cleanEmail)) {
      return res.status(400).json({
        error: 'Please provide a valid corporate / enterprise work email address (free email providers are not supported).'
      });
    }

    if (!company || !String(company).trim()) {
      return res.status(400).json({ error: 'Company or organization name is required.' });
    }

    // Free text from an unauthenticated form: cap lengths and strip line breaks so it
    // cannot inject mail headers; it is HTML-escaped where rendered below.
    const plain = (v: unknown, max: number) => String(v ?? '').replace(/[\r\n]+/g, ' ').trim().slice(0, max);
    const cleanName = plain(name, 120);
    const cleanCompany = plain(company, 160);
    const cleanRole = role ? plain(role, 120) : 'Unspecified';
    const cleanEnvSize = environmentSize ? plain(environmentSize, 60) : 'Unspecified';
    const cleanInterests = (Array.isArray(interests) ? interests : (interests ? [String(interests)] : ['General Assessment']))
      .slice(0, 12).map(i => plain(i, 80)).filter(Boolean);
    const h = (v: unknown): string => String(v ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const cleanTier = tier ? String(tier).trim() : null;

    const assessmentId = `pqc_req_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

    // Ensure database table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pqc_assessments (
        id VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        company VARCHAR(255) NOT NULL,
        role VARCHAR(100),
        environment_size VARCHAR(100),
        interests JSONB,
        tier VARCHAR(50),
        utm_source VARCHAR(255),
        utm_medium VARCHAR(255),
        utm_campaign VARCHAR(255),
        status VARCHAR(50) DEFAULT 'new',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert record
    await pool.query(
      `INSERT INTO pqc_assessments
       (id, name, email, company, role, environment_size, interests, tier, utm_source, utm_medium, utm_campaign, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'new')`,
      [
        assessmentId,
        cleanName,
        cleanEmail,
        cleanCompany,
        cleanRole,
        cleanEnvSize,
        JSON.stringify(cleanInterests),
        cleanTier,
        utmSource ? String(utmSource).slice(0, 255) : null,
        utmMedium ? String(utmMedium).slice(0, 255) : null,
        utmCampaign ? String(utmCampaign).slice(0, 255) : null
      ]
    );

    // Notify PQCA inbox (best-effort)
    const emailSubject = `[PQC Assessment Request] ${cleanCompany} — ${cleanName}`;
    const emailText = [
      `New PQC Assessment Request: ${assessmentId}`,
      `-----------------------------------------`,
      `Name:             ${cleanName}`,
      `Work Email:       ${cleanEmail}`,
      `Company:          ${cleanCompany}`,
      `Role:             ${cleanRole}`,
      `Environment Size: ${cleanEnvSize}`,
      `Selected Tier:    ${cleanTier || 'Custom / None'}`,
      `Interests:        ${cleanInterests.join(', ')}`,
      `UTM Source:       ${utmSource || 'direct'}`,
      `Submitted:        ${new Date().toISOString()}`
    ].join('\n');

    const emailHtml = `
      <div style="font-family:sans-serif; max-width:600px; color:#1e293b;">
        <h2 style="color:#0284c7; margin-bottom:1rem;">New Enterprise PQC Assessment Request</h2>
        <table style="width:100%; border-collapse:collapse; font-size:14px;">
          <tr><td style="padding:6px 0; font-weight:bold; width:150px;">Request ID:</td><td><code>${assessmentId}</code></td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Contact Name:</td><td>${h(cleanName)}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Work Email:</td><td><a href="mailto:${h(cleanEmail)}">${h(cleanEmail)}</a></td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Company:</td><td>${h(cleanCompany)}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Role:</td><td>${h(cleanRole)}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Environment Size:</td><td>${h(cleanEnvSize)}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Selected Tier:</td><td>${h(cleanTier || 'None')}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Interests:</td><td>${cleanInterests.map(i => `<span style="background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:4px; font-size:12px; margin-right:4px;">${h(i)}</span>`).join(' ')}</td></tr>
        </table>
        <hr style="margin:1.5rem 0; border:none; border-top:1px solid #e2e8f0;" />
        <p style="font-size:12px; color:#64748b;">Delivered automatically by QuarkShield Assessment Flow to ${PQCA_INBOX}</p>
      </div>
    `;

    sendSupportEmail({
      to: PQCA_INBOX,
      subject: emailSubject,
      text: emailText,
      html: emailHtml
    }).catch(err => console.warn('[ASSESSMENT] PQCA notification email dispatch failed:', err?.message));

    // Also dispatch confirmation receipt directly to the requesting client
    const clientSubject = `QuarkShield Enterprise PQC Assessment Confirmation — ${cleanCompany} [${assessmentId}]`;
    const clientText = [
      `Dear ${cleanName},`,
      ``,
      `Thank you for requesting an Enterprise Post-Quantum Cryptography (PQC) Readiness Assessment for ${cleanCompany}.`,
      ``,
      `We have registered your assessment scoping request under Reference ID: ${assessmentId}.`,
      ``,
      `Assessment Request Summary:`,
      `-----------------------------------------`,
      `Organization:      ${cleanCompany}`,
      `Contact Name:      ${cleanName}`,
      `Environment Size:  ${cleanEnvSize}`,
      `Target Tier:       ${cleanTier || 'Custom / Enterprise'}`,
      `Focus Areas:       ${cleanInterests.join(', ')}`,
      `Submitted:         ${new Date().toUTCString()}`,
      ``,
      `Next Steps:`,
      `A Senior Cryptographic Architect from our PQC Assessment team will analyze your infrastructure parameters and contact you within 1 business day with your scoping questionnaire and migration roadmap preview.`,
      ``,
      `In the meantime, you can explore our technical whitepapers and documentation:`,
      `- Documentation Center: https://quarkshield.ai/docs/AGENTLESS_PQC_ARCHITECTURE.md`,
      `- CNSA 2.0 Compliance: https://quarkshield.ai/#cnsa-news`,
      ``,
      `If you have urgent questions, reply directly to this email or reach our operations desk at PQCA@quarkshield.ai.`,
      ``,
      `Best regards,`,
      `QuarkShield PQC Assessment Team`,
      `FedMitigate LLC`,
      `https://quarkshield.ai`
    ].join('\n');

    const clientHtml = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background:#080b16; color:#eef1fa; padding:24px; margin:0;">
        <div style="max-width:600px; margin:0 auto; background:#0f172a; border:1px solid #1e293b; border-radius:12px; overflow:hidden;">
          <div style="background:linear-gradient(135deg, #0d1322 0%, #171b34 100%); padding:28px; text-align:center; border-bottom:1px solid #26304f;">
            <h1 style="margin:0; font-size:24px; color:#ffffff; letter-spacing:0.5px; font-weight:800;">
              quark<span style="color:#a855f7; font-style:italic;">shield</span>
            </h1>
            <p style="margin:6px 0 0 0; font-size:13px; color:#9aa6c4; text-transform:uppercase; letter-spacing:1px; font-weight:600;">
              Post-Quantum Cryptography Readiness
            </p>
          </div>
          <div style="padding:28px 32px;">
            <div style="display:inline-block; background:rgba(168,85,247,0.15); border:1px solid rgba(168,85,247,0.35); border-radius:6px; padding:4px 12px; font-size:12px; color:#c084fc; font-weight:600; margin-bottom:16px;">
              Assessment Request Confirmed
            </div>
            <h2 style="margin:0 0 16px 0; font-size:20px; color:#ffffff;">
              Hello ${h(cleanName)},
            </h2>
            <p style="color:#cbd5e1; font-size:14px; line-height:1.6; margin-bottom:20px;">
              Thank you for requesting an Enterprise PQC Readiness Assessment for <strong style="color:#ffffff;">${h(cleanCompany)}</strong>. We have logged your scoping parameters under reference token <code style="background:#1e293b; color:#22d3ee; padding:2px 6px; border-radius:4px; font-size:13px;">${assessmentId}</code>.
            </p>

            <div style="background:#131c31; border:1px solid #26304f; border-radius:8px; padding:18px 20px; margin-bottom:24px;">
              <h3 style="margin:0 0 12px 0; font-size:13px; text-transform:uppercase; letter-spacing:0.5px; color:#9aa6c4;">
                Submission Parameters
              </h3>
              <table style="width:100%; border-collapse:collapse; font-size:13px; color:#cbd5e1;">
                <tr>
                  <td style="padding:5px 0; color:#94a3b8; width:140px;">Organization:</td>
                  <td style="padding:5px 0; font-weight:600; color:#f1f5f9;">${h(cleanCompany)}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#94a3b8;">Environment Size:</td>
                  <td style="padding:5px 0; font-weight:600; color:#f1f5f9;">${h(cleanEnvSize)}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#94a3b8;">Target Tier:</td>
                  <td style="padding:5px 0; font-weight:600; color:#22d3ee;">${h(cleanTier || 'Custom / Enterprise')}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#94a3b8; vertical-align:top;">Focus Areas:</td>
                  <td style="padding:5px 0;">
                    ${cleanInterests.map(i => `<span style="display:inline-block; background:rgba(34,211,238,0.12); color:#22d3ee; border:1px solid rgba(34,211,238,0.3); border-radius:4px; padding:2px 6px; font-size:11px; margin:2px 4px 2px 0;">${i}</span>`).join('')}
                  </td>
                </tr>
              </table>
            </div>

            <h3 style="margin:20px 0 10px 0; font-size:15px; color:#ffffff;">What Happens Next</h3>
            <p style="color:#cbd5e1; font-size:13.5px; line-height:1.6; margin-bottom:20px;">
              A Senior Cryptographic Architect from our PQC Assessment team (<a href="mailto:PQCA@quarkshield.ai" style="color:#a855f7; text-decoration:none;">PQCA@quarkshield.ai</a>) will analyze your infrastructure profile and contact you within <strong>1 business day</strong> with:
            </p>
            <ul style="color:#cbd5e1; font-size:13px; line-height:1.7; padding-left:20px; margin-bottom:24px;">
              <li>Scoping plan for agentless discovery across your PKI, TLS gateways, and endpoints.</li>
              <li>Estimated Cryptographic Bill of Materials (CBOM) generation timeline.</li>
              <li>NIST FIPS 203/204/205 &amp; NSA CNSA 2.0 compliance gap analysis schedule.</li>
            </ul>

            <div style="text-align:center; margin:28px 0 12px 0;">
              <a href="https://quarkshield.ai/docs/AGENTLESS_PQC_ARCHITECTURE.md" style="background:linear-gradient(135deg, #a855f7 0%, #7e22ce 100%); color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:6px; font-weight:600; font-size:13px; display:inline-block;">
                Explore Agentless Architecture Whitepaper →
              </a>
            </div>
          </div>

          <div style="background:#080b16; padding:18px; text-align:center; font-size:11.5px; color:#64748b; border-top:1px solid #1e293b;">
            QuarkShield PQC Operations Desk • FedMitigate LLC • <a href="mailto:PQCA@quarkshield.ai" style="color:#94a3b8; text-decoration:none;">PQCA@quarkshield.ai</a>
          </div>
        </div>
      </body>
      </html>
    `;

    sendSupportEmail({
      to: cleanEmail,
      subject: clientSubject,
      text: clientText,
      html: clientHtml
    }).catch(err => console.warn('[ASSESSMENT] Client confirmation email dispatch failed:', err?.message));

    console.log(`[ASSESSMENT] ${assessmentId} created for ${cleanEmail} (${cleanCompany})`);

    return res.status(200).json({
      ok: true,
      assessmentId,
      message: 'routed to the QuarkShield PQC Assessment team at PQCA@quarkshield.ai'
    });
  } catch (err: any) {
    console.error('[ASSESSMENT] Error creating assessment request:', err);
    return res.status(500).json({ error: 'Failed to record assessment request. Please try again or email PQCA@quarkshield.ai.' });
  }
};
