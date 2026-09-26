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

    const cleanName = String(name).trim();
    const cleanCompany = String(company).trim();
    const cleanRole = role ? String(role).trim() : 'Unspecified';
    const cleanEnvSize = environmentSize ? String(environmentSize).trim() : 'Unspecified';
    const cleanInterests = Array.isArray(interests) ? interests : (interests ? [String(interests)] : ['General Assessment']);
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
          <tr><td style="padding:6px 0; font-weight:bold;">Contact Name:</td><td>${cleanName}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Work Email:</td><td><a href="mailto:${cleanEmail}">${cleanEmail}</a></td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Company:</td><td>${cleanCompany}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Role:</td><td>${cleanRole}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Environment Size:</td><td>${cleanEnvSize}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Selected Tier:</td><td>${cleanTier || 'None'}</td></tr>
          <tr><td style="padding:6px 0; font-weight:bold;">Interests:</td><td>${cleanInterests.map(i => `<span style="background:#e0f2fe; color:#0369a1; padding:2px 8px; border-radius:4px; font-size:12px; margin-right:4px;">${i}</span>`).join(' ')}</td></tr>
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
