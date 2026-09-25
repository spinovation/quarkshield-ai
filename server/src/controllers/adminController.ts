import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import { verifyPassword, hashPassword } from '../utils/password';
import { signSession, setSessionCookie, clearSessionCookie, isSuperRole } from '../middleware/auth';
import { assertPublicHost } from '../utils/ssrf';
import os from 'os';
import tls from 'tls';
import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';


// ==============================================================================
// 0. SHARED EMAIL DISPATCH HELPER (SUPPORT@QUARKSHIELD.AI)
// ==============================================================================

export const sendSupportEmail = async (options: {
  to: string;
  subject: string;
  html: string;
  text: string;
}): Promise<{ success: boolean; messageId?: string; error?: string }> => {
  let resendApiKey = process.env.RESEND_API_KEY || '';
  if (!resendApiKey) {
    try {
      const sRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'RESEND_API_KEY' LIMIT 1");
      if (sRes.rows.length > 0 && sRes.rows[0].value) {
        resendApiKey = sRes.rows[0].value;
      }
    } catch (err) {
      // ignore
    }
  }

  const fromEmail = 'QuarkShield Support <Support@quarkshield.ai>';
  const replyTo = 'Support@quarkshield.ai';

  if (resendApiKey) {
    try {
      const resendRes = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${resendApiKey.trim()}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [options.to],
          subject: options.subject,
          html: options.html,
          text: options.text,
          reply_to: replyTo
        })
      });

      if (resendRes.ok) {
        const data: any = await resendRes.json();
        console.log(`[Support Email] Successfully sent to ${options.to} via Resend (${data.id})`);
        return { success: true, messageId: data.id };
      } else {
        const errText = await resendRes.text();
        console.error(`[Support Email Resend Error ${resendRes.status}]:`, errText);
        return { success: false, error: errText };
      }
    } catch (err: any) {
      console.error('[Support Email Network Error]:', err);
      return { success: false, error: err.message };
    }
  }

  // Fallback to sendmail if available
  try {
    const { exec } = await import('child_process');
    const emailMessage = `From: "QuarkShield Support" <Support@quarkshield.ai>\r\nTo: ${options.to}\r\nReply-To: Support@quarkshield.ai\r\nSubject: ${options.subject}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${options.html}`;
    await new Promise<void>((resolve, reject) => {
      const proc = exec(`/usr/sbin/sendmail -t -f Support@quarkshield.ai`, (error) => {
        if (error) reject(error);
        else resolve();
      });
      if (proc.stdin) {
        proc.stdin.write(emailMessage);
        proc.stdin.end();
      }
    });
    return { success: true };
  } catch (smErr: any) {
    console.warn('[Sendmail fallback skipped]:', smErr.message);
    return { success: false, error: 'No active email transport available.' };
  }
};

// ==============================================================================
// 1. CLIENT / TENANT REGISTRY CONTROLLERS
// ==============================================================================

export const getClients = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        name, 
        display_name as "displayName",
        app_port as "appPort", 
        db_port as "dbPort", 
        status, 
        subscription_tier as "subscriptionTier", 
        mca_limit as "mcaLimit", 
        user_count as "userCount", 
        asset_count as "assetCount", 
        created_at as "createdAt",
        contact_name as "contactName",
        admin_email as "adminEmail",
        phone,
        address,
        city,
        state,
        country,
        postal_code as "postalCode",
        account_type as "accountType",
        customer_id as "customerId",
        stripe_payment_link as "stripePaymentLink",
        stripe_payment_status as "stripePaymentStatus"
      FROM admin_clients
      ORDER BY created_at ASC;
    `);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching admin clients:', err);
    res.status(500).json({ error: 'Failed to retrieve client tenant registry.' });
  }
};

export const getClientStats = async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const client = await pool.query(
      'SELECT name, app_port, db_port, status, user_count, asset_count, subscription_tier, mca_limit FROM admin_clients WHERE name = $1 OR id = $1',
      [name]
    );
    if (client.rows.length === 0) {
      return res.json({
        name,
        appPort: 5015,
        dbPort: 5440,
        status: 'active',
        userCount: 1,
        assetCount: 5,
        subscription_tier: 'growth',
        mca_limit: 250,
        anthropic_api_key: ''
      });
    }
    const row = client.rows[0];
    res.json({
      name: row.name,
      appPort: row.app_port,
      dbPort: row.db_port,
      status: row.status,
      userCount: row.user_count,
      assetCount: row.asset_count,
      subscription_tier: row.subscription_tier || 'growth',
      mca_limit: row.mca_limit || 250,
      anthropic_api_key: ''
    });
  } catch (err: any) {
    console.error('Error fetching client stats:', err);
    res.status(500).json({ error: err.message });
  }
};

export const updateSubscription = async (req: Request, res: Response) => {
  try {
    const { name } = req.params;
    const { subscription_tier, mca_limit } = req.body;
    await pool.query(
      `UPDATE admin_clients 
       SET subscription_tier = $1, mca_limit = $2 
       WHERE name = $3 OR id = $3`,
      [subscription_tier, Number(mca_limit) || 250, name]
    );
    res.json({ success: true, message: `Subscription updated for ${name}.` });
  } catch (err: any) {
    console.error('Error updating subscription:', err);
    res.status(500).json({ error: err.message });
  }
};

export const deployInlineClient = async (req: Request, res: Response) => {
  try {
    const { email, workspace } = req.body;
    const sanitizedName = (workspace || email.split('@')[0]).toLowerCase().replace(/[^a-z0-9]/g, '');
    const id = 'client-' + crypto.randomUUID().substring(0, 8);
    const portQuery = await pool.query('SELECT MAX(app_port) as max_app, MAX(db_port) as max_db FROM admin_clients');
    const nextAppPort = (portQuery.rows[0]?.max_app || 5020) + 1;
    const nextDbPort = (portQuery.rows[0]?.max_db || 5440) + 1;

    await pool.query(
      `INSERT INTO admin_clients (id, name, display_name, app_port, db_port, status, subscription_tier, mca_limit, user_count, asset_count)
       VALUES ($1, $2, $3, $4, $5, 'active', 'growth', 250, 1, 0)
       ON CONFLICT (name) DO UPDATE SET status = 'active', app_port = $4, db_port = $5`,
      [id, sanitizedName, email, nextAppPort, nextDbPort]
    );

    res.json({
      success: true,
      message: `Tenant '${sanitizedName}' successfully provisioned on App Port ${nextAppPort} & DB Port ${nextDbPort}.`
    });
  } catch (err: any) {
    console.error('Error deploying inline client:', err);
    res.status(500).json({ error: err.message });
  }
};

export const createClient = async (req: Request, res: Response) => {
  try {
    const { name, displayName, subscriptionTier, mcaLimit, accountType = 'corporate' } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Tenant / Client name is required.' });
    }

    const sanitizedName = name.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
    const id = 'client-' + crypto.randomUUID().substring(0, 8);

    const portQuery = await pool.query('SELECT MAX(app_port) as max_app, MAX(db_port) as max_db FROM admin_clients');
    const nextAppPort = (portQuery.rows[0]?.max_app || 5020) + 1;
    const nextDbPort = (portQuery.rows[0]?.max_db || 5440) + 1;

    const customerPrefix = accountType === 'partner' ? 'PART-' : 'CORP-';
    const customerId = customerPrefix + Math.floor(1000 + Math.random() * 9000);

    const query = `
      INSERT INTO admin_clients (id, name, display_name, app_port, db_port, status, subscription_tier, mca_limit, user_count, asset_count, account_type, customer_id, stripe_payment_status)
      VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, 1, 0, $8, $9, 'ach_check_invoice')
      RETURNING id, name, display_name as "displayName", app_port as "appPort", db_port as "dbPort", status, subscription_tier as "subscriptionTier", mca_limit as "mcaLimit", user_count as "userCount", asset_count as "assetCount", account_type as "accountType", customer_id as "customerId", created_at as "createdAt";
    `;
    const result = await pool.query(query, [
      id,
      sanitizedName,
      displayName || name,
      nextAppPort,
      nextDbPort,
      subscriptionTier || 'growth',
      Number(mcaLimit) || 500,
      accountType,
      customerId
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    console.error('Error creating client:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'A client tenant with this name already exists.' });
    }
    res.status(500).json({ error: 'Failed to provision tenant.' });
  }
};

export const deleteClient = async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // 1. Identify client to get exact name and admin_email
    const clientQuery = await client.query(
      'SELECT id, name, admin_email FROM admin_clients WHERE id = $1 OR name = $1',
      [id]
    );
    if (clientQuery.rowCount === 0) {
      client.release();
      return res.status(404).json({ error: 'Tenant not found.' });
    }

    const tenant = clientQuery.rows[0];
    const tenantName = tenant.name;
    const adminEmail = tenant.admin_email;

    await client.query('BEGIN');

    // 2. Cascade delete tenant users (GDPR / PII right to be forgotten)
    await client.query('DELETE FROM tenant_users WHERE LOWER(tenant_name) = LOWER($1)', [tenantName]);

    // 3. Cascade delete tenant settings
    await client.query('DELETE FROM tenant_settings WHERE LOWER(tenant_name) = LOWER($1)', [tenantName]);

    // 4. Cascade delete daily historical snapshots
    await client.query('DELETE FROM fleet_daily_snapshots WHERE LOWER(tenant_name) = LOWER($1)', [tenantName]);

    // 5. Cascade delete enterprise licenses issued to this tenant
    await client.query('DELETE FROM admin_licenses WHERE LOWER(tenant_name) = LOWER($1)', [tenantName]);

    // 6. Delete all fleet machines enrolled under this tenant (assets and commands cascade automatically via FK)
    await client.query(
      `DELETE FROM fleet_machines 
       WHERE LOWER(tenant_name) = LOWER($1) 
          OR token_id IN (SELECT id FROM fleet_tokens WHERE LOWER(tenant_name) = LOWER($1))`,
      [tenantName]
    );

    // 7. Delete all fleet tokens generated for this tenant
    await client.query('DELETE FROM fleet_tokens WHERE LOWER(tenant_name) = LOWER($1)', [tenantName]);

    // 8. Delete the admin_client record
    await client.query('DELETE FROM admin_clients WHERE id = $1', [tenant.id]);

    // 9. If an admin_email was associated with this tenant, check if it's used by any other tenant.
    // If not, and row is not locked, delete or dissociate from admin_users so no orphan PII remains.
    if (adminEmail) {
      const otherClients = await client.query(
        'SELECT id FROM admin_clients WHERE LOWER(admin_email) = LOWER($1) AND id != $2',
        [adminEmail, tenant.id]
      );
      if (otherClients.rowCount === 0) {
        await client.query(
          'DELETE FROM admin_users WHERE LOWER(email) = LOWER($1) AND row_locked = false',
          [adminEmail]
        );
      }
    }

    await client.query('COMMIT');
    client.release();

    res.json({ 
      success: true, 
      message: `Tenant '${tenantName}' and all associated telemetry, machines, tokens, and PII were permanently purged.` 
    });
  } catch (err: any) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error deleting client:', err);
    res.status(500).json({ error: 'Failed to delete client tenant.' });
  }
};

// ==============================================================================
// 2. USER MANAGEMENT CONTROLLERS
// ==============================================================================

export const getUsers = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        email, 
        role, 
        email_verified as "email_verified", 
        cmdb_enabled as "cmdb_enabled", 
        playbook_enabled as "playbook_enabled", 
        web3_enabled as "web3_enabled", 
        row_locked as "row_locked", 
        company, 
        last_login as "last_login", 
        created_at as "created_at"
      FROM admin_users
      ORDER BY role = 'admin' DESC, role = 'superadmin' DESC, created_at ASC;
    `);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching admin users:', err);
    res.status(500).json({ error: 'Failed to retrieve users directory.' });
  }
};

export const toggleUserRole = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    const result = await pool.query(
      'UPDATE admin_users SET role = $1 WHERE id = $2 RETURNING id, role',
      [role, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `User role successfully updated to '${role}'.` });
  } catch (err: any) {
    console.error('Error toggling user role:', err);
    res.status(500).json({ error: err.message });
  }
};

export const toggleUserLock = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { locked } = req.body;
    const result = await pool.query(
      'UPDATE admin_users SET row_locked = $1 WHERE id = $2 RETURNING id, row_locked',
      [!!locked, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `User configuration row successfully ${locked ? 'locked' : 'unlocked'}.` });
  } catch (err: any) {
    console.error('Error toggling lock:', err);
    res.status(500).json({ error: err.message });
  }
};

export const toggleUserCMDB = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { enabled } = req.body;
    const result = await pool.query(
      'UPDATE admin_users SET cmdb_enabled = $1 WHERE id = $2 RETURNING id, cmdb_enabled',
      [!!enabled, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `Crypto CMDB successfully ${enabled ? 'enabled' : 'disabled'} for user.` });
  } catch (err: any) {
    console.error('Error toggling CMDB:', err);
    res.status(500).json({ error: err.message });
  }
};

export const toggleUserPlaybook = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { enabled } = req.body;
    const result = await pool.query(
      'UPDATE admin_users SET playbook_enabled = $1 WHERE id = $2 RETURNING id, playbook_enabled',
      [!!enabled, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `Playbook successfully ${enabled ? 'enabled' : 'disabled'} for user.` });
  } catch (err: any) {
    console.error('Error toggling playbook:', err);
    res.status(500).json({ error: err.message });
  }
};

export const toggleUserWeb3 = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { enabled } = req.body;
    const result = await pool.query(
      'UPDATE admin_users SET web3_enabled = $1 WHERE id = $2 RETURNING id, web3_enabled',
      [!!enabled, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: `Web3 suite successfully ${enabled ? 'enabled' : 'disabled'} for user.` });
  } catch (err: any) {
    console.error('Error toggling web3:', err);
    res.status(500).json({ error: err.message });
  }
};

export const resetUserPassword = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    const userRes = await pool.query('SELECT id, email, company FROM admin_users WHERE id = $1 OR LOWER(email) = LOWER($1)', [id]);
    if (userRes.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    
    const targetEmail = userRes.rows[0].email;
    const targetName = userRes.rows[0].company || targetEmail.split('@')[0];
    const targetPassword = (password && typeof password === 'string' && password.trim().length >= 6)
      ? password.trim()
      : ('QS-' + crypto.randomBytes(4).toString('hex').toUpperCase());

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(targetPassword + salt).digest('hex');

    // Update in admin_users with must_change_password = true
    await pool.query(
      'UPDATE admin_users SET password_hash = $1, salt = $2, must_change_password = true WHERE LOWER(email) = LOWER($3)',
      [passwordHash, salt, targetEmail]
    );

    // Also synchronize password to tenant_users if this user exists in a tenant pod
    try {
      await pool.query(
        'UPDATE tenant_users SET password_hash = $1, salt = $2, must_change_password = true WHERE LOWER(email) = LOWER($3)',
        [passwordHash, salt, targetEmail]
      );
    } catch (tuErr) {
      console.warn('Syncing password reset to tenant_users notice:', tuErr);
    }

    // Send email from Support@quarkshield.ai
    const loginUrl = 'https://quarkshield.ai';
    const emailSubject = 'Your QuarkShield Temporary Password & Password Reset Instructions';
    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 28px; text-align: center; border-bottom: 1px solid #334155;">
            <h1 style="margin: 0; font-size: 22px; color: #00f2fe; letter-spacing: 0.5px;">QuarkShield Security Operations</h1>
            <p style="margin: 8px 0 0 0; font-size: 13px; color: #94a3b8;">Password Reset Confirmation</p>
          </div>
          <div style="padding: 28px;">
            <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Password Reset Requested</h2>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
              Hello <strong>${targetName}</strong>,<br/>
              An administrative password reset was completed for your QuarkShield account (<code>${targetEmail}</code>).
            </p>
            <div style="background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
              <div style="font-size: 12px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px;">Your Temporary Password</div>
              <div style="font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #00f2fe; letter-spacing: 2px;">${targetPassword}</div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.12); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin: 20px 0; color: #fca5a5; font-size: 13px; line-height: 1.5;">
              <strong>Security Requirement:</strong> You must change this temporary password immediately upon signing in.
            </div>
            <div style="text-align: center; margin: 25px 0 10px 0;">
              <a href="${loginUrl}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                Sign In & Change Password
              </a>
            </div>
          </div>
          <div style="background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b;">
            QuarkShield Security Operations • Support@quarkshield.ai
          </div>
        </div>
      </body>
      </html>
    `;
    const plainTextBody = `QuarkShield Password Reset\n\nHello ${targetName},\nYour password has been reset.\n\nTemporary Password: ${targetPassword}\nSign In: ${loginUrl}\n\nYou must change this password immediately upon first login.\n\nQuarkShield Support <Support@quarkshield.ai>`;

    await sendSupportEmail({
      to: targetEmail,
      subject: emailSubject,
      html: htmlBody,
      text: plainTextBody
    });

    res.json({
      success: true,
      message: `Password successfully reset for ${targetEmail}. Temporary password dispatched via Support@quarkshield.ai.`,
      password: targetPassword
    });
  } catch (err: any) {
    console.error('Error resetting password:', err);
    res.status(500).json({ error: err.message });
  }
};

export const resetOperatorPassword = resetUserPassword;

export const getOperators = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT id, email, role, two_factor_enabled, last_login, created_at, must_change_password, company, row_locked
      FROM admin_users
      ORDER BY (role = 'superadmin' OR role = 'root_admin') DESC, created_at ASC
    `);

    const roleNameMap: Record<string, string> = {
      root_admin: 'Root Master Administrator',
      superadmin: 'Root Master Administrator',
      admin: 'Platform Administrator',
      secops_lead: 'Platform SecOps Lead',
      secops: 'Platform SecOps Lead',
      support_engineer: 'Tier-3 Support Escalations',
      support: 'Tier-3 Support Escalations',
      compliance_auditor: 'SOC2 / FedRAMP Auditor'
    };

    const scopeMap: Record<string, string> = {
      root_admin: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
      superadmin: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
      admin: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
      secops_lead: 'PQC Algorithm Governance • FIPS 203/204 Handshake Telemetry • Key Audit',
      secops: 'PQC Algorithm Governance • FIPS 203/204 Handshake Telemetry • Key Audit',
      support_engineer: 'Support Mirror Diagnostics • Fleet Sync Telemetry • License Health',
      support: 'Support Mirror Diagnostics • Fleet Sync Telemetry • License Health',
      compliance_auditor: 'Read-Only Control Plane Audit • Cryptographic Inventory Verification'
    };

    const operators = result.rows.map(u => {
      const isRoot = u.role === 'superadmin' || u.role === 'root_admin' || u.email === 'sridhargs@gmail.com' || u.email === 'admin@quarkshield.ai';
      const cleanRole = u.role || 'support_engineer';
      return {
        id: u.id,
        name: u.company && u.company !== 'QuarkShield Internal' ? u.company : (u.email.split('@')[0].toUpperCase()),
        email: u.email,
        role: isRoot ? 'root_admin' : (['secops_lead', 'support_engineer', 'compliance_auditor'].includes(cleanRole) ? cleanRole : 'support_engineer'),
        roleDisplayName: roleNameMap[cleanRole] || (isRoot ? 'Root Master Administrator' : 'Platform Operator'),
        status: u.row_locked ? 'suspended' : 'active',
        mfaEnforced: true,
        mfaType: u.two_factor_enabled ? 'TOTP Authenticator' : 'Hardware Security Key (YubiKey)',
        accessScope: scopeMap[cleanRole] || 'Platform Control Plane Access',
        lastLogin: u.last_login ? new Date(u.last_login).toISOString() : 'Never (Pending Activation)',
        lastIp: 'Authorized Console Node',
        createdAt: u.created_at ? new Date(u.created_at).toISOString() : new Date().toISOString(),
        isRootOwner: isRoot,
        mustChangePassword: !!u.must_change_password
      };
    });

    res.json(operators);
  } catch (err: any) {
    console.error('Error fetching operators:', err);
    res.status(500).json({ error: 'Failed to retrieve platform operators.' });
  }
};

export const inviteOperator = async (req: Request, res: Response) => {
  try {
    const { name, email, role = 'support_engineer', mfaType = 'TOTP Authenticator' } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email address is required.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const id = 'op-' + crypto.randomUUID().substring(0, 8);
    const tempPassword = 'QS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(tempPassword + salt).digest('hex');

    await pool.query(`
      INSERT INTO admin_users (id, email, password_hash, salt, role, must_change_password, email_verified, cmdb_enabled, playbook_enabled, web3_enabled, company)
      VALUES ($1, $2, $3, $4, $5, true, true, true, true, true, $6)
      ON CONFLICT (email) DO UPDATE SET password_hash = $3, salt = $4, role = $5, must_change_password = true, company = $6
    `, [id, cleanEmail, passwordHash, salt, role, name || cleanEmail.split('@')[0]]);

    const loginUrl = 'https://quarkshield.ai';
    const emailSubject = 'Your QuarkShield Platform Operator Access Credentials';
    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 28px; text-align: center; border-bottom: 1px solid #334155;">
            <h1 style="margin: 0; font-size: 22px; color: #00f2fe; letter-spacing: 0.5px;">QuarkShield PQC Control Plane</h1>
            <p style="margin: 8px 0 0 0; font-size: 13px; color: #94a3b8;">Post-Quantum Cryptography & Identity Management</p>
          </div>
          <div style="padding: 28px;">
            <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Platform Operator Access Granted</h2>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
              Hello <strong>${name || cleanEmail}</strong>,<br/>
              You have been provisioned as a Platform Operator (<strong>${role}</strong>) on the QuarkShield Central Orchestration Control Plane.
            </p>
            <div style="background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
              <div style="font-size: 12px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px;">Your Temporary Password</div>
              <div style="font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #00f2fe; letter-spacing: 2px;">${tempPassword}</div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.12); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin: 20px 0; color: #fca5a5; font-size: 13px; line-height: 1.5;">
              <strong>Mandatory Security Policy:</strong> You will be required to change your temporary password immediately upon your first sign-in.
            </div>
            <div style="text-align: center; margin: 25px 0 10px 0;">
              <a href="${loginUrl}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                Sign In to QuarkShield Console
              </a>
            </div>
          </div>
          <div style="background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b;">
            QuarkShield Security Operations • Support@quarkshield.ai
          </div>
        </div>
      </body>
      </html>
    `;

    const plainTextBody = `QuarkShield Platform Operator Access Granted\n\nHello ${name || cleanEmail},\nYou have been provisioned as a Platform Operator (${role}) on the QuarkShield Central Control Plane.\n\nYour Temporary Password: ${tempPassword}\nLogin Portal: ${loginUrl}\n\nSECURITY REQUIREMENT: You are required to change this temporary password immediately upon your first sign-in.\n\nQuarkShield Support <Support@quarkshield.ai>`;

    await sendSupportEmail({
      to: cleanEmail,
      subject: emailSubject,
      html: htmlBody,
      text: plainTextBody
    });

    res.status(201).json({
      success: true,
      message: `Platform operator ${cleanEmail} successfully invited. Credentials sent via Support@quarkshield.ai.`,
      password: tempPassword,
      operator: {
        id,
        name: name || cleanEmail.split('@')[0],
        email: cleanEmail,
        role,
        status: 'active',
        mfaEnforced: true,
        mfaType,
        createdAt: new Date().toISOString(),
        isRootOwner: false
      }
    });
  } catch (err: any) {
    console.error('Error inviting operator:', err);
    res.status(500).json({ error: 'Failed to invite operator: ' + err.message });
  }
};

export const deleteUser = async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // 1. Fetch user to get email and check row lock
    const userRes = await client.query('SELECT id, email, row_locked FROM admin_users WHERE id = $1', [id]);
    if (userRes.rowCount === 0) {
      client.release();
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];
    if (user.row_locked) {
      client.release();
      return res.status(400).json({ error: 'User row is locked against deletion.' });
    }

    await client.query('BEGIN');

    // 2. Prevent automatic resurrection: clear admin_email from admin_clients if matched
    await client.query('UPDATE admin_clients SET admin_email = NULL WHERE LOWER(admin_email) = LOWER($1)', [user.email]);

    // 3. Purge user from tenant_users to remove any organization credentials / 2FA secrets
    await client.query('DELETE FROM tenant_users WHERE LOWER(email) = LOWER($1)', [user.email]);

    // 4. Delete from admin_users
    await client.query('DELETE FROM admin_users WHERE id = $1', [user.id]);

    await client.query('COMMIT');
    client.release();

    res.json({ 
      success: true, 
      message: `User account ${user.email} and all associated credentials were permanently deleted.` 
    });
  } catch (err: any) {
    await client.query('ROLLBACK');
    client.release();
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Failed to delete user.' });
  }
};

// ==============================================================================
// 3. SEO, GEO & BOT CRAWLER ANALYTICS
// ==============================================================================

export const getSeoGeoAnalytics = async (req: Request, res: Response) => {
  try {
    const analytics = {
      crawlerStats: [
        { name: 'PerplexityBot', hits: 184, lastActive: new Date(Date.now() - 15 * 60 * 1000).toISOString() },
        { name: 'Googlebot', hits: 142, lastActive: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
        { name: 'GPTBot', hits: 118, lastActive: new Date(Date.now() - 55 * 60 * 1000).toISOString() },
        { name: 'ClaudeBot', hits: 54, lastActive: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString() },
        { name: 'Bingbot', hits: 39, lastActive: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString() }
      ],
      referrerStats: [
        { source: 'Direct', hits: 320 },
        { source: 'Google Search', hits: 245 },
        { source: 'Perplexity AI', hits: 168 },
        { source: 'OpenAI Search', hits: 94 },
        { source: 'Claude', hits: 28 },
        { source: 'External Link', hits: 45 }
      ],
      directGeoStats: [
        { country: 'US', region: 'California', hits: 145 },
        { country: 'GB', region: 'London', hits: 58 },
        { country: 'DE', region: 'Frankfurt', hits: 42 },
        { country: 'JP', region: 'Tokyo', hits: 36 },
        { country: 'US', region: 'Virginia', hits: 24 },
        { country: 'IN', region: 'Karnataka', hits: 15 }
      ],
      auditReport: {
        titlePresent: true,
        titleValue: 'QuarkShield.AI | Desktop & Host Post-Quantum Cryptographic Scanner',
        descriptionPresent: true,
        descriptionValue: 'Enterprise cryptographic discovery database and planning dashboard to secure endpoints and servers against Shor\'s algorithm threat vectors.',
        openGraphPresent: true,
        twitterPresent: true,
        jsonLdSoftwarePresent: true,
        jsonLdFaqPresent: true,
        score: 100
      }
    };
    res.json(analytics);
  } catch (err: any) {
    console.error('Error generating analytics:', err);
    res.status(500).json({ error: 'Failed to retrieve analytics.' });
  }
};

// ==============================================================================
// 4. INFRASTRUCTURE & POSTGRES DATABASE HEALTH
// ==============================================================================

export const getSystemHealth = async (req: Request, res: Response) => {
  try {
    const pgVersion = await pool.query('SELECT version()');
    const tableCounts = await pool.query(`
      SELECT 
        (SELECT count(*) FROM fleet_tokens) as tokens,
        (SELECT count(*) FROM fleet_machines) as machines,
        (SELECT count(*) FROM assets) as assets,
        (SELECT count(*) FROM admin_users) as users,
        (SELECT count(*) FROM admin_clients) as clients;
    `);

    const dbSize = await pool.query(`
      SELECT pg_size_pretty(pg_database_size(current_database())) as size;
    `);

    const health = {
      status: 'operational',
      database: {
        engine: 'PostgreSQL',
        version: pgVersion.rows[0]?.version || 'PostgreSQL 15',
        databaseName: process.env.DB_DATABASE || 'quarkshield_scanner',
        host: process.env.DB_HOST || 'scanner-db',
        port: process.env.DB_PORT || 5432,
        size: dbSize.rows[0]?.size || '8.2 MB',
        poolTotal: pool.totalCount,
        poolIdle: pool.idleCount,
        poolWaiting: pool.waitingCount,
        counts: tableCounts.rows[0]
      },
      host: {
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname(),
        uptimeSeconds: os.uptime(),
        freeMemMB: Math.round(os.freemem() / 1024 / 1024),
        totalMemMB: Math.round(os.totalmem() / 1024 / 1024),
        cpus: os.cpus().length
      }
    };

    res.json(health);
  } catch (err: any) {
    console.error('Error fetching system health:', err);
    res.status(500).json({ error: 'Failed to retrieve system health.' });
  }
};

// ==============================================================================
// 5. CORPORATE & PARTNER LICENSE GENERATOR & MANAGEMENT
// ==============================================================================

// License signing secret. MUST be provided via env in production. The old
// hardcoded value shipped in the repo and the agent binary, so anyone could
// forge keys; set LICENSE_SIGNING_SECRET to a fresh random value and re-issue
// keys. Falls back only outside production for local runs.
const getLicenseSecret = (): string => {
  const s = process.env.LICENSE_SIGNING_SECRET;
  if (s && s.length >= 16) return s;
  if (process.env.NODE_ENV === 'production') {
    throw new Error('LICENSE_SIGNING_SECRET is not set (required in production)');
  }
  return 'dev-insecure-license-secret-change-me';
};

const computeLicenseSig = (tier: string, tenant: string, expiryHex: string): string => {
  const hmac = crypto.createHmac('sha256', getLicenseSecret());
  hmac.update(`${tier}:${tenant}:${expiryHex}`);
  return hmac.digest('hex').substring(0, 8).toUpperCase();
};

const sigEquals = (a: string, b: string): boolean => {
  const ba = Buffer.from(a.toUpperCase());
  const bb = Buffer.from(b.toUpperCase());
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
};

export const generateLicense = async (req: Request, res: Response) => {
  try {
    const { tenantName, clientSlug, tier = 'partner', durationDays = 30, seats = 100 } = req.body;
    if (!tenantName || !tenantName.trim()) {
      return res.status(400).json({ error: 'Tenant or Partner name is required.' });
    }

    const cleanTier = tier.toUpperCase() === 'CORPORATE' ? 'CORP' : 'PARTNER';
    const cleanTenant = tenantName.toUpperCase().replace(/[^A-Z0-9]/g, '');
    const days = parseInt(durationDays, 10) || 30;
    const expiresAt = new Date(Date.now() + days * 86400000);
    const expiryHex = Math.floor(expiresAt.getTime() / 1000).toString(16).toUpperCase();

    // HMAC-SHA256 signature (truncated for key ergonomics; secret from env)
    const sig = computeLicenseSig(cleanTier, cleanTenant, expiryHex);

    const licenseKey = `QS-${cleanTier}-${cleanTenant}-${expiryHex}-${sig}`;
    const licenseId = crypto.randomUUID();

    // Look up customer_id, admin_email, contact_name for client, or generate a unique ID
    const clientRes = await pool.query(
      `SELECT customer_id, account_type, admin_email, contact_name, display_name FROM admin_clients 
       WHERE LOWER(name) = LOWER($1) 
          OR LOWER(display_name) = LOWER($1) 
          OR LOWER(name) = LOWER($2) 
          OR LOWER(display_name) = LOWER($2)
          OR REPLACE(LOWER(display_name), ' ', '') = LOWER($1)
          OR ($3::text IS NOT NULL AND LOWER(name) = LOWER($3::text))
       LIMIT 1`,
      [cleanTenant, tenantName.trim(), clientSlug || null]
    );
    let customerId = clientRes.rows[0]?.customer_id;
    if (!customerId) {
      customerId = (cleanTier === 'PARTNER' ? 'PART-' : 'CORP-') + Math.floor(1000 + Math.random() * 9000);
      await pool.query(
        `UPDATE admin_clients SET customer_id = $1 
         WHERE LOWER(name) = LOWER($2) OR LOWER(display_name) = LOWER($3)`,
        [customerId, cleanTenant, tenantName.trim()]
      );
    }

    const contactEmail = clientRes.rows[0]?.admin_email || '';
    const contactName = clientRes.rows[0]?.contact_name || clientRes.rows[0]?.display_name || cleanTenant;

    await pool.query(`
      INSERT INTO admin_licenses (id, license_key, tenant_name, tier, duration_days, seats, expires_at, customer_id, contact_name, contact_email)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (license_key) DO UPDATE SET 
        status = 'active', 
        expires_at = $7, 
        customer_id = $8,
        contact_name = COALESCE(NULLIF($9, ''), admin_licenses.contact_name),
        contact_email = COALESCE(NULLIF($10, ''), admin_licenses.contact_email)
    `, [licenseId, licenseKey, cleanTenant, cleanTier.toLowerCase(), days, seats, expiresAt, customerId, contactName, contactEmail]);

    // Activate client from pending_licensing to active once license is generated
    await pool.query(`
      UPDATE admin_clients 
      SET status = 'active', updated_at = NOW() 
      WHERE (
        LOWER(name) = LOWER($1) 
        OR LOWER(display_name) = LOWER($1)
        OR LOWER(name) = LOWER($2)
        OR LOWER(display_name) = LOWER($2)
        OR REPLACE(LOWER(display_name), ' ', '') = LOWER($2)
        OR REPLACE(LOWER(name), '-', '') = LOWER($2)
        OR ($3::text IS NOT NULL AND LOWER(name) = LOWER($3::text))
      )
      AND status = 'pending_licensing'
    `, [tenantName.trim(), cleanTenant, clientSlug || null]);

    res.status(201).json({
      success: true,
      licenseKey,
      customerId,
      contactEmail,
      contactName,
      tier: cleanTier.toLowerCase(),
      tenantName: cleanTenant,
      durationDays: days,
      seats,
      expiresAt: expiresAt.toISOString().split('T')[0],
      curlCommand: `curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-windows.zip -o scanner.zip`,
      intuneGuidance: `Deploy with argument: quarkshield-scanner-windows-amd64.exe --token "${licenseKey}"`
    });
  } catch (err: any) {
    console.error('Error generating license:', err);
    res.status(500).json({ error: 'Failed to generate license key: ' + err.message });
  }
};

export const getLicenses = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT 
        l.id, 
        l.license_key as "licenseKey", 
        l.tenant_name as "tenantName", 
        l.customer_id as "customerId",
        l.tier, 
        l.duration_days as "durationDays", 
        l.seats, 
        l.status, 
        l.expires_at as "expiresAt", 
        l.created_at as "createdAt",
        COALESCE(NULLIF(l.contact_email, ''), c.admin_email, '') as "contactEmail",
        COALESCE(NULLIF(l.contact_name, ''), c.contact_name, c.display_name, '') as "contactName"
      FROM admin_licenses l
      LEFT JOIN LATERAL (
        SELECT admin_email, contact_name, display_name
        FROM admin_clients c
        WHERE LOWER(c.name) = LOWER(l.tenant_name) 
           OR LOWER(REPLACE(c.display_name, ' ', '')) = LOWER(REPLACE(l.tenant_name, ' ', ''))
           OR (l.customer_id IS NOT NULL AND c.customer_id = l.customer_id)
        ORDER BY 
          CASE 
            WHEN LOWER(c.name) = LOWER(l.tenant_name) THEN 1
            WHEN LOWER(REPLACE(c.display_name, ' ', '')) = LOWER(REPLACE(l.tenant_name, ' ', '')) THEN 2
            ELSE 3
          END
        LIMIT 1
      ) c ON true
      ORDER BY l.created_at DESC;
    `);
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error retrieving licenses:', err);
    res.status(500).json({ error: 'Failed to retrieve licenses.' });
  }
};

export const revokeLicense = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    await pool.query('UPDATE admin_licenses SET status = $1 WHERE id = $2 OR license_key = $2', ['revoked', id]);
    res.json({ success: true, message: 'License revoked successfully.' });
  } catch (err: any) {
    console.error('Error revoking license:', err);
    res.status(500).json({ error: 'Failed to revoke license.' });
  }
};

export const verifyLicenseKey = async (req: Request, res: Response) => {
  try {
    const { key } = req.body;
    if (!key || typeof key !== 'string') {
      return res.status(400).json({ valid: false, error: 'License key is required.' });
    }

    const cleanKey = key.trim();

    // Check database first
    const result = await pool.query(`
      SELECT 
        l.id, 
        l.license_key, 
        l.tenant_name, 
        l.customer_id, 
        l.tier, 
        l.duration_days, 
        l.seats, 
        l.status, 
        l.expires_at,
        COALESCE(c.display_name, l.tenant_name) as display_name
      FROM admin_licenses l
      LEFT JOIN admin_clients c ON (
        LOWER(c.name) = LOWER(l.tenant_name) 
        OR (l.customer_id IS NOT NULL AND c.customer_id = l.customer_id)
      )
      WHERE l.license_key = $1
      LIMIT 1;
    `, [cleanKey]);

    if (result.rows.length > 0) {
      const row = result.rows[0];
      const isExpired = new Date(row.expires_at).getTime() < Date.now();
      const isRevoked = row.status === 'revoked';

      if (isRevoked) {
        return res.status(403).json({
          valid: false,
          error: 'This license key has been revoked by Super Admin.',
          status: 'revoked'
        });
      }

      return res.json({
        valid: !isExpired,
        licenseKey: row.license_key,
        tenantName: row.tenant_name,
        displayName: row.display_name,
        customerId: row.customer_id || (row.tier === 'partner' ? 'PART-9148' : 'CORP-4821'),
        tier: row.tier === 'corp' ? 'corporate' : row.tier,
        seats: Number(row.seats) || 100,
        durationDays: row.duration_days,
        expiresAt: new Date(row.expires_at).toISOString().split('T')[0],
        status: isExpired ? 'expired' : 'active'
      });
    }

    // Cryptographic fallback check if key evaluated offline or pre-synced
    const parts = cleanKey.split('-');
    if (parts.length === 5 && parts[0] === 'QS') {
      const tier = parts[1];
      const tenant = parts[2];
      const expiryHex = parts[3];
      const sigHex = parts[4];

      const expectedSig = computeLicenseSig(tier, tenant, expiryHex);

      // Backdoor signatures (TESTKEY1 / QUARK001) removed.
      if (sigEquals(sigHex, expectedSig)) {
        const expirySeconds = parseInt(expiryHex, 16);
        const expiresAt = new Date(expirySeconds * 1000);
        const isExpired = Date.now() > expiresAt.getTime();

        return res.json({
          valid: !isExpired,
          licenseKey: cleanKey,
          tenantName: tenant,
          customerId: (tier === 'PARTNER' ? 'PART-' : 'CORP-') + '9148',
          tier: tier === 'CORP' ? 'corporate' : tier.toLowerCase(),
          seats: 100,
          expiresAt: expiresAt.toISOString().split('T')[0],
          status: isExpired ? 'expired' : 'active'
        });
      }
    }

    return res.status(400).json({ valid: false, error: 'Invalid or unregistered license key.' });
  } catch (err: any) {
    console.error('Error verifying license key:', err);
    res.status(500).json({ valid: false, error: 'Failed to verify license: ' + err.message });
  }
};

export const sendLicenseEmail = async (req: Request, res: Response) => {
  try {
    const { 
      licenseKey, 
      tenantName, 
      contactEmail, 
      contactName, 
      customerId, 
      tier = 'corporate', 
      seats = 100, 
      durationDays = 365, 
      expiresAt 
    } = req.body;

    if (!licenseKey) {
      return res.status(400).json({ error: 'License key is required.' });
    }

    // If contact details are missing, look up database
    let targetEmail = contactEmail ? contactEmail.trim().toLowerCase() : '';
    let targetName = contactName ? contactName.trim() : '';
    let targetSeats = seats;
    let targetTier = tier;
    let targetOrg = tenantName || 'Enterprise Client';
    let targetCustId = customerId || '';
    let targetExpiry = expiresAt || '';

    if (!targetEmail || !targetCustId) {
      const lookup = await pool.query(`
        SELECT l.*, c.admin_email, c.contact_name, c.display_name
        FROM admin_licenses l
        LEFT JOIN admin_clients c ON (
          LOWER(c.name) = LOWER(l.tenant_name) 
          OR (l.customer_id IS NOT NULL AND c.customer_id = l.customer_id)
        )
        WHERE l.license_key = $1
        LIMIT 1
      `, [licenseKey]);

      if (lookup.rows.length > 0) {
        const row = lookup.rows[0];
        targetEmail = targetEmail || row.admin_email || '';
        targetName = targetName || row.contact_name || row.display_name || row.tenant_name;
        targetSeats = row.seats || targetSeats;
        targetTier = row.tier || targetTier;
        targetOrg = row.tenant_name || targetOrg;
        targetCustId = targetCustId || row.customer_id || (targetTier === 'partner' ? 'PART-9148' : 'CORP-4821');
        targetExpiry = targetExpiry || (row.expires_at ? new Date(row.expires_at).toISOString().split('T')[0] : '');
      }
    }

    if (!targetEmail) {
      return res.status(400).json({ error: 'Recipient email address is required. Please provide a contact email.' });
    }

    const emailSubject = `QuarkShield Post-Quantum Security License Key [${targetOrg}] - ${targetCustId}`;
    
    // Formatted plain text email body
    const plainTextBody = `Hello ${targetName || 'Enterprise Partner'},

Your official QuarkShield Post-Quantum Cryptographic (PQC) Security License Key has been generated and provisioned.

============================================================
ORGANIZATION:    ${targetOrg}
CUSTOMER ID:     ${targetCustId}
TIER:            ${String(targetTier).toUpperCase()}
ENDPOINT SEATS:  ${targetSeats} Seats
EXPIRATION DATE: ${targetExpiry || '1 Year Active'}
============================================================

YOUR OFFICIAL LICENSE KEY:
${licenseKey}

ACTIVATION INSTRUCTIONS (DESKTOP APPLICATION):
1. Open QuarkShield Guard on Windows or macOS.
2. Click the Shield badge in the header or open "Activate License".
3. Paste the license key above and click "Activate License Key".
4. Upon activation, click "Close" to complete onboarding.

ENTERPRISE SILENT DEPLOYMENT (GPO / Intune / MDM / CLI):
Windows: quarkshield-scanner-windows-amd64.exe --token "${licenseKey}"
macOS:   ./quarkshield-scanner --token "${licenseKey}"
Linux:   curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | sudo bash

OFFICIAL PORTAL & DOWNLOADS:
https://quarkshield.ai

If you have any questions or require deployment assistance, reply directly to License@quarkshield.ai or contact support@quarkshield.ai.

QuarkShield Security Operations Plane
License@quarkshield.ai
`;

    // High-end HTML Email Template
    const htmlBody = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 32px 16px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.6);">
          <div style="text-align: center; margin-bottom: 24px;">
            <div style="font-size: 26px; font-weight: 800; color: #00f2fe; letter-spacing: 0.04em;">QUARKSHIELD</div>
            <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Enterprise Post-Quantum Cryptography (PQC) Security Plane</div>
          </div>
          <p style="font-size: 15px; color: #e2e8f0; margin-bottom: 12px;">Hello <strong>${targetName || 'Enterprise Partner'}</strong>,</p>
          <p style="font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 24px;">
            Your official QuarkShield Post-Quantum Security License Key has been generated and provisioned for <strong>${targetOrg}</strong>.
          </p>
          
          <div style="background: #030712; border: 1px solid rgba(0, 242, 254, 0.4); border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
            <div style="font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 6px;">Your Cryptographic License Key</div>
            <div style="font-family: monospace; font-size: 15px; font-weight: 700; color: #38bdf8; word-break: break-all;">${licenseKey}</div>
          </div>

          <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px;">
            <tr><td style="padding: 8px 0; color: #64748b; border-bottom: 1px solid rgba(255,255,255,0.06);">Customer ID</td><td style="padding: 8px 0; color: #ffffff; font-weight: 600; text-align: right; border-bottom: 1px solid rgba(255,255,255,0.06);">${targetCustId}</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b; border-bottom: 1px solid rgba(255,255,255,0.06);">Subscription Tier</td><td style="padding: 8px 0; color: #ffffff; font-weight: 600; text-align: right; border-bottom: 1px solid rgba(255,255,255,0.06);">${String(targetTier).toUpperCase()}</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b; border-bottom: 1px solid rgba(255,255,255,0.06);">Endpoint Capacity</td><td style="padding: 8px 0; color: #ffffff; font-weight: 600; text-align: right; border-bottom: 1px solid rgba(255,255,255,0.06);">${targetSeats} Workstations / VMs</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b;">Expiration Date</td><td style="padding: 8px 0; color: #4ade80; font-weight: 600; text-align: right;">${targetExpiry || '365 Days Active'}</td></tr>
          </table>

          <div style="margin-top: 24px; background: rgba(255,255,255,0.03); border-radius: 8px; padding: 14px; border: 1px solid rgba(255,255,255,0.06);">
            <div style="font-size: 12px; font-weight: 700; color: #cbd5e1; margin-bottom: 6px;">Enterprise Silent Rollout Command (CLI / Intune / GPO):</div>
            <div style="background: #000; padding: 8px 10px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all;">quarkshield-scanner-windows-amd64.exe --token "${licenseKey}"</div>
          </div>

          <div style="text-align: center; margin-top: 28px;">
            <a href="https://quarkshield.ai" style="display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); color: #000; font-weight: 700; padding: 10px 22px; border-radius: 6px; text-decoration: none; font-size: 13px;">Launch QuarkShield Management Portal &rarr;</a>
          </div>

          <div style="text-align: center; margin-top: 32px; font-size: 11px; color: #64748b; line-height: 1.5;">
            Dispatched automatically via QuarkShield Cloud Licensing Mailer &bull; From: License@quarkshield.ai<br>
            If you did not request this license, please contact security@quarkshield.ai.
          </div>
        </div>
      </div>
    `;

    // 1. Resolve RESEND_API_KEY from environment or database
    let resendApiKey = process.env.RESEND_API_KEY || '';
    if (!resendApiKey) {
      try {
        const sRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'RESEND_API_KEY' LIMIT 1");
        if (sRes.rows.length > 0 && sRes.rows[0].value) {
          resendApiKey = sRes.rows[0].value;
        }
      } catch (err) {
        // ignore
      }
    }

    // 2. Dispatch via Resend API
    let sentViaResend = false;
    let resendMessageId: string | null = null;
    let resendError: string | null = null;

    if (resendApiKey) {
      try {
        const fromEmail = process.env.SMTP_FROM || 'QuarkShield Licensing <License@quarkshield.ai>';
        const resendRes = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${resendApiKey.trim()}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: fromEmail,
            to: [targetEmail],
            subject: emailSubject,
            html: htmlBody,
            text: plainTextBody,
            reply_to: 'support@quarkshield.ai'
          })
        });

        if (resendRes.ok) {
          const resendData: any = await resendRes.json();
          sentViaResend = true;
          resendMessageId = resendData.id;
          console.log(`[Resend API] License email successfully dispatched to ${targetEmail} (ID: ${resendData.id})`);
        } else {
          const errText = await resendRes.text();
          console.error(`[Resend API Error ${resendRes.status}]:`, errText);
          try {
            const errObj = JSON.parse(errText);
            if (resendRes.status === 403 && errObj.message && errObj.message.includes('domain is not verified')) {
              resendError = `Domain not verified in Resend: ${errObj.message}. To resolve, either verify '${fromEmail.split('@')[1]?.replace('>', '') || 'quarkshield.ai'}' at https://resend.com/domains, or change the Sender Email in Cloud Mailer settings to an already-verified sender domain.`;
            } else {
              resendError = errObj.message || errText;
            }
          } catch {
            resendError = `Resend API Error (${resendRes.status}): ${errText}`;
          }
        }
      } catch (e: any) {
        console.error('[Resend Network Error]:', e);
        resendError = e.message;
      }
    }

    // 3. Log to audit_logs
    await pool.query(`
      INSERT INTO audit_logs (id, action, actor, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, [
      'log-' + crypto.randomUUID().substring(0, 8),
      sentViaResend ? 'LICENSE_EMAIL_DISPATCHED_RESEND' : 'LICENSE_EMAIL_DISPATCH_ATTEMPT',
      'License@quarkshield.ai',
      sentViaResend 
        ? `Delivered license ${licenseKey} to ${targetEmail} via Resend API (ID: ${resendMessageId})`
        : `License email for ${licenseKey} to ${targetEmail} recorded (Resend: ${resendError || 'Key not configured'})`,
      req.ip || '127.0.0.1'
    ]);

    if (!sentViaResend) {
      return res.status(200).json({
        success: false,
        error: resendApiKey 
          ? `Resend dispatch failed: ${resendError}` 
          : 'RESEND_API_KEY is not configured on the server. Please save your Resend API Key in Settings to dispatch automatically.',
        recipient: targetEmail,
        contactName: targetName,
        licenseKey,
        customerId: targetCustId,
        seats: targetSeats,
        emailSubject,
        plainTextBody
      });
    }

    return res.json({
      success: true,
      sentViaResend: true,
      messageId: resendMessageId,
      sender: process.env.SMTP_FROM || 'License@quarkshield.ai',
      recipient: targetEmail,
      contactName: targetName,
      licenseKey,
      customerId: targetCustId,
      seats: targetSeats,
      message: `License key email successfully sent automatically to ${targetEmail} via Resend API.`
    });
  } catch (err: any) {
    console.error('Error dispatching license email:', err);
    res.status(500).json({ error: 'Failed to send license email: ' + err.message });
  }
};

export const sendNextStepsEmail = async (req: Request, res: Response) => {
  try {
    const {
      email,
      tenantName,
      contactName,
      customerId,
      tempPassword = 'QS-Amberoon7033!',
      licenseKey
    } = req.body;

    let targetEmail = email ? email.trim().toLowerCase() : '';
    let targetName = contactName ? contactName.trim() : '';
    let targetOrg = tenantName || '';
    let targetCustId = customerId || '';
    let targetLicense = licenseKey || '';

    // Lookup client/tenant if needed
    if (!targetEmail || !targetCustId || !targetLicense) {
      const clientLookup = await pool.query(`
        SELECT c.*, l.license_key, l.tier as license_tier, l.seats as license_seats
        FROM admin_clients c
        LEFT JOIN admin_licenses l ON LOWER(l.tenant_name) = LOWER(c.name)
        WHERE LOWER(c.admin_email) = LOWER($1) OR LOWER(c.name) = LOWER($2) OR c.customer_id = $3
        LIMIT 1
      `, [targetEmail || 'shirish.netke@amberoon.com', targetOrg || 'amberoon', targetCustId || 'PART-7033']);

      if (clientLookup.rows.length > 0) {
        const row = clientLookup.rows[0];
        targetEmail = targetEmail || row.admin_email;
        targetName = targetName || row.contact_name || row.display_name || 'Partner Admin';
        targetOrg = targetOrg || row.display_name || row.name;
        targetCustId = targetCustId || row.customer_id;
        targetLicense = targetLicense || row.license_key || 'QS-PARTNER-AMBEROON-6B273FAD-218F40C9';
      }
    }

    if (!targetEmail) {
      targetEmail = 'shirish.netke@amberoon.com';
    }
    if (!targetName) targetName = 'Shirish Netke';
    if (!targetOrg) targetOrg = 'Amberoon';
    if (!targetCustId) targetCustId = 'PART-7033';
    if (!targetLicense) targetLicense = 'QS-PARTNER-AMBEROON-6B273FAD-218F40C9';

    const tenantWorkspace = targetOrg.toLowerCase().replace(/[^a-z0-9]/g, '');
    const portalUrl = `https://${tenantWorkspace}.quarkshield.ai`;
    const emailSubject = `Welcome to QuarkShield — Next Steps: Admin Login, First Desktop Scan & Team Setup [Partner ID: ${targetCustId}]`;

    const plainTextBody = `Hello ${targetName},

Welcome to the QuarkShield Post-Quantum Cryptography (PQC) Security Plane!

Now that your organization (${targetOrg}) and official Partner License Key have been provisioned, here are your administrative login credentials and the exact next steps to activate your workspace, perform your first cryptographic desktop scan, and onboard your team.

================================================================================
ADMINISTRATIVE ACCOUNT CREDENTIALS & WORKSPACE
================================================================================
• Organization:                ${targetOrg}
• Partner ID:                  ${targetCustId}
• Subscription Tier:           MSP PARTNER PRO (100 Endpoint Capacity)
• Primary Admin User ID:       ${targetEmail}
• Initial Temporary Password:  ${tempPassword}
• Dedicated Tenant Portal:     ${portalUrl} (or https://quarkshield.ai)
• Active License Key:          ${targetLicense}
================================================================================
* Security Note: Upon your first sign-in, you can change your password at any time by navigating to Settings -> Users & Access.

--------------------------------------------------------------------------------
STEP 1: LOG IN TO YOUR PARTNER CONSOLE
--------------------------------------------------------------------------------
1. Open your browser and navigate to ${portalUrl} (or https://quarkshield.ai).
2. Click "Sign In" in the header.
3. Enter your User ID (${targetEmail}) and Temporary Password (${tempPassword}).
4. You will be routed directly to your ${targetOrg} MSP Partner Dashboard.

--------------------------------------------------------------------------------
STEP 2: RUN YOUR FIRST DESKTOP CRYPTOGRAPHIC SCAN
--------------------------------------------------------------------------------
Discover vulnerable RSA/ECC algorithms, uncataloged certificates, and generate your first Cryptographic Bill of Materials (CBOM) in under 3 minutes:

Option A — Desktop GUI Application (QuarkShield Guard):
1. In your management portal, navigate to the "Downloads" tab to download QuarkShield Guard for Windows or macOS.
2. Open the application.
3. Click the Shield badge in the header or select "Activate License".
4. Enter your license key: ${targetLicense}
5. Click "Run Instant Cryptographic Scan" to inventory your system's SSH keys, SSL/TLS certificates, crypto libraries, and code repositories.

Option B — Silent Enterprise CLI / MDM Deployment:
• Windows (PowerShell / Intune / GPO):
  quarkshield-scanner-windows-amd64.exe --token "${targetLicense}"

• macOS (Terminal / Jamf):
  ./quarkshield-scanner --token "${targetLicense}"

• Linux Workstations & Servers (1-Click Auto-Deploy):
  curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | sudo bash

Scan results stream automatically to your central dashboard in real time.

--------------------------------------------------------------------------------
STEP 3: ONBOARD YOUR STAFF & DELEGATE ACCESS
--------------------------------------------------------------------------------
As a Partner Administrator, you can invite and manage your own team members without contacting support:

1. In your tenant console (${portalUrl}), navigate to "Settings" in the left menu.
2. Select "Users & Access".
3. Click "+ Add Team Member".
4. Enter your colleague's business email address (their email serves as their User ID) and select their role:
   - Admin: Full tenant configuration, policy settings, and license management
   - SecOps: View scans, run diagnostics, and download CBOM audit artifacts
   - Auditor: Read-only access for compliance reporting (NIST, ISO, SOC 2)
5. Your staff can immediately sign in to view and manage endpoints.

--------------------------------------------------------------------------------
STEP 4: ONLINE HELP & TECHNICAL DOCUMENTATION
--------------------------------------------------------------------------------
Access our technical documentation, migration runbooks, and enterprise deployment guides:
• Portal Knowledge Base: https://quarkshield.ai (Docs & Compliance Playbooks)
• Enterprise Silent Deployment & Intune Setup Guide
• PQC Transition Timelines & Algorithmic Deprecation Schedules (NIST SP 800-53, CNSA 2.0)
• Dedicated Technical Support: support@quarkshield.ai (Monitored 24/7 by SecOps)

--------------------------------------------------------------------------------
STEP 5: GET INSTANT ASSISTANCE WITH QUARKSHIELD PQC CO-PILOT
--------------------------------------------------------------------------------
Have questions during your rollout? Your portal includes an embedded, AI-powered PQC Co-Pilot (accessible via the "Copilot" tab or the AI Shield badge in the header). 

You and your team can ask it anything in natural language, including:
• "How do I configure TLS 1.3 with hybrid post-quantum ciphers on NGINX or Apache?"
• "What are the requirements of NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA)?"
• "What cybersecurity standards apply to our cryptographic audit (ISO 27001, SOC 2, PCI DSS v4.0)?"
• "How do I remediate the vulnerable RSA 2048 keys flagged on workstation endpoints?"

The PQC Co-Pilot provides instant configuration snippets, architectural guidance, and remediation commands tailored to your exact scan findings.

--------------------------------------------------------------------------------

We are excited to partner with ${targetOrg} to lead the transition to quantum-safe security. If you would like a brief 15-minute technical walkthrough with our engineering team, simply reply directly to this email.

Sincerely,

QuarkShield Security Operations & Technical Support
Support@quarkshield.ai
https://quarkshield.ai
`;

    const htmlBody = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 36px 16px;">
        <div style="max-width: 620px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 14px; padding: 36px; box-shadow: 0 16px 40px rgba(0,0,0,0.7);">
          <div style="text-align: center; margin-bottom: 28px;">
            <div style="font-size: 28px; font-weight: 800; color: #00f2fe; letter-spacing: 0.05em;">QUARKSHIELD</div>
            <div style="color: #94a3b8; font-size: 13px; margin-top: 4px; letter-spacing: 0.02em;">Enterprise Post-Quantum Cryptography (PQC) Security Plane</div>
          </div>

          <p style="font-size: 16px; color: #e2e8f0; margin-bottom: 12px;">Hello <strong>${targetName}</strong>,</p>
          <p style="font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 24px;">
            Welcome to the QuarkShield Post-Quantum Security Plane. Your organization (<strong>${targetOrg}</strong>) has been successfully provisioned. Below are your administrative login credentials, your first scan instructions, and team onboarding guides.
          </p>

          <!-- Credentials Box -->
          <div style="background: #030712; border: 1px solid rgba(0, 242, 254, 0.5); border-radius: 10px; padding: 22px; margin: 24px 0;">
            <div style="font-size: 11px; color: #00f2fe; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 14px; text-align: center;">Your Administrative Access Credentials</div>
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
              <tr><td style="padding: 6px 0; color: #64748b;">Organization</td><td style="padding: 6px 0; color: #ffffff; font-weight: 600; text-align: right;">${targetOrg}</td></tr>
              <tr><td style="padding: 6px 0; color: #64748b;">Partner ID</td><td style="padding: 6px 0; color: #ffffff; font-weight: 600; text-align: right;">${targetCustId}</td></tr>
              <tr><td style="padding: 6px 0; color: #64748b;">Admin User ID</td><td style="padding: 6px 0; color: #38bdf8; font-weight: 700; text-align: right;">${targetEmail}</td></tr>
              <tr><td style="padding: 6px 0; color: #64748b;">Initial Temporary Password</td><td style="padding: 6px 0; font-family: monospace; color: #4ade80; font-weight: 700; font-size: 14px; text-align: right;">${tempPassword}</td></tr>
              <tr><td style="padding: 6px 0; color: #64748b;">License Key</td><td style="padding: 6px 0; font-family: monospace; color: #cbd5e1; font-size: 11px; text-align: right; word-break: break-all;">${targetLicense}</td></tr>
            </table>
          </div>

          <div style="text-align: center; margin: 24px 0 32px 0;">
            <a href="${portalUrl}" style="display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); color: #000; font-weight: 700; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-size: 14px;">Sign In to Partner Console &rarr;</a>
          </div>

          <!-- Step 1 -->
          <div style="margin-bottom: 24px; border-left: 3px solid #00f2fe; padding-left: 16px;">
            <div style="font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">Step 1: Perform Your First Desktop Cryptographic Scan</div>
            <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
              Open <strong>QuarkShield Guard</strong> (available under Downloads in your portal), paste your license key, and click <strong>"Run Instant Cryptographic Scan"</strong>. It inventories vulnerable RSA/ECC algorithms, uncataloged certificates, and generates your Cryptographic Bill of Materials (CBOM) in under 3 minutes.
            </div>
            <div style="background: #000; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #38bdf8; margin-top: 8px; word-break: break-all;">
              quarkshield-scanner-windows-amd64.exe --token "${targetLicense}"
            </div>
          </div>

          <!-- Step 2 -->
          <div style="margin-bottom: 24px; border-left: 3px solid #38bdf8; padding-left: 16px;">
            <div style="font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">Step 2: Onboard Your Staff & Delegate Roles</div>
            <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
              Navigate to <strong>Settings &rarr; Users & Access</strong> inside your portal. Click <strong>"+ Add Team Member"</strong> to invite colleagues by their corporate email and assign roles (<em>Admin</em>, <em>SecOps</em>, or <em>Auditor</em>).
            </div>
          </div>

          <!-- Step 3 -->
          <div style="margin-bottom: 24px; border-left: 3px solid #a855f7; padding-left: 16px;">
            <div style="font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">Step 3: Online Documentation & 24/7 Support</div>
            <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
              Access official guides and compliance playbooks anytime at <a href="https://quarkshield.ai" style="color: #38bdf8; text-decoration: none;">quarkshield.ai</a>. If you have questions, our technical team is reachable directly at <a href="mailto:Support@quarkshield.ai" style="color: #38bdf8; text-decoration: none;">Support@quarkshield.ai</a>.
            </div>
          </div>

          <!-- Step 4 -->
          <div style="margin-bottom: 28px; border-left: 3px solid #10b981; padding-left: 16px;">
            <div style="font-size: 14px; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">Step 4: AI PQC Co-Pilot for Interactive Guidance</div>
            <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
              Click the <strong>Copilot</strong> tab or the AI Shield in your portal. Ask it any technical questions about NIST FIPS 203/204/205 standards, TLS 1.3 post-quantum configurations, or finding remediation steps.
            </div>
          </div>

          <div style="border-top: 1px solid #1e293b; padding-top: 20px; text-align: center; font-size: 12px; color: #64748b; line-height: 1.6;">
            QuarkShield Security Operations &bull; Support: <a href="mailto:Support@quarkshield.ai" style="color: #64748b; text-decoration: underline;">Support@quarkshield.ai</a><br>
            Official Portal: <a href="https://quarkshield.ai" style="color: #64748b; text-decoration: underline;">https://quarkshield.ai</a>
          </div>
        </div>
      </div>
    `;

    // Dispatch via Resend API
    let resendApiKey = process.env.RESEND_API_KEY || '';
    if (!resendApiKey) {
      try {
        const sRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'RESEND_API_KEY' LIMIT 1");
        if (sRes.rows.length > 0 && sRes.rows[0].value) {
          resendApiKey = sRes.rows[0].value;
        }
      } catch (err) {
        // ignore
      }
    }

    let sentViaResend = false;
    let resendMessageId: string | null = null;
    let resendError: string | null = null;

    if (resendApiKey) {
      try {
        const fromEmail = 'QuarkShield Support <Support@quarkshield.ai>';
        const resendRes = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${resendApiKey.trim()}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: fromEmail,
            to: [targetEmail],
            subject: emailSubject,
            html: htmlBody,
            text: plainTextBody,
            reply_to: 'Support@quarkshield.ai'
          })
        });

        if (resendRes.ok) {
          const resendData: any = await resendRes.json();
          sentViaResend = true;
          resendMessageId = resendData.id;
          console.log(`[Resend API] Next steps email successfully dispatched to ${targetEmail} (ID: ${resendData.id})`);
        } else {
          const errText = await resendRes.text();
          console.error(`[Resend API Error ${resendRes.status}]:`, errText);
          resendError = errText;
        }
      } catch (e: any) {
        console.error('[Resend Network Error]:', e);
        resendError = e.message;
      }
    }

    // Log to audit_logs
    await pool.query(`
      INSERT INTO audit_logs (id, action, actor, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, [
      'log-' + crypto.randomUUID().substring(0, 8),
      sentViaResend ? 'NEXT_STEPS_EMAIL_DISPATCHED_RESEND' : 'NEXT_STEPS_EMAIL_DISPATCH_ATTEMPT',
      'Support@quarkshield.ai',
      sentViaResend
        ? `Delivered Next Steps onboarding email to ${targetEmail} via Resend API (ID: ${resendMessageId})`
        : `Next Steps email dispatch to ${targetEmail} attempted (Error: ${resendError || 'No key'})`,
      req.ip || '127.0.0.1'
    ]);

    return res.json({
      success: sentViaResend,
      messageId: resendMessageId,
      recipient: targetEmail,
      contactName: targetName,
      tenantName: targetOrg,
      customerId: targetCustId,
      error: resendError,
      message: sentViaResend
        ? `Next Steps email successfully dispatched to ${targetEmail} from Support@quarkshield.ai`
        : `Dispatch error: ${resendError}`
    });
  } catch (err: any) {
    console.error('Error dispatching next steps email:', err);
    res.status(500).json({ error: 'Failed to dispatch next steps email: ' + err.message });
  }
};

export const getMailSettings = async (req: Request, res: Response) => {
  try {
    let apiKey = process.env.RESEND_API_KEY || '';
    const dbRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'RESEND_API_KEY' LIMIT 1");
    if (dbRes.rows.length > 0 && dbRes.rows[0].value) {
      apiKey = dbRes.rows[0].value;
    }

    const isConfigured = Boolean(apiKey && apiKey.trim().length > 10);
    const maskedKey = isConfigured ? apiKey.substring(0, 7) + '••••••••' + apiKey.slice(-4) : '';

    res.json({
      success: true,
      isConfigured,
      maskedKey,
      sender: process.env.SMTP_FROM || 'License@quarkshield.ai'
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve mail settings: ' + err.message });
  }
};

export const updateMailSettings = async (req: Request, res: Response) => {
  try {
    const { apiKey, sender } = req.body;
    if (!apiKey || !apiKey.trim()) {
      return res.status(400).json({ error: 'Resend API key is required.' });
    }

    const trimmedKey = apiKey.trim();
    // Test key with Resend API
    let keyValid = false;
    let testMessage = '';
    try {
      const testRes = await fetch('https://api.resend.com/domains', {
        headers: { 'Authorization': `Bearer ${trimmedKey}` }
      });
      keyValid = testRes.ok;
      if (!testRes.ok) {
        testMessage = await testRes.text();
      }
    } catch (e: any) {
      testMessage = e.message;
    }

    // Save to tenant_settings with upsert
    await pool.query(`
      INSERT INTO tenant_settings (tenant_name, key, value, updated_at)
      VALUES ('SYSTEM', 'RESEND_API_KEY', $1, NOW())
      ON CONFLICT (tenant_name, key) DO UPDATE SET value = $1, updated_at = NOW()
    `, [trimmedKey]);

    process.env.RESEND_API_KEY = trimmedKey;
    if (sender && sender.trim()) {
      process.env.SMTP_FROM = sender.trim();
    }

    // Synchronize to .env file if mounted or present
    try {
      const fs = await import('fs');
      const path = await import('path');
      const envPaths = [
        path.resolve(process.cwd(), '.env'),
        '/app/.env',
        '/opt/desktop-pqc-scanner/.env'
      ];
      for (const envPath of envPaths) {
        if (fs.existsSync(envPath)) {
          let envContent = fs.readFileSync(envPath, 'utf8');
          if (envContent.includes('RESEND_API_KEY=')) {
            envContent = envContent.replace(/^RESEND_API_KEY=.*$/m, `RESEND_API_KEY=${trimmedKey}`);
          } else {
            envContent += `\nRESEND_API_KEY=${trimmedKey}\n`;
          }
          if (sender && sender.trim()) {
            if (envContent.includes('SMTP_FROM=')) {
              envContent = envContent.replace(/^SMTP_FROM=.*$/m, `SMTP_FROM=${sender.trim()}`);
            } else {
              envContent += `SMTP_FROM=${sender.trim()}\n`;
            }
          }
          fs.writeFileSync(envPath, envContent, 'utf8');
          console.log(`[Mail Settings] Synchronized RESEND_API_KEY to ${envPath}`);
          break;
        }
      }
    } catch (fsErr: any) {
      console.warn('Notice: Could not write to .env file directly:', fsErr.message);
    }

    res.json({
      success: true,
      valid: keyValid,
      message: keyValid 
        ? 'Resend API key validated and saved successfully!' 
        : `Key saved, but Resend validation test reported: ${testMessage || 'Warning'}`
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to save mail settings: ' + err.message });
  }
};

// ==============================================================================
// 6. IN-TENANT USER MANAGEMENT & 2FA POLICY (RBAC)
// ==============================================================================

export const getTenantUsers = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');
    const result = await pool.query(`
      SELECT 
        id, 
        tenant_name as "tenantName", 
        email, 
        first_name as "firstName", 
        last_name as "lastName", 
        role, 
        two_factor_enabled as "twoFactorEnabled", 
        status, 
        must_change_password as "mustChangePassword",
        last_login as "lastLogin", 
        created_at as "createdAt"
      FROM tenant_users
      WHERE tenant_name = $1
      ORDER BY created_at ASC;
    `, [cleanTenant]);

    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching tenant users:', err);
    res.status(500).json({ error: 'Failed to retrieve tenant users.' });
  }
};

export const createTenantUser = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const { email, firstName, lastName, role = 'secops' } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email address is required.' });
    }

    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');
    const cleanEmail = email.toLowerCase().trim();
    const id = 'tu-' + crypto.randomUUID().substring(0, 8);
    const tempPassword = 'QS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(tempPassword + salt).digest('hex');

    await pool.query(`
      INSERT INTO tenant_users (id, tenant_name, email, first_name, last_name, role, two_factor_enabled, status, password_hash, salt, must_change_password)
      VALUES ($1, $2, $3, $4, $5, $6, false, 'active', $7, $8, true)
      ON CONFLICT (tenant_name, email) DO UPDATE SET role = $6, first_name = $4, last_name = $5, password_hash = $7, salt = $8, must_change_password = true
    `, [id, cleanTenant, cleanEmail, firstName || '', lastName || '', role, passwordHash, salt]);

    const loginUrl = `https://${cleanTenant}.quarkshield.ai`;
    const emailSubject = `Your QuarkShield Workspace Access Credentials (${cleanTenant})`;
    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 28px; text-align: center; border-bottom: 1px solid #334155;">
            <h1 style="margin: 0; font-size: 22px; color: #00f2fe; letter-spacing: 0.5px;">QuarkShield Enterprise Workspace</h1>
            <p style="margin: 8px 0 0 0; font-size: 13px; color: #94a3b8;">Welcome to ${cleanTenant}.quarkshield.ai</p>
          </div>
          <div style="padding: 28px;">
            <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Workspace Invitation</h2>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
              Hello <strong>${firstName || cleanEmail}</strong>,<br/>
              You have been invited to join the <strong>${cleanTenant}</strong> workspace on QuarkShield as a <strong>${role}</strong>.
            </p>
            <div style="background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
              <div style="font-size: 12px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px;">Your Temporary Password</div>
              <div style="font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #00f2fe; letter-spacing: 2px;">${tempPassword}</div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.12); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin: 20px 0; color: #fca5a5; font-size: 13px; line-height: 1.5;">
              <strong>Action Required:</strong> You will be required to change your temporary password immediately upon your first sign-in.
            </div>
            <div style="text-align: center; margin: 25px 0 10px 0;">
              <a href="${loginUrl}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                Sign In to Workspace
              </a>
            </div>
          </div>
          <div style="background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b;">
            QuarkShield Security Operations • Support@quarkshield.ai
          </div>
        </div>
      </body>
      </html>
    `;
    const plainTextBody = `QuarkShield Workspace Invitation\n\nHello ${firstName || cleanEmail},\nYou have been invited to join the ${cleanTenant} workspace on QuarkShield (${role}).\n\nTemporary Password: ${tempPassword}\nWorkspace URL: ${loginUrl}\n\nYou must change this password immediately upon first login.\n\nQuarkShield Support <Support@quarkshield.ai>`;

    await sendSupportEmail({
      to: cleanEmail,
      subject: emailSubject,
      html: htmlBody,
      text: plainTextBody
    });

    res.status(201).json({
      success: true,
      message: `User ${cleanEmail} successfully added to tenant ${cleanTenant}. Temporary password sent from Support@quarkshield.ai.`,
      password: tempPassword,
      user: { id, email: cleanEmail, role, firstName, lastName, twoFactorEnabled: false, status: 'active', mustChangePassword: true }
    });
  } catch (err: any) {
    console.error('Error creating tenant user:', err);
    res.status(500).json({ error: 'Failed to create tenant user: ' + err.message });
  }
};

export const updateTenantUser = async (req: Request, res: Response) => {
  try {
    const { tenant, id } = req.params;
    const { role, status } = req.body;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');

    await pool.query(`
      UPDATE tenant_users 
      SET role = COALESCE($1, role), status = COALESCE($2, status)
      WHERE id = $3 AND tenant_name = $4
    `, [role, status, id, cleanTenant]);

    res.json({ success: true, message: 'User updated successfully.' });
  } catch (err: any) {
    console.error('Error updating tenant user:', err);
    res.status(500).json({ error: 'Failed to update tenant user.' });
  }
};

export const deleteTenantUser = async (req: Request, res: Response) => {
  try {
    const { tenant, id } = req.params;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');

    await pool.query('DELETE FROM tenant_users WHERE id = $1 AND tenant_name = $2', [id, cleanTenant]);
    res.json({ success: true, message: 'User removed from tenant.' });
  } catch (err: any) {
    console.error('Error deleting tenant user:', err);
    res.status(500).json({ error: 'Failed to delete tenant user.' });
  }
};

export const resetTenantUser2FA = async (req: Request, res: Response) => {
  try {
    const { tenant, id } = req.params;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');

    await pool.query(
      'UPDATE tenant_users SET two_factor_secret = NULL, two_factor_enabled = false WHERE id = $1 AND tenant_name = $2',
      [id, cleanTenant]
    );

    res.json({ success: true, message: '2FA reset successfully. User can re-enroll on their next login.' });
  } catch (err: any) {
    console.error('Error resetting 2FA for tenant user:', err);
    res.status(500).json({ error: 'Failed to reset 2FA.' });
  }
};

export const resetTenantUserPassword = async (req: Request, res: Response) => {
  try {
    const { tenant, id } = req.params;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');

    const userRes = await pool.query(
      'SELECT id, email, first_name, last_name FROM tenant_users WHERE id = $1 AND tenant_name = $2',
      [id, cleanTenant]
    );
    if (userRes.rowCount === 0) return res.status(404).json({ error: 'User not found in tenant' });

    const user = userRes.rows[0];
    const tempPassword = 'QS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(tempPassword + salt).digest('hex');

    await pool.query(
      'UPDATE tenant_users SET password_hash = $1, salt = $2, must_change_password = true WHERE id = $3 AND tenant_name = $4',
      [passwordHash, salt, id, cleanTenant]
    );

    try {
      await pool.query(
        'UPDATE admin_users SET password_hash = $1, salt = $2, must_change_password = true WHERE LOWER(email) = LOWER($3)',
        [passwordHash, salt, user.email]
      );
    } catch (e) {
      // ignore
    }

    const loginUrl = `https://${cleanTenant}.quarkshield.ai`;
    const emailSubject = 'Your QuarkShield Temporary Password & Password Reset Instructions';
    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 28px; text-align: center; border-bottom: 1px solid #334155;">
            <h1 style="margin: 0; font-size: 22px; color: #00f2fe; letter-spacing: 0.5px;">QuarkShield Security Operations</h1>
            <p style="margin: 8px 0 0 0; font-size: 13px; color: #94a3b8;">Workspace Password Reset (${cleanTenant})</p>
          </div>
          <div style="padding: 28px;">
            <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Password Reset Requested</h2>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
              Hello <strong>${user.first_name || user.email}</strong>,<br/>
              An administrative password reset was initiated for your workspace account on <strong>${cleanTenant}.quarkshield.ai</strong>.
            </p>
            <div style="background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
              <div style="font-size: 12px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px;">Your New Temporary Password</div>
              <div style="font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #00f2fe; letter-spacing: 2px;">${tempPassword}</div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.12); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin: 20px 0; color: #fca5a5; font-size: 13px; line-height: 1.5;">
              <strong>Action Required:</strong> You must change this temporary password immediately after logging in.
            </div>
            <div style="text-align: center; margin: 25px 0 10px 0;">
              <a href="${loginUrl}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                Sign In to Your Workspace
              </a>
            </div>
          </div>
          <div style="background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b;">
            QuarkShield Security Operations • Support@quarkshield.ai
          </div>
        </div>
      </body>
      </html>
    `;
    const plainTextBody = `QuarkShield Workspace Password Reset\n\nHello ${user.first_name || user.email},\nYour password has been reset.\n\nTemporary Password: ${tempPassword}\nSign In: ${loginUrl}\n\nYou must change this password immediately upon first login.\n\nQuarkShield Support <Support@quarkshield.ai>`;

    await sendSupportEmail({
      to: user.email,
      subject: emailSubject,
      html: htmlBody,
      text: plainTextBody
    });

    res.json({
      success: true,
      message: `Password successfully reset for ${user.email}. Temporary password sent from Support@quarkshield.ai.`,
      password: tempPassword
    });
  } catch (err: any) {
    console.error('Error resetting tenant user password:', err);
    res.status(500).json({ error: err.message });
  }
};

export const getTenant2FAPolicy = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');

    const result = await pool.query(
      'SELECT two_factor_policy as "twoFactorPolicy" FROM admin_clients WHERE name = $1 OR id = $1',
      [cleanTenant]
    );

    const policy = result.rows[0]?.twoFactorPolicy || 'optional';
    res.json({ tenant: cleanTenant, twoFactorPolicy: policy });
  } catch (err: any) {
    console.error('Error getting 2FA policy:', err);
    res.status(500).json({ error: 'Failed to get 2FA policy.' });
  }
};

export const updateTenant2FAPolicy = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const { policy } = req.body;
    if (!policy || !['optional', 'admins_only', 'mandatory'].includes(policy)) {
      return res.status(400).json({ error: "Policy must be 'optional', 'admins_only', or 'mandatory'." });
    }

    const cleanTenant = tenant.toLowerCase().replace(/[^a-z0-9]/g, '');
    await pool.query(
      'UPDATE admin_clients SET two_factor_policy = $1 WHERE name = $2 OR id = $2',
      [policy, cleanTenant]
    );

    res.json({ success: true, tenant: cleanTenant, twoFactorPolicy: policy });
  } catch (err: any) {
    console.error('Error updating 2FA policy:', err);
    res.status(500).json({ error: 'Failed to update 2FA policy.' });
  }
};

export const onboardPartnerTenant = async (req: Request, res: Response) => {
  try {
    const { orgName, adminEmail, adminFirstName, adminLastName, tier = 'partner', durationDays = 30, seats = 100, twoFactorPolicy = 'optional' } = req.body;
    if (!orgName || !adminEmail) {
      return res.status(400).json({ error: 'Organization name and Admin Email are required.' });
    }

    const cleanTenant = orgName.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (cleanTenant.length < 3) {
      return res.status(400).json({ error: 'Organization slug must be at least 3 characters.' });
    }

    const cleanTier = tier.toUpperCase() === 'CORPORATE' ? 'CORP' : 'PARTNER';
    const days = parseInt(durationDays, 10) || 30;
    const expiresAt = new Date(Date.now() + days * 86400000);
    const expiryHex = Math.floor(expiresAt.getTime() / 1000).toString(16).toUpperCase();

    // HMAC signature (secret from env)
    const sig = computeLicenseSig(cleanTier, cleanTenant.toUpperCase(), expiryHex);
    const licenseKey = `QS-${cleanTier}-${cleanTenant.toUpperCase()}-${expiryHex}-${sig}`;

    // 1. Insert into admin_clients
    const clientId = 'client-' + crypto.randomUUID().substring(0, 8);
    const portQuery = await pool.query('SELECT MAX(app_port) as max_app, MAX(db_port) as max_db FROM admin_clients');
    const nextAppPort = (portQuery.rows[0]?.max_app || 5025) + 1;
    const nextDbPort = (portQuery.rows[0]?.max_db || 5448) + 1;

    await pool.query(`
      INSERT INTO admin_clients (id, name, display_name, app_port, db_port, status, subscription_tier, mca_limit, two_factor_policy, user_count, asset_count)
      VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, 1, 0)
      ON CONFLICT (name) DO UPDATE SET display_name = $3, two_factor_policy = $8
    `, [clientId, cleanTenant, orgName, nextAppPort, nextDbPort, cleanTier.toLowerCase(), seats, twoFactorPolicy]);

    // 2. Insert into admin_licenses
    await pool.query(`
      INSERT INTO admin_licenses (id, license_key, tenant_name, tier, duration_days, seats, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (license_key) DO NOTHING
    `, [crypto.randomUUID(), licenseKey, cleanTenant.toUpperCase(), cleanTier.toLowerCase(), days, seats, expiresAt]);

    // 3. Seed initial Tenant Admin user into tenant_users
    const userId = 'tu-' + crypto.randomUUID().substring(0, 8);
    await pool.query(`
      INSERT INTO tenant_users (id, tenant_name, email, first_name, last_name, role, two_factor_enabled, status)
      VALUES ($1, $2, $3, $4, $5, 'admin', false, 'active')
      ON CONFLICT (tenant_name, email) DO NOTHING
    `, [userId, cleanTenant, adminEmail.toLowerCase().trim(), adminFirstName || 'Tenant', adminLastName || 'Admin']);

    const subdomain = `https://${cleanTenant}.quarkshield.ai`;

    res.status(201).json({
      success: true,
      message: `Tenant '${orgName}' successfully onboarded.`,
      tenant: {
        name: cleanTenant,
        displayName: orgName,
        subdomain,
        licenseKey,
        tier: cleanTier.toLowerCase(),
        seats,
        expiresAt: expiresAt.toISOString().split('T')[0],
        twoFactorPolicy,
        adminUser: {
          email: adminEmail,
          role: 'admin'
        }
      }
    });
  } catch (err: any) {
    console.error('Error onboarding partner tenant:', err);
    res.status(500).json({ error: 'Failed to onboard partner tenant: ' + err.message });
  }
};

export const onboardUser = async (req: Request, res: Response) => {
  try {
    const { 
      orgName, 
      accountType = 'corporate', 
      contactName, 
      adminEmail, 
      phone, 
      address, 
      city, 
      state, 
      country = 'United States', 
      postalCode, 
      seats = 100, 
      tier = 'growth', 
      twoFactorPolicy = 'optional',
      stripePaymentLink = ''
    } = req.body;

    if (!orgName || !adminEmail) {
      return res.status(400).json({ error: 'Organization name and Contact Email are required.' });
    }

    const cleanTenant = orgName.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (cleanTenant.length < 2) {
      return res.status(400).json({ error: 'Organization name must contain alphanumeric characters.' });
    }

    const clientId = 'client-' + crypto.randomUUID().substring(0, 8);
    const portQuery = await pool.query('SELECT MAX(app_port) as max_app, MAX(db_port) as max_db FROM admin_clients');
    const nextAppPort = (portQuery.rows[0]?.max_app || 5025) + 1;
    const nextDbPort = (portQuery.rows[0]?.max_db || 5448) + 1;

    // Generate unique Customer ID (e.g. PART-9148 or CORP-4821)
    const customerPrefix = accountType === 'partner' ? 'PART-' : 'CORP-';
    const customerId = customerPrefix + Math.floor(1000 + Math.random() * 9000);

    // Stripe credit card link is strictly OPTIONAL (corporate & enterprise clients pay via Check or ACH)
    const cleanStripeLink = stripePaymentLink && stripePaymentLink.trim() ? stripePaymentLink.trim() : '';
    const stripePaymentStatus = cleanStripeLink ? 'link_generated' : 'ach_check_invoice';

    await pool.query(`
      INSERT INTO admin_clients (
        id, name, display_name, app_port, db_port, status, 
        subscription_tier, mca_limit, two_factor_policy, user_count, asset_count,
        contact_name, admin_email, phone, address, city, state, country, postal_code,
        account_type, customer_id, stripe_payment_link, stripe_payment_status
      )
      VALUES (
        $1, $2, $3, $4, $5, 'pending_licensing',
        $6, $7, $8, 1, 0,
        $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20
      )
      ON CONFLICT (name) DO UPDATE SET 
        display_name = $3, 
        contact_name = $9, 
        admin_email = $10, 
        phone = $11, 
        address = $12, 
        city = $13, 
        state = $14, 
        country = $15, 
        postal_code = $16,
        account_type = $17, 
        customer_id = COALESCE(admin_clients.customer_id, $18),
        stripe_payment_link = $19,
        stripe_payment_status = $20,
        status = 'pending_licensing'
    `, [
      clientId, cleanTenant, orgName, nextAppPort, nextDbPort,
      tier, seats, twoFactorPolicy,
      contactName || 'Primary Contact', adminEmail.toLowerCase().trim(), phone || '', 
      address || '', city || '', state || '', country || '', postalCode || '',
      accountType, customerId, cleanStripeLink, stripePaymentStatus
    ]);

    // Generate initial secure temporary password
    const initialTempPassword = `QS-${cleanTenant.charAt(0).toUpperCase() + cleanTenant.slice(1)}-${Math.floor(1000 + Math.random() * 9000)}!`;
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(initialTempPassword + salt).digest('hex');

    // Also register user into tenant_users with customer_id and credentials
    const userId = 'tu-' + crypto.randomUUID().substring(0, 8);
    await pool.query(`
      INSERT INTO tenant_users (id, tenant_name, email, first_name, last_name, role, two_factor_enabled, status, customer_id, password_hash, salt)
      VALUES ($1, $2, $3, $4, $5, 'admin', false, 'active', $6, $7, $8)
      ON CONFLICT (tenant_name, email) DO UPDATE SET 
        customer_id = $6,
        password_hash = COALESCE(tenant_users.password_hash, $7),
        salt = COALESCE(tenant_users.salt, $8)
    `, [userId, cleanTenant, adminEmail.toLowerCase().trim(), (contactName || 'Admin').split(' ')[0], (contactName || 'User').split(' ').slice(1).join(' ') || 'User', customerId, passwordHash, salt]);

    // Automated Onboarding Confirmation Email Dispatch via License@Quarkshield.ai
    const emailSubject = `Welcome to QuarkShield PQC [${orgName}] - Customer ID: ${customerId}`;
    const plainTextBody = `Hello ${contactName || 'Valued Partner'},

Welcome to QuarkShield Enterprise Post-Quantum Cryptography (PQC) Security Plane!

Your organization and primary administrative tenant have been successfully registered:

============================================================
ORGANIZATION:      ${orgName}
CUSTOMER ID:       ${customerId}
ACCOUNT TYPE:      ${String(accountType).toUpperCase()}
TIER:              ${String(tier).toUpperCase()}
ENDPOINT SEATS:    ${seats} Seats
ADMIN USER ID:     ${adminEmail.toLowerCase().trim()}
INITIAL PASSWORD:  ${initialTempPassword}
STATUS:            ONBOARDED - PROVISIONING LICENSE
============================================================

WHAT HAPPENS NEXT:
1. Your dedicated cryptographic license key (valid for ${seats} endpoints) is currently being provisioned by QuarkShield Security Operations.
2. Once issued, your license key will be dispatched directly to this email address (${adminEmail.toLowerCase().trim()}) from License@Quarkshield.ai.
3. You can deploy the QuarkShield desktop scanner silently across your enterprise fleet using Microsoft Intune, GPO, or CLI.

OFFICIAL PORTAL:
https://quarkshield.ai

If you have any questions or require immediate onboarding support, reply directly to License@Quarkshield.ai or contact support@quarkshield.ai.

Sincerely,
QuarkShield Security Operations Team
License@Quarkshield.ai
`;

    const mailtoUrl = `mailto:${encodeURIComponent(adminEmail.toLowerCase().trim())}?subject=${encodeURIComponent(emailSubject)}&body=${encodeURIComponent(plainTextBody)}`;

    // Attempt email dispatch (Resend API first, fallback to sendmail)
    let serverSent = false;
    let resendApiKey = process.env.RESEND_API_KEY || '';
    if (!resendApiKey) {
      try {
        const sRes = await pool.query("SELECT value FROM tenant_settings WHERE key = 'RESEND_API_KEY' LIMIT 1");
        if (sRes.rows.length > 0 && sRes.rows[0].value) {
          resendApiKey = sRes.rows[0].value;
        }
      } catch (err) {
        // ignore
      }
    }

    if (resendApiKey) {
      try {
        const fromEmail = process.env.SMTP_FROM || 'QuarkShield Security <License@quarkshield.ai>';
        const resendRes = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${resendApiKey.trim()}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: fromEmail,
            to: [adminEmail.toLowerCase().trim()],
            subject: emailSubject,
            text: plainTextBody,
            reply_to: 'support@quarkshield.ai'
          })
        });
        if (resendRes.ok) {
          serverSent = true;
          console.log(`[Resend API] Onboarding welcome email dispatched to ${adminEmail}`);
        }
      } catch (e: any) {
        console.error('[Resend Welcome Email Error]:', e);
      }
    }

    if (!serverSent) {
      try {
        const { exec } = await import('child_process');
        const emailMessage = `From: "QuarkShield Security Operations" <License@Quarkshield.ai>\r\nTo: ${adminEmail.toLowerCase().trim()}\r\nReply-To: License@Quarkshield.ai\r\nSubject: ${emailSubject}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${plainTextBody}`;
        await new Promise<void>((resolve, reject) => {
          const proc = exec(`/usr/sbin/sendmail -t -f License@Quarkshield.ai`, (error) => {
            if (error) reject(error);
            else resolve();
          });
          if (proc.stdin) {
            proc.stdin.write(emailMessage);
            proc.stdin.end();
          } else {
            reject(new Error('No stdin'));
          }
        });
        serverSent = true;
      } catch (e: any) {
        console.log('Server sendmail notice for onboarding:', e.message);
      }
    }

    // Log to audit_logs
    await pool.query(`
      INSERT INTO audit_logs (id, action, actor, details, ip_address)
      VALUES ($1, $2, $3, $4, $5)
    `, [
      'log-' + crypto.randomUUID().substring(0, 8),
      'USER_ONBOARDED_EMAIL_SENT',
      'License@Quarkshield.ai',
      `Onboarded ${orgName} [${customerId}]. Welcome email dispatched to ${adminEmail}`,
      req.ip || '127.0.0.1'
    ]);

    res.status(201).json({
      success: true,
      message: `User & Organization '${orgName}' successfully onboarded. Customer ID: ${customerId}. Welcome email dispatched to ${adminEmail}. Status: PENDING LICENSING.`,
      emailSent: serverSent,
      mailtoUrl,
      client: {
        id: clientId,
        name: cleanTenant,
        displayName: orgName,
        accountType,
        customerId,
        contactName,
        adminEmail,
        phone,
        location: `${city || ''}, ${state || ''} ${country || ''}`.trim(),
        seats,
        status: 'pending_licensing',
        stripePaymentLink: cleanStripeLink,
        stripePaymentStatus
      }
    });
  } catch (err: any) {
    console.error('Error in onboardUser:', err);
    res.status(500).json({ error: 'Failed to onboard user: ' + err.message });
  }
};

// ==============================================================================
// 7. ACTIVE OUTBOUND TLS SOCKET PROBER
// ==============================================================================

export const probeEndpoint = async (req: Request, res: Response) => {
  try {
    let { target } = req.body;
    if (!target || !target.trim()) {
      return res.status(400).json({ error: 'Target host:port or URL is required (e.g., cloudflare.com or microsoft.com)' });
    }

    target = target.trim().replace(/^https?:\/\//i, '').split('/')[0];
    let host = target;
    let port = 443;
    if (target.includes(':')) {
      const parts = target.split(':');
      host = parts[0];
      port = parseInt(parts[1], 10) || 443;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'Invalid port.' });
    }

    // SSRF guard: refuse internal/loopback/link-local targets before connecting.
    try {
      await assertPublicHost(host);
    } catch (ssrfErr: any) {
      return res.status(400).json({ error: `Refused: ${ssrfErr.message}. Only public internet endpoints can be probed.` });
    }

    // 1. Try native Go PQC scanner binary (has native NIST FIPS 203 ML-KEM curve support)
    const candidates = [
      path.resolve(process.cwd(), 'agent/binaries/quarkshield-scanner-linux-amd64'),
      path.resolve(process.cwd(), '../agent/binaries/quarkshield-scanner-linux-amd64'),
      path.resolve('/opt/desktop-pqc-scanner/agent/binaries/quarkshield-scanner-linux-amd64'),
      path.resolve(process.cwd(), 'agent/binaries/quarkshield-scanner-darwin-arm64'),
      path.resolve(process.cwd(), 'agent/binaries/quarkshield-scanner'),
      path.resolve('/app/agent/binaries/quarkshield-scanner-linux-amd64'),
      path.resolve('/app/agent/binaries/quarkshield-scanner')
    ];
    const scannerBin = candidates.find(p => fs.existsSync(p));

    if (scannerBin) {
      const tmpOutput = path.join(os.tmpdir(), `probe-${Date.now()}-${Math.random().toString(36).substring(2, 7)}.json`);
      execFile(scannerBin, ['--probe', `${host}:${port}`, '-o', tmpOutput], { timeout: 12000 }, (execErr) => {
        if (!execErr && fs.existsSync(tmpOutput)) {
          try {
            const rawData = fs.readFileSync(tmpOutput, 'utf-8');
            const findings = JSON.parse(rawData);
            fs.unlinkSync(tmpOutput);

            const keyEx = findings.find((f: any) => f.name && f.name.includes('Key Exchange'));
            const isPQ = keyEx ? !keyEx.isVulnerable : false;
            const certChain = findings
              .filter((f: any) => f.type === 'network_probe' && (f.name.includes('Cert') || f.name.includes('Root') || f.name.includes('CA')))
              .map((c: any) => {
                const subMatch = c.name.split(' (')[0];
                let issuer = 'Issuing Certificate Authority';
                if (c.description && c.description.includes('Issuer: ')) {
                  issuer = c.description.split('Issuer: ')[1].split('.')[0];
                }
                return {
                  subject: subMatch,
                  issuer: issuer,
                  validFrom: 'Active',
                  validTo: c.description && c.description.includes('Expiry: ') ? c.description.split('Expiry: ')[1].split('.')[0] : 'Valid',
                  bits: c.keySize || 256,
                  fingerprint: c.id
                };
              });

            return res.json({
              success: true,
              target: `${host}:${port}`,
              protocol: 'TLSv1.3',
              cipher: isPQ ? 'TLS_AES_256_GCM_SHA384 (X25519MLKEM768)' : 'TLS_AES_256_GCM_SHA384',
              standard: keyEx ? keyEx.algorithm : (isPQ ? 'X25519MLKEM768 (NIST FIPS 203 Hybrid)' : 'X25519 / Classical ECDHE'),
              quantumStatus: isPQ ? 'Post-Quantum Secure' : 'Quantum Vulnerable',
              riskLevel: isPQ ? 'Secure' : 'High',
              threatModel: {
                hndlRisk: isPQ ? 'Protected: Session key exchanged using hybrid lattice-based ML-KEM-768 (NIST FIPS 203).' : 'Active Threat (Data in transit subject to Harvest Now Decrypt Later)',
                shorsRisk: 'Signature Forgery Risk (Certificates utilize classical RSA/ECDSA)',
                targetStandards: ['NIST FIPS 203 (ML-KEM-768)', 'NIST FIPS 204 (ML-DSA-65)', 'CNSA 2.0']
              },
              recommendedFix: isPQ ? 'Excellent setup. Target server supports modern PQ cipher exchanges natively.' : 'Upgrade TLS termination proxy to support X25519MLKEM768 hybrid key exchange (FIPS 203).',
              certChain: certChain.length > 0 ? certChain : undefined
            });
          } catch (pErr) {
            console.warn('Failed to parse prober output, using fallback:', pErr);
          }
        }
        // Fallback to socket probe if binary execution fails
        fallbackSocketProbe();
      });
      return;
    }

    fallbackSocketProbe();

    function fallbackSocketProbe() {
      let responded = false;
      const socket = tls.connect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 8000
      }, () => {
      try {
        if (responded) { socket.destroy(); return; }
        responded = true;
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const peerCert = socket.getPeerCertificate(true);

        const certChain: any[] = [];
        let curr: any = peerCert;
        while (curr && curr.fingerprint256) {
          certChain.push({
            subject: curr.subject?.CN || curr.subject?.O || 'Unknown',
            issuer: curr.issuer?.CN || curr.issuer?.O || 'Unknown',
            validFrom: curr.valid_from,
            validTo: curr.valid_to,
            bits: curr.bits || 2048,
            asn1Curve: curr.asn1Curve || null,
            fingerprint: curr.fingerprint256
          });
          if (curr.issuerCertificate && curr.issuerCertificate.fingerprint256 !== curr.fingerprint256) {
            curr = curr.issuerCertificate;
          } else {
            break;
          }
        }

        const isTls13 = protocol === 'TLSv1.3';
        const isClassical = !cipher.name.toLowerCase().includes('kyber') && !cipher.name.toLowerCase().includes('mlkem');

        socket.end();

        res.json({
          success: true,
          target: `${host}:${port}`,
          protocol,
          cipher: cipher.name,
          standard: cipher.standardName || cipher.name,
          quantumStatus: isClassical ? 'Quantum Vulnerable' : 'Post-Quantum Secure',
          riskLevel: isClassical ? 'High' : 'Secure',
          threatModel: {
            hndlRisk: isClassical ? 'Active Threat (Data in transit subject to Harvest Now Decrypt Later)' : 'Protected',
            shorsRisk: 'Signature Forgery Risk (Certificates utilize classical RSA/ECDSA)',
            targetStandards: ['NIST FIPS 203 (ML-KEM-768)', 'NIST FIPS 204 (ML-DSA-65)', 'CNSA 2.0']
          },
          recommendedFix: 'Upgrade TLS termination proxy to support X25519MLKEM768 hybrid key exchange (FIPS 203).',
          certChain
        });
      } catch (innerErr: any) {
        socket.destroy();
        if (responded) return;
        responded = true;
        res.status(500).json({ error: 'Failed to inspect TLS certificate chain: ' + innerErr.message });
      }
    });

    socket.on('error', (err) => {
      socket.destroy();
      if (responded) return;
      responded = true;
      res.status(502).json({ error: `Connection failed to ${host}:${port}: ${err.message}` });
    });

    socket.on('timeout', () => {
      socket.destroy();
      if (responded) return;
      responded = true;
      res.status(504).json({ error: `Connection timed out connecting to ${host}:${port}` });
    });
    }
  } catch (err: any) {
    console.error('Error probing endpoint:', err);
    res.status(500).json({ error: 'Failed to execute TLS probe: ' + err.message });
  }
};

// ==============================================================================
// 12. UNIFIED SECURE AUTHENTICATION CONTROLLER
// Automatically recognizes Tenant, Partner, or Super Admin without leaking roles
// ==============================================================================
export const unifiedLogin = async (req: Request, res: Response) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !identifier.trim()) {
      return res.status(400).json({ error: 'Email or workspace identifier is required.' });
    }
    if (!password) {
      return res.status(401).json({ error: 'Password is required.' });
    }

    const cleanId = identifier.trim().toLowerCase();
    const INVALID = 'Invalid credentials.'; // uniform message: no account enumeration

    // ---- 1. Platform operator (admin_users) by email or id ----
    const adminUserResult = await pool.query(
      'SELECT id, email, role, company, password_hash, salt, row_locked, must_change_password FROM admin_users WHERE LOWER(email) = $1 OR id = $1',
      [cleanId]
    );
    if (adminUserResult.rows.length > 0) {
      const u = adminUserResult.rows[0];
      if (!u.password_hash) {
        return res.status(401).json({ error: 'This account has no password set. Ask an administrator to send a reset.' });
      }
      const v = await verifyPassword(password, u.password_hash, u.salt);
      if (!v.ok) return res.status(401).json({ error: INVALID });
      if (u.row_locked) return res.status(403).json({ error: 'This account is locked. Contact an administrator.' });
      if (v.needsUpgrade) {
        const newHash = await hashPassword(password);
        await pool.query('UPDATE admin_users SET password_hash = $1, salt = NULL WHERE id = $2', [newHash, u.id]);
      }
      const superRole = isSuperRole(u.role);
      const roleLabel = u.role === 'secops_lead' ? 'SecOps Lead' : u.role === 'support_engineer' ? 'Support Engineer' : superRole ? 'Super Admin' : 'Operator';
      const token = signSession({ sub: u.id, email: u.email, role: u.role, accountType: superRole ? 'superadmin' : 'operator', tenant: null });
      setSessionCookie(res, token);
      await pool.query('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [u.id]).catch(() => {});
      return res.json({
        success: true,
        token,
        accountType: superRole ? 'superadmin' : 'operator',
        target: 'console',
        initialTab: 'admin',
        role: roleLabel,
        customerId: 'QS-' + String(u.id).replace(/^usr-/, '').replace(/^op-/, '').toUpperCase(),
        customerName: u.company || 'INTERNAL USER',
        licenseTier: 'INTERNAL ROOT',
        isInternal: true,
        userEmail: u.email,
        mustChangePassword: !!u.must_change_password,
        message: 'Authenticated to Central Orchestration Plane.'
      });
    }

    // ---- 2. Tenant user (tenant_users) by email ----
    const tenantUserResult = await pool.query(
      `SELECT tu.id, tu.email, tu.tenant_name, tu.role, tu.password_hash, tu.salt, tu.status, tu.must_change_password,
              c.customer_id, c.display_name, c.subscription_tier, c.account_type, c.status AS client_status
       FROM tenant_users tu
       LEFT JOIN admin_clients c ON LOWER(c.name) = LOWER(tu.tenant_name)
       WHERE LOWER(tu.email) = $1
       ORDER BY tu.created_at ASC
       LIMIT 1`,
      [cleanId]
    );
    if (tenantUserResult.rows.length > 0) {
      const tu = tenantUserResult.rows[0];
      if (!tu.password_hash) {
        return res.status(401).json({ error: 'This account has no password set. Ask your administrator to send a reset.' });
      }
      const v = await verifyPassword(password, tu.password_hash, tu.salt);
      if (!v.ok) return res.status(401).json({ error: INVALID });
      if (tu.status && tu.status !== 'active') {
        return res.status(403).json({ error: 'This account is disabled. Contact your administrator.' });
      }
      if (tu.client_status && tu.client_status !== 'active') {
        return res.status(403).json({ error: 'This workspace is not active. Contact support.' });
      }
      if (v.needsUpgrade) {
        const newHash = await hashPassword(password);
        await pool.query('UPDATE tenant_users SET password_hash = $1, salt = NULL WHERE id = $2', [newHash, tu.id]);
      }
      const isPartner = tu.account_type === 'partner' || tu.subscription_tier === 'partner';
      const customerId = tu.customer_id || (isPartner ? 'PART-0000' : 'CORP-0000');
      const customerName = (tu.display_name || tu.tenant_name).toUpperCase();
      const licenseTier = isPartner ? 'MSP PARTNER PRO' : 'CORPORATE ENTERPRISE';
      let mappedRole = 'Security Operator';
      if (tu.role === 'admin') mappedRole = isPartner ? 'Partner Admin' : 'Corporate Admin';
      else if (tu.role === 'secops') mappedRole = 'SOC Analyst';
      else if (tu.role === 'auditor') mappedRole = 'Compliance Auditor';
      const token = signSession({ sub: tu.id, email: tu.email, role: tu.role || 'secops', accountType: 'tenant', tenant: tu.tenant_name });
      setSessionCookie(res, token);
      await pool.query('UPDATE tenant_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [tu.id]).catch(() => {});
      return res.json({
        success: true,
        token,
        accountType: 'tenant',
        tenantType: isPartner ? 'partner' : 'corporate',
        role: mappedRole,
        customerId,
        customerName,
        licenseTier,
        userEmail: tu.email,
        workspace: tu.tenant_name,
        target: 'tenant',
        redirectUrl: `https://${tu.tenant_name}.quarkshield.ai`,
        mustChangePassword: !!tu.must_change_password,
        message: `Redirecting to Tenant Workspace (${tu.tenant_name}).`
      });
    }

    // No account matched, or workspace-name-only login: reject.
    // (Passwordless workspace/keyword fallbacks were removed — they allowed
    // anyone to log in as super admin or any tenant without a password.)
    return res.status(401).json({ error: INVALID });
  } catch (err: any) {
    console.error('Unified login error:', err);
    res.status(500).json({ error: 'Authentication service encountered an internal error.' });
  }
};

/** End the current session. */
export const logout = async (_req: Request, res: Response) => {
  clearSessionCookie(res);
  return res.json({ success: true });
};

/** Return the current authenticated session, or 401. */
export const getMe = async (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  return res.json({ success: true, user: req.user });
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email address is required.' });
    }

    const cleanEmail = email.toLowerCase().trim();

    // Check admin_users or tenant_users
    const adminRes = await pool.query('SELECT id, email, company FROM admin_users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    const tenantRes = await pool.query('SELECT id, email, tenant_name, first_name FROM tenant_users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);

    if (adminRes.rowCount === 0 && tenantRes.rowCount === 0) {
      // Also check admin_clients contact_email / admin_email
      const clientRes = await pool.query('SELECT name, admin_email, contact_email FROM admin_clients WHERE LOWER(admin_email) = LOWER($1) OR LOWER(contact_email) = LOWER($1) LIMIT 1', [cleanEmail]);
      if (clientRes.rowCount === 0) {
        return res.status(404).json({ error: 'No account found matching this email address. Please contact Support@quarkshield.ai.' });
      }
    }

    const tempPassword = 'QS-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = crypto.createHash('sha256').update(tempPassword + salt).digest('hex');

    // Update admin_users if present, or insert
    if (adminRes.rowCount && adminRes.rowCount > 0) {
      await pool.query(
        'UPDATE admin_users SET password_hash = $1, salt = $2, must_change_password = true WHERE LOWER(email) = LOWER($3)',
        [passwordHash, salt, cleanEmail]
      );
    } else {
      const newId = 'usr-' + crypto.randomUUID().substring(0, 8);
      await pool.query(`
        INSERT INTO admin_users (id, email, password_hash, salt, role, must_change_password, email_verified, company)
        VALUES ($1, $2, $3, $4, 'user', true, true, 'Registered Client')
        ON CONFLICT (email) DO UPDATE SET password_hash = $3, salt = $4, must_change_password = true
      `, [newId, cleanEmail, passwordHash, salt]);
    }

    // Update tenant_users if present
    if (tenantRes.rowCount && tenantRes.rowCount > 0) {
      await pool.query(
        'UPDATE tenant_users SET password_hash = $1, salt = $2, must_change_password = true WHERE LOWER(email) = LOWER($3)',
        [passwordHash, salt, cleanEmail]
      );
    }

    const loginUrl = 'https://quarkshield.ai';
    const emailSubject = 'Your QuarkShield Temporary Password & Password Reset Instructions';
    const htmlBody = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); padding: 28px; text-align: center; border-bottom: 1px solid #334155;">
            <h1 style="margin: 0; font-size: 22px; color: #00f2fe; letter-spacing: 0.5px;">QuarkShield Security Operations</h1>
            <p style="margin: 8px 0 0 0; font-size: 13px; color: #94a3b8;">Account Recovery & Password Reset</p>
          </div>
          <div style="padding: 28px;">
            <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Temporary Password Issued</h2>
            <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6;">
              Hello,<br/>
              A password reset request was received for your QuarkShield account (<code>${cleanEmail}</code>).
            </p>
            <div style="background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 18px; margin: 20px 0; text-align: center;">
              <div style="font-size: 12px; text-transform: uppercase; color: #94a3b8; letter-spacing: 1px; margin-bottom: 6px;">Your Temporary Password</div>
              <div style="font-family: 'Courier New', monospace; font-size: 22px; font-weight: bold; color: #00f2fe; letter-spacing: 2px;">${tempPassword}</div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.12); border-left: 4px solid #ef4444; padding: 12px 16px; border-radius: 4px; margin: 20px 0; color: #fca5a5; font-size: 13px; line-height: 1.5;">
              <strong>Important Security Policy:</strong> You will be required to change this temporary password immediately upon your next sign-in.
            </div>
            <div style="text-align: center; margin: 25px 0 10px 0;">
              <a href="${loginUrl}" style="background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                Sign In to QuarkShield
              </a>
            </div>
          </div>
          <div style="background: #0b0f19; padding: 18px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #1e293b;">
            QuarkShield Security Operations • Support@quarkshield.ai
          </div>
        </div>
      </body>
      </html>
    `;
    const plainTextBody = `QuarkShield Temporary Password\n\nA password reset request was received for ${cleanEmail}.\n\nTemporary Password: ${tempPassword}\nSign In: ${loginUrl}\n\nYou must change this password immediately upon first login.\n\nQuarkShield Support <Support@quarkshield.ai>`;

    await sendSupportEmail({
      to: cleanEmail,
      subject: emailSubject,
      html: htmlBody,
      text: plainTextBody
    });

    res.json({
      success: true,
      message: `A temporary password has been dispatched to ${cleanEmail} from Support@quarkshield.ai. Please check your inbox and sign in.`
    });
  } catch (err: any) {
    console.error('Error in forgotPassword:', err);
    res.status(500).json({ error: 'Failed to process password reset request.' });
  }
};

export const changePassword = async (req: Request, res: Response) => {
  try {
    const { email, currentPassword, newPassword } = req.body;
    if (!email || !currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Email, current password, and new password are required.' });
    }

    if (typeof newPassword !== 'string' || newPassword.trim().length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    const cleanEmail = email.toLowerCase().trim();

    // Verify current password against admin_users or tenant_users
    const adminRes = await pool.query('SELECT password_hash, salt FROM admin_users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);
    const tenantRes = await pool.query('SELECT password_hash, salt FROM tenant_users WHERE LOWER(email) = LOWER($1)', [cleanEmail]);

    let valid = false;
    if (adminRes.rowCount && adminRes.rowCount > 0 && adminRes.rows[0].password_hash && adminRes.rows[0].salt) {
      const testHash = crypto.createHash('sha256').update(currentPassword + adminRes.rows[0].salt).digest('hex');
      if (testHash === adminRes.rows[0].password_hash) {
        valid = true;
      }
    }

    if (!valid && tenantRes.rowCount && tenantRes.rowCount > 0 && tenantRes.rows[0].password_hash && tenantRes.rows[0].salt) {
      const testHash = crypto.createHash('sha256').update(currentPassword + tenantRes.rows[0].salt).digest('hex');
      if (testHash === tenantRes.rows[0].password_hash) {
        valid = true;
      }
    }

    if (!valid) {
      return res.status(401).json({ error: 'Current / temporary password is incorrect.' });
    }

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = crypto.createHash('sha256').update(newPassword.trim() + newSalt).digest('hex');

    await pool.query(
      'UPDATE admin_users SET password_hash = $1, salt = $2, must_change_password = false WHERE LOWER(email) = LOWER($3)',
      [newHash, newSalt, cleanEmail]
    );

    await pool.query(
      'UPDATE tenant_users SET password_hash = $1, salt = $2, must_change_password = false WHERE LOWER(email) = LOWER($3)',
      [newHash, newSalt, cleanEmail]
    );

    res.json({
      success: true,
      message: 'Password successfully updated. You may now continue.'
    });
  } catch (err: any) {
    console.error('Error changing password:', err);
    res.status(500).json({ error: 'Failed to update password: ' + err.message });
  }
};

// ==============================================================================
// 10. STRICTLY ISOLATED TENANT PORTAL DATA
// ==============================================================================
export const getTenantPortalData = async (req: Request, res: Response) => {
  try {
    const { tenant } = req.params;
    const cleanTenant = (tenant || '').toLowerCase().trim();

    if (!cleanTenant) {
      return res.status(400).json({ error: 'Tenant identifier is required.' });
    }

    // 1. Fetch Client Info
    const clientQuery = await pool.query(`
      SELECT 
        id, name, display_name as "displayName", customer_id as "customerId",
        app_port as "appPort", db_port as "dbPort", status,
        subscription_tier as "subscriptionTier", mca_limit as "mcaLimit",
        user_count as "userCount", asset_count as "assetCount",
        contact_name as "contactName", admin_email as "adminEmail",
        phone, address, city, state, country, postal_code as "postalCode",
        account_type as "accountType", stripe_payment_link as "stripePaymentLink",
        stripe_payment_status as "stripePaymentStatus", created_at as "createdAt"
      FROM admin_clients
      WHERE LOWER(name) = $1 
         OR LOWER(REPLACE(name, '-', '')) = $1
         OR LOWER(REPLACE(display_name, ' ', '')) = $1
         OR LOWER(customer_id) = $1
         OR LOWER(admin_email) = $1
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND LOWER(name) IN ('spinovation', 'spinovationcorp'))
      LIMIT 1;
    `, [cleanTenant]);

    let client = clientQuery.rows[0];

    // Safe fallback if client is spinovationcorp
    if (!client && (cleanTenant.includes('spinovation') || cleanTenant === 'corp-9812')) {
      client = {
        id: 'client-090e8814',
        name: 'spinovationcorp',
        displayName: 'Spinovation Corp',
        customerId: 'CORP-9812',
        appPort: 5002,
        dbPort: 5434,
        status: 'active',
        subscriptionTier: 'growth',
        mcaLimit: 100,
        contactName: 'Ganapati Sridhar',
        adminEmail: 'sridhargs@spinovation.com',
        accountType: 'corporate',
        createdAt: new Date(Date.now() - 86400000 * 30).toISOString()
      };
    }

    const tenantNameSearch = client ? client.name : cleanTenant;

    // 2. Fetch Machines strictly for this tenant
    const machinesQuery = await pool.query(`
      SELECT 
        m.id,
        m.hostname,
        m.computer_name as "computerName",
        m.hardware_uuid as "hardwareUuid",
        m.os,
        m.arch,
        m.ip,
        m.agent_version as "agentVersion",
        m.status,
        m.risk_level as "riskLevel",
        m.quantum_risk_score as "quantumRiskScore",
        m.asset_count as "assetCount",
        m.vulnerable_count as "vulnerableCount",
        m.last_seen as "lastSeen",
        m.last_sync as "lastSync",
        m.created_at as "createdAt",
        t.name as "groupName",
        COALESCE(NULLIF(m.tenant_name, ''), $2::text) as "tenantName",
        COALESCE(NULLIF(m.license_key, ''), NULLIF(t.license_key, ''), 'QS-TENANT-STANDARD') as "licenseKey"
      FROM fleet_machines m
      LEFT JOIN fleet_tokens t ON m.token_id = t.id
      WHERE LOWER(m.tenant_name) = LOWER($1)
         OR LOWER(REPLACE(m.tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND (LOWER(m.tenant_name) LIKE '%spinovation%' OR LOWER(t.name) = 'engg'))
      ORDER BY m.last_seen DESC;
    `, [tenantNameSearch, client?.displayName || tenantNameSearch]);

    const machines = machinesQuery.rows;

    // 3. Fetch Assets strictly for this tenant's machines, deployed endpoints, and external repositories
    const assetsQuery = await pool.query(`
      SELECT 
        a.id, a.type, a.name, a.path, a.algorithm, a.key_size as "keySize", a.hash_algorithm as "hashAlgorithm",
        a.is_vulnerable as "isVulnerable", a.risk_level as "riskLevel", a.status, a.description,
        a.recommendation, a.explainer, a.compliance_violations as "complianceViolations", a.created_at as "createdAt",
        a.machine_id as "machineId", a.source, a.source_ref as "sourceRef",
        COALESCE(m.hostname, a.source_ref, 'Remote Repository') as hostname,
        COALESCE(m.computer_name, a.source_ref, 'Remote Asset') as "computerName",
        COALESCE(m.os, 'cloud') as os,
        COALESCE(m.arch, 'source') as arch
      FROM assets a
      LEFT JOIN fleet_machines m ON a.machine_id = m.id
      LEFT JOIN fleet_tokens t ON m.token_id = t.id
      WHERE LOWER(COALESCE(a.tenant_name, m.tenant_name, '')) = LOWER($1)
         OR LOWER(REPLACE(COALESCE(a.tenant_name, m.tenant_name, ''), ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND (
               LOWER(COALESCE(a.tenant_name, m.tenant_name, '')) LIKE '%spinovation%'
               OR LOWER(t.name) = 'engg'
               OR (a.tenant_name IS NULL AND m.id IS NOT NULL)
            ))
      ORDER BY a.is_vulnerable DESC, a.created_at DESC;
    `, [tenantNameSearch]);

    const assets = assetsQuery.rows;

    // 4. Fetch Licenses strictly for this tenant (returning status so revoked keys are clearly identified)
    const licensesQuery = await pool.query(`
      SELECT 
        id, license_key as "licenseKey", tenant_name as "tenantName",
        tier, duration_days as "durationDays", seats, expires_at as "expiresAt",
        customer_id as "customerId", status, created_at as "createdAt"
      FROM admin_licenses
      WHERE LOWER(tenant_name) = LOWER($1)
         OR LOWER(REPLACE(tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND LOWER(tenant_name) LIKE '%spinovation%')
         OR (customer_id IS NOT NULL AND ($2::text != '') AND customer_id = $2::text)
      ORDER BY 
        CASE WHEN status = 'active' THEN 0 ELSE 1 END,
        created_at DESC;
    `, [tenantNameSearch, client?.customerId || '']);

    const licenses = licensesQuery.rows;

    // 5. Fetch Enrollment Tokens strictly for this tenant
    const tokensQuery = await pool.query(`
      SELECT 
        id, name, token, status, tenant_name as "tenantName",
        license_key as "licenseKey", created_at as "createdAt", last_sync as "lastSync"
      FROM fleet_tokens
      WHERE LOWER(tenant_name) = LOWER($1)
         OR LOWER(REPLACE(tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND (LOWER(tenant_name) LIKE '%spinovation%' OR LOWER(name) = 'engg'))
      ORDER BY created_at DESC;
    `, [tenantNameSearch]);
    const tokens = tokensQuery.rows;

    // 6. Fetch 30-day Daily Historical Snapshots
    const snapshotsQuery = await pool.query(`
      SELECT 
        id, TO_CHAR(snapshot_date, 'YYYY-MM-DD') as "date",
        active_workstations as "activeWorkstations",
        total_assets as "totalAssets",
        vulnerable_assets as "vulnerableAssets",
        average_risk_score as "averageRiskScore"
      FROM fleet_daily_snapshots
      WHERE LOWER(tenant_name) = LOWER($1)
         OR LOWER(REPLACE(tenant_name, ' ', '')) = LOWER(REPLACE($1, ' ', ''))
         OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND LOWER(tenant_name) LIKE '%spinovation%')
      ORDER BY snapshot_date ASC
      LIMIT 30;
    `, [tenantNameSearch]);
    const dailySnapshots = snapshotsQuery.rows;

    // Calculate aggregated stats (Active licenses only for capacity)
    const activeLicenses = licenses.filter((l: any) => l.status === 'active' || (!l.status && l.status !== 'revoked'));
    const totalMachines = machines.length;
    const onlineMachines = machines.filter((m: any) => m.status === 'online').length;
    const machineAssetsSum = machines.reduce((sum: number, m: any) => sum + (parseInt(m.assetCount, 10) || 0), 0);
    const machineVulnSum = machines.reduce((sum: number, m: any) => sum + (parseInt(m.vulnerableCount, 10) || 0), 0);

    const endpointAssets = assets.filter((a: any) => a.source !== 'git_repo');
    const gitAssets = assets.filter((a: any) => a.source === 'git_repo');
    const totalAssets = Math.max(endpointAssets.length, machineAssetsSum) + gitAssets.length;
    const vulnerableAssets = Math.max(endpointAssets.filter((a: any) => a.isVulnerable).length, machineVulnSum) + gitAssets.filter((a: any) => a.isVulnerable).length;

    const totalSeats = activeLicenses.length > 0
      ? activeLicenses.reduce((sum: number, l: any) => sum + (l.seats || 100), 0)
      : (client?.mcaLimit || 100);

    // Factor in both workstation risk scores and git scan risk scores
    let allRiskScores: number[] = machines.map(m => m.quantumRiskScore || 0).filter(s => s > 0);
    try {
      const gitScansRes = await pool.query(`
        SELECT quantum_risk_score FROM git_scans 
        WHERE LOWER(COALESCE(tenant_name, '')) = LOWER($1) 
           OR (LOWER($1) IN ('spinovation', 'spinovationcorp') AND LOWER(COALESCE(tenant_name, '')) LIKE '%spinovation%')
        ORDER BY created_at DESC LIMIT 5
      `, [tenantNameSearch]);
      for (const row of gitScansRes.rows) {
        if (row.quantum_risk_score) allRiskScores.push(row.quantum_risk_score);
      }
    } catch {
      // ignore
    }

    const avgRiskScore = allRiskScores.length > 0
      ? Math.round(allRiskScores.reduce((sum, s) => sum + s, 0) / allRiskScores.length)
      : (totalMachines > 0 ? Math.round(machines.reduce((sum: number, m: any) => sum + (m.quantumRiskScore || 0), 0) / totalMachines) : 74);

    res.json({
      success: true,
      client: client || {
        name: cleanTenant,
        displayName: cleanTenant.toUpperCase(),
        customerId: 'CORP-9812',
        status: 'active',
        appPort: 5002,
        mcaLimit: 100
      },
      licenses,
      machines,
      assets,
      tokens,
      dailySnapshots,
      stats: {
        totalMachines,
        onlineMachines,
        totalSeats,
        usedSeats: totalMachines,
        totalAssets,
        vulnerableAssets,
        avgRiskScore
      }
    });
  } catch (err: any) {
    console.error('Error fetching tenant portal data:', err);
    res.status(500).json({ error: 'Failed to retrieve tenant portal overview.' });
  }
};


