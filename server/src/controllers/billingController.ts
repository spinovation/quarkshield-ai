import { Request, Response } from 'express';
import Stripe from 'stripe';
import crypto from 'crypto';
import pool from '../config/db';

const APP_HOST = process.env.APP_HOST_URL || 'https://quarkshield.ai';

const getStripe = (): Stripe => {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error('STRIPE_SECRET_KEY is not configured in server environment.');
  }
  return new Stripe(key);
};

export interface PlanTierConfig {
  tier: 'entry' | 'growth' | 'enterprise';
  displayName: string;
  monthlyAmountCents: number;
  annualAmountCents: number;
  seatLimit: number;
  description: string;
}

export const QUARKSHIELD_PLANS: Record<string, PlanTierConfig> = {
  entry: {
    tier: 'entry',
    displayName: 'QuarkShield Entry — PQC Assessment',
    monthlyAmountCents: 30000, // $300/mo
    annualAmountCents: 300000, // $3,000/yr ($600 savings)
    seatLimit: 5,
    description: '5 Workstation/Server endpoint licenses, executive Quantum Risk Score, and CycloneDX 1.6 CBOM export.'
  },
  scale: {
    tier: 'growth',
    displayName: 'QuarkShield Scale — Growth Fleet',
    monthlyAmountCents: 250000, // $2,500/mo
    annualAmountCents: 2500000, // $25,000/yr ($5,000 savings)
    seatLimit: 50,
    description: 'Up to 50 monitored fleet endpoints, automated cryptographic drift detection, MDM group tokens, real-time alerts.'
  },
  enterprise: {
    tier: 'enterprise',
    displayName: 'QuarkShield Enterprise — Enterprise Pro',
    monthlyAmountCents: 1000000, // $10,000/mo
    annualAmountCents: 10000000, // $100,000/yr ($20,000 savings)
    seatLimit: 250,
    description: 'Up to 250 hybrid enterprise endpoints, Remote Git scanner, full QS Copilot AI, dedicated tenant subdomain, 2FA.'
  }
};

const getLicenseSecret = (): string => {
  const s = process.env.LICENSE_SIGNING_SECRET;
  if (s && s.length >= 16) return s;
  return 'dev-insecure-license-secret-change-me';
};

const computeLicenseSig = (tier: string, tenant: string, expiryHex: string): string => {
  const hmac = crypto.createHmac('sha256', getLicenseSecret());
  hmac.update(`${tier}:${tenant}:${expiryHex}`);
  return hmac.digest('hex').substring(0, 8).toUpperCase();
};

/**
 * POST /api/billing/checkout
 * Initiates public Stripe checkout session for Entry, Scale, or Enterprise subscriptions.
 */
export const createCheckoutSession = async (req: Request, res: Response) => {
  try {
    const { tier = 'scale', billingInterval = 'monthly', companyName, contactName, email } = req.body;

    if (!email || !companyName) {
      return res.status(400).json({ error: 'Company name and corporate email address are required.' });
    }

    const cleanTierKey = String(tier).toLowerCase();
    const plan = QUARKSHIELD_PLANS[cleanTierKey] || QUARKSHIELD_PLANS['scale'];
    const isAnnual = billingInterval === 'annual';
    const amountCents = isAnnual ? plan.annualAmountCents : plan.monthlyAmountCents;
    const intervalStr = isAnnual ? 'year' : 'month';

    const stripe = getStripe();
    const cleanSubdomain = companyName.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 24) || 'tenant';
    const regId = 'reg-' + crypto.randomUUID().substring(0, 8);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [
        {
          price_data: {
            currency: 'usd',
            unit_amount: amountCents,
            recurring: {
              interval: intervalStr
            },
            product_data: {
              name: plan.displayName,
              description: plan.description,
              metadata: {
                tier: plan.tier,
                seats: String(plan.seatLimit)
              }
            }
          },
          quantity: 1
        }
      ],
      customer_email: email.toLowerCase().trim(),
      subscription_data: {
        trial_period_days: 14,
        metadata: {
          companyName: companyName.trim(),
          tier: plan.tier,
          seats: String(plan.seatLimit),
          subdomain: cleanSubdomain
        }
      },
      metadata: {
        registrationId: regId,
        companyName: companyName.trim(),
        contactName: (contactName || '').trim(),
        email: email.toLowerCase().trim(),
        tier: plan.tier,
        billingInterval: isAnnual ? 'annual' : 'monthly',
        subdomain: cleanSubdomain,
        seats: String(plan.seatLimit)
      },
      success_url: `${APP_HOST}/signup-result.html?status=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_HOST}/#pricing`
    });

    // Record pending registration
    await pool.query(
      `INSERT INTO pending_registrations 
       (id, stripe_session_id, email, company_name, contact_name, tier, billing_interval, subdomain, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
       ON CONFLICT (stripe_session_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`,
      [regId, session.id, email.toLowerCase().trim(), companyName.trim(), contactName?.trim() || null, plan.tier, isAnnual ? 'annual' : 'monthly', cleanSubdomain]
    );

    res.json({
      success: true,
      sessionId: session.id,
      checkoutUrl: session.url
    });
  } catch (err: any) {
    console.error('Error creating Stripe checkout session:', err);
    res.status(500).json({ error: 'Could not initialize Stripe checkout: ' + err.message });
  }
};

/**
 * GET /api/billing/registration-status/:sessionId
 * Polls the fulfillment state of a completed checkout session.
 */
export const getRegistrationStatus = async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    const result = await pool.query(
      `SELECT * FROM pending_registrations WHERE stripe_session_id = $1 LIMIT 1`,
      [sessionId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Checkout registration session not found.' });
    }

    const reg = result.rows[0];
    res.json({
      status: reg.status,
      clientId: reg.result_client_id,
      licenseKey: reg.result_license_key,
      subdomain: reg.subdomain,
      failureReason: reg.failure_reason,
      createdAt: reg.created_at
    });
  } catch (err: any) {
    console.error('Error checking registration status:', err);
    res.status(500).json({ error: 'Failed to retrieve registration status.' });
  }
};

/**
 * POST /api/billing/custom-checkout
 * Super Admin creates bespoke one-off or recurring Stripe payment link for enterprise/MSP contracts.
 */
export const createCustomCheckoutSession = async (req: Request, res: Response) => {
  try {
    const {
      customerName,
      customerEmail,
      description,
      amountDollars,
      recurring = false,
      interval = 'month',
      tier = 'enterprise',
      seats = 100
    } = req.body;

    if (!customerEmail || !description || !amountDollars) {
      return res.status(400).json({ error: 'Customer email, description, and dollar amount are required.' });
    }

    const amountCents = Math.round(parseFloat(amountDollars) * 100);
    if (isNaN(amountCents) || amountCents <= 0) {
      return res.status(400).json({ error: 'Valid positive amount in dollars is required.' });
    }

    const inviteId = 'inv-' + crypto.randomUUID().substring(0, 8);
    const stripe = getStripe();

    const priceData: Stripe.Checkout.SessionCreateParams.LineItem.PriceData = {
      currency: 'usd',
      unit_amount: amountCents,
      product_data: {
        name: description,
        description: `QuarkShield PQC Enterprise License (${seats} Seats • ${tier.toUpperCase()})`
      },
      ...(recurring ? { recurring: { interval: interval === 'year' ? 'year' : 'month' } } : {})
    };

    const session = await stripe.checkout.sessions.create({
      mode: recurring ? 'subscription' : 'payment',
      line_items: [{ price_data: priceData, quantity: 1 }],
      customer_email: customerEmail.toLowerCase().trim(),
      success_url: `${APP_HOST}/signup-result.html?status=success&custom=1&invite_id=${inviteId}`,
      cancel_url: `${APP_HOST}/#pricing`,
      metadata: {
        customCheckoutInviteId: inviteId,
        customerName: customerName || '',
        customerEmail: customerEmail.toLowerCase().trim(),
        tier,
        seats: String(seats)
      }
    });

    await pool.query(
      `INSERT INTO custom_checkout_invites 
       (id, customer_name, customer_email, description, amount_cents, recurring, billing_interval, checkout_url, stripe_session_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'created')`,
      [
        inviteId,
        customerName?.trim() || null,
        customerEmail.toLowerCase().trim(),
        description.trim(),
        amountCents,
        !!recurring,
        recurring ? interval : null,
        session.url,
        session.id
      ]
    );

    res.json({
      success: true,
      inviteId,
      checkoutUrl: session.url
    });
  } catch (err: any) {
    console.error('Error generating custom checkout session:', err);
    res.status(500).json({ error: 'Could not create custom checkout link: ' + err.message });
  }
};

/**
 * POST /api/billing/custom-checkout/:id/send
 * Dispatches the custom Stripe checkout link email to the client via system mailer.
 */
export const sendCustomCheckoutEmail = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { subject, emailBody } = req.body;

    const result = await pool.query(
      `SELECT * FROM custom_checkout_invites WHERE id = $1 LIMIT 1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Custom checkout invite not found.' });
    }

    const invite = result.rows[0];
    const emailSubject = subject || `QuarkShield Enterprise PQC Agreement & Payment Link`;
    const emailContent = emailBody || `Hello ${invite.customer_name || 'Partner'},\n\n` +
      `Thank you for choosing QuarkShield as your Cryptographic Observability and PQC Migration platform.\n\n` +
      `Your bespoke commercial package (${invite.description}) is ready. Please complete your subscription and payment securely via the link below:\n\n` +
      `${invite.checkout_url}\n\n` +
      `Upon completion, your workspace, cryptographic license keys, and fleet enrollment tokens will be provisioned immediately.\n\n` +
      `Best regards,\nQuarkShield Commercial Operations\nhttps://quarkshield.ai`;

    // Mark as sent
    await pool.query(
      `UPDATE custom_checkout_invites 
       SET status = CASE WHEN status = 'paid' THEN status ELSE 'sent' END,
           email_subject = $1, email_body = $2, sent_at = CURRENT_TIMESTAMP
       WHERE id = $3`,
      [emailSubject, emailContent, id]
    );

    // Resolve Resend API Key & dispatch live email if configured
    let resendApiKey = process.env.RESEND_API_KEY || '';
    let resendSender = process.env.RESEND_SENDER_EMAIL || 'License@quarkshield.ai';
    try {
      const sRes = await pool.query("SELECT key, value FROM tenant_settings WHERE key IN ('RESEND_API_KEY', 'RESEND_SENDER_EMAIL')");
      for (const row of sRes.rows) {
        if (row.key === 'RESEND_API_KEY' && row.value) resendApiKey = row.value;
        if (row.key === 'RESEND_SENDER_EMAIL' && row.value) resendSender = row.value;
      }
    } catch (_) {}

    let resendSuccess = false;
    let resendError = null;

    if (resendApiKey) {
      try {
        const formattedAmount = (invite.amount_cents / 100).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
        const htmlBody = `
          <div style="background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 40px 20px; color: #f8fafc;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #111827; border: 1px solid rgba(0, 242, 254, 0.2); border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
              <div style="text-align: center; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 24px; margin-bottom: 24px;">
                <div style="font-size: 26px; font-weight: 800; color: #00f2fe; letter-spacing: 0.04em;">QUARKSHIELD</div>
                <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Enterprise Post-Quantum Cryptography (PQC) Commercial Agreement</div>
              </div>
              <p style="font-size: 15px; color: #e2e8f0; margin-bottom: 12px;">Hello <strong>${invite.customer_name || 'Enterprise Partner'}</strong>,</p>
              <p style="font-size: 14px; color: #94a3b8; line-height: 1.6; margin-bottom: 20px;">
                Thank you for choosing QuarkShield. Your tailored commercial package has been prepared and is ready for activation.
              </p>
              
              <div style="background: #030712; border: 1px solid rgba(0, 242, 254, 0.3); border-radius: 8px; padding: 18px; margin: 20px 0;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                  <tr><td style="padding: 6px 0; color: #64748b;">Package:</td><td style="padding: 6px 0; color: #ffffff; font-weight: 600; text-align: right;">${invite.description}</td></tr>
                  <tr><td style="padding: 6px 0; color: #64748b;">Amount:</td><td style="padding: 6px 0; color: #38bdf8; font-weight: 700; text-align: right; font-size: 15px;">${formattedAmount} ${invite.recurring ? `/${invite.billing_interval || 'month'}` : '(One-time)'}</td></tr>
                  <tr><td style="padding: 6px 0; color: #64748b;">Invoice Reference:</td><td style="padding: 6px 0; color: #a855f7; font-family: monospace; text-align: right;">${invite.id}</td></tr>
                </table>
              </div>

              <div style="text-align: center; margin: 28px 0;">
                <a href="${invite.checkout_url}" style="display: inline-block; background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); color: #000; font-weight: 800; padding: 12px 28px; border-radius: 6px; text-decoration: none; font-size: 14px; box-shadow: 0 4px 15px rgba(0, 242, 254, 0.4);">
                  Complete Secure Payment on Stripe &rarr;
                </a>
              </div>

              <p style="font-size: 12px; color: #94a3b8; line-height: 1.5;">
                Upon completing payment, your tenant console, cryptographic HMAC-SHA256 licenses, and enrollment tokens will be activated automatically.
              </p>

              <div style="text-align: center; margin-top: 32px; font-size: 11px; color: #64748b; line-height: 1.5; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
                QuarkShield Commercial Operations &bull; https://quarkshield.ai &bull; billing@quarkshield.ai
              </div>
            </div>
          </div>
        `;

        const mailRes = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${resendApiKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: resendSender,
            to: [invite.customer_email],
            subject: emailSubject,
            html: htmlBody
          })
        });

        if (mailRes.ok) {
          resendSuccess = true;
        } else {
          const errData = await mailRes.text();
          resendError = errData;
          console.warn('Resend mail error for custom checkout:', errData);
        }
      } catch (mErr: any) {
        resendError = mErr.message;
        console.warn('Failed to call Resend API for custom checkout:', mErr);
      }
    }

    res.json({
      success: true,
      message: resendSuccess
        ? `Payment link successfully dispatched via email to ${invite.customer_email}`
        : `Payment link recorded. (Email direct send ${resendApiKey ? 'warning: ' + resendError : 'skipped: configure Resend API Key in Admin Panel'})`,
      recipient: invite.customer_email,
      checkoutUrl: invite.checkout_url,
      resendDelivered: resendSuccess
    });
  } catch (err: any) {
    console.error('Error sending custom checkout email:', err);
    res.status(500).json({ error: 'Failed to send checkout email: ' + err.message });
  }
};

/**
 * GET /api/billing/custom-checkout/invites
 * Lists custom Stripe deals generated by Super Admin.
 */
export const getCustomCheckoutInvites = async (_req: Request, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT id, customer_name as "customerName", customer_email as "customerEmail",
              description, amount_cents as "amountCents", recurring, billing_interval as "billingInterval",
              checkout_url as "checkoutUrl", status, email_subject as "emailSubject",
              sent_at as "sentAt", paid_at as "paidAt", created_at as "createdAt"
       FROM custom_checkout_invites 
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error retrieving custom checkout invites:', err);
    res.status(500).json({ error: 'Failed to retrieve custom checkout invites.' });
  }
};

/**
 * POST /api/billing/portal-session
 * Generates a self-service Stripe Customer Portal session for authenticated tenants to manage payment cards and invoices.
 */
export const createCustomerPortalSession = async (req: Request, res: Response) => {
  try {
    const tenant = (req as any).user?.tenant;
    if (!tenant) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const clientRes = await pool.query(
      `SELECT stripe_customer_id, admin_email, name, display_name FROM admin_clients 
       WHERE LOWER(name) = LOWER($1) OR LOWER(display_name) = LOWER($1) LIMIT 1`,
      [tenant]
    );

    let customerId = clientRes.rows[0]?.stripe_customer_id;
    const stripe = getStripe();

    if (!customerId) {
      const email = clientRes.rows[0]?.admin_email;
      if (email) {
        const customers = await stripe.customers.list({ email: email.toLowerCase().trim(), limit: 1 });
        if (customers.data.length > 0) {
          customerId = customers.data[0].id;
          await pool.query(
            `UPDATE admin_clients SET stripe_customer_id = $1 WHERE LOWER(name) = LOWER($2)`,
            [customerId, tenant]
          );
        }
      }
    }

    if (!customerId) {
      return res.status(404).json({
        error: 'No active Stripe billing profile found for this tenant. Subscriptions provisioned manually or via ACH can be managed with support.'
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${APP_HOST}`
    });

    res.json({ success: true, portalUrl: session.url });
  } catch (err: any) {
    console.error('Error initializing Stripe Customer Portal session:', err);
    res.status(500).json({ error: 'Could not open billing portal: ' + err.message });
  }
};

/**
 * Internal helper to fulfill a successful checkout session:
 * Creates client, provisions cryptographic license key, and generates fleet token.
 */
async function fulfillPaidRegistration(session: Stripe.Checkout.Session) {
  const meta = session.metadata || {};
  const companyName = meta.companyName || session.customer_details?.name || 'Enterprise Client';
  const email = (meta.email || session.customer_details?.email || '').toLowerCase().trim();
  const contactName = meta.contactName || session.customer_details?.name || 'Client Administrator';
  const tier = (meta.tier || 'growth').toLowerCase();
  const seats = parseInt(meta.seats || '50', 10);
  const billingInterval = meta.billingInterval || 'monthly';

  const cleanSlug = (meta.subdomain || companyName.toLowerCase().replace(/[^a-z0-9]/g, '')).substring(0, 24) || 'tenant';
  const customerId = (tier === 'partner' ? 'PART-' : 'CORP-') + Math.floor(1000 + Math.random() * 9000);
  const clientId = 'cli-' + crypto.randomUUID().substring(0, 8);
  const stripeCustId = typeof session.customer === 'string' ? session.customer : session.customer?.id;
  const stripeSubId = typeof session.subscription === 'string' ? session.subscription : session.subscription?.id;

  // 1. Provision or update admin_clients
  await pool.query(
    `INSERT INTO admin_clients 
     (id, name, display_name, status, subscription_tier, mca_limit, account_type, customer_id, admin_email, contact_name, stripe_customer_id, stripe_subscription_id, stripe_payment_status, stripe_payment_link, billing_interval)
     VALUES ($1, $2, $3, 'active', $4, $5, 'corporate', $6, $7, $8, $9, $10, 'paid', $11, $12)
     ON CONFLICT (name) DO UPDATE SET 
       status = 'active',
       subscription_tier = $4,
       mca_limit = $5,
       stripe_customer_id = COALESCE($9, admin_clients.stripe_customer_id),
       stripe_subscription_id = COALESCE($10, admin_clients.stripe_subscription_id),
       stripe_payment_status = 'paid',
       updated_at = CURRENT_TIMESTAMP`,
    [
      clientId,
      cleanSlug,
      companyName,
      tier,
      seats,
      customerId,
      email,
      contactName,
      stripeCustId || null,
      stripeSubId || null,
      session.url || null,
      billingInterval
    ]
  );

  // 2. Generate cryptographically signed Enterprise / Growth License Key
  const cleanTier = tier.toUpperCase() === 'ENTERPRISE' ? 'CORP' : (tier.toUpperCase() === 'PARTNER' ? 'PARTNER' : 'CORP');
  const cleanTenant = cleanSlug.toUpperCase();
  const durationDays = billingInterval === 'annual' ? 365 : 30;
  const expiresAt = new Date(Date.now() + durationDays * 86400000);
  const expiryHex = Math.floor(expiresAt.getTime() / 1000).toString(16).toUpperCase();
  const sig = computeLicenseSig(cleanTier, cleanTenant, expiryHex);
  const licenseKey = `QS-${cleanTier}-${cleanTenant}-${expiryHex}-${sig}`;
  const licenseId = crypto.randomUUID();

  await pool.query(
    `INSERT INTO admin_licenses 
     (id, license_key, tenant_name, customer_id, tier, duration_days, seats, status, expires_at, contact_name, contact_email)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10)
     ON CONFLICT (id) DO NOTHING`,
    [licenseId, licenseKey, cleanSlug, customerId, tier, durationDays, seats, expiresAt, contactName, email]
  );

  // 3. Generate initial Fleet Enrollment Token
  const tokenVal = 'qs_flt_' + crypto.randomBytes(16).toString('hex');
  const tokenId = 'tok-' + crypto.randomUUID().substring(0, 8);
  await pool.query(
    `INSERT INTO fleet_tokens (id, name, token, max_machines, machine_count, tenant_name, license_key, expires_at)
     VALUES ($1, $2, $3, $4, 0, $5, $6, $7)
     ON CONFLICT (id) DO NOTHING`,
    [tokenId, `${companyName} Initial Fleet Token`, tokenVal, seats, cleanSlug, licenseKey, expiresAt]
  );

  // 4. Update pending registration record
  if (meta.registrationId || session.id) {
    await pool.query(
      `UPDATE pending_registrations 
       SET status = 'completed', result_client_id = $1, result_license_key = $2, subdomain = $3, updated_at = CURRENT_TIMESTAMP
       WHERE stripe_session_id = $4 OR id = $5`,
      [clientId, licenseKey, cleanSlug, session.id, meta.registrationId || '']
    );
  }

  console.log(`✅ QuarkShield Stripe Billing Fulfilled: Tenant ${cleanSlug} activated with license ${licenseKey}`);
}

/**
 * POST /api/billing/webhook
 * Stripe webhook handler for subscription events and checkout fulfillment.
 */
export const handleStripeWebhook = async (req: Request, res: Response) => {
  const signature = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event: Stripe.Event;

  try {
    const stripe = getStripe();
    if (webhookSecret && typeof signature === 'string') {
      event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    } else {
      // In dev or test environments without webhook secret, parse payload directly
      const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      event = payload as Stripe.Event;
    }
  } catch (err: any) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object as Stripe.Checkout.Session;
        if (session.metadata?.customCheckoutInviteId) {
          const inviteId = session.metadata.customCheckoutInviteId;
          await pool.query(
            `UPDATE custom_checkout_invites SET status = 'paid', paid_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [inviteId]
          );
        } else {
          await fulfillPaidRegistration(session);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const sub = event.data.object as Stripe.Subscription;
        await pool.query(
          `UPDATE admin_clients SET status = 'suspended' WHERE stripe_subscription_id = $1`,
          [sub.id]
        );
        break;
      }
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object as Stripe.Invoice;
        const subId = typeof (invoice as any).subscription === 'string' ? (invoice as any).subscription : (invoice as any).subscription?.id;
        if (subId) {
          await pool.query(
            `UPDATE admin_clients SET stripe_payment_status = 'paid' WHERE stripe_subscription_id = $1`,
            [subId]
          );
        }
        break;
      }
      default:
        // Ignore unhandled event types
        break;
    }
  } catch (procErr: any) {
    console.error(`Error processing Stripe webhook event ${event.type}:`, procErr);
  }

  res.json({ received: true });
};
