import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import { sendSupportEmail } from './adminController';

interface Attachment { name: string; size: number; type: string; data?: string }
interface SupportTicketBody {
  name?: string;
  email?: string;
  userEmail?: string;
  subject?: string;
  message?: string;
  attachments?: Attachment[];
}

const MAX_ATTACHMENTS = 5;
const MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024;   // per file
const MAX_TOTAL_BYTES = 18 * 1024 * 1024;        // all files (under the 20MB body limit)
const SUPPORT_INBOX = process.env.SUPPORT_INBOX || 'support@quarkshield.ai';

const isEmail = (s: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

export const submitSupportTicket = async (req: Request, res: Response) => {
  try {
    const body: SupportTicketBody = req.body || {};
    const { name, email, userEmail, subject, message, attachments } = body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message content is required.' });
    }

    const senderEmail = (email?.trim() || userEmail?.trim() || 'anonymous@quarkshield.ai');
    if (senderEmail !== 'anonymous@quarkshield.ai' && !isEmail(senderEmail)) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }

    // Validate attachments (count, per-file and total size) before storing.
    const atts = Array.isArray(attachments) ? attachments : [];
    if (atts.length > MAX_ATTACHMENTS) {
      return res.status(400).json({ error: `At most ${MAX_ATTACHMENTS} attachments are allowed.` });
    }
    let total = 0;
    for (const a of atts) {
      const bytes = a.data ? Buffer.byteLength(a.data, 'base64') : (a.size || 0);
      if (bytes > MAX_ATTACHMENT_BYTES) {
        return res.status(400).json({ error: `Attachment "${a.name}" exceeds the 15 MB limit.` });
      }
      total += bytes;
    }
    if (total > MAX_TOTAL_BYTES) {
      return res.status(400).json({ error: 'Attachments exceed the 18 MB total limit.' });
    }

    const ticketId = `qs_tkt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const senderName = name?.trim() || (senderEmail.includes('@') ? senderEmail.split('@')[0] : 'Workstation User');
    const ticketSubject = subject?.trim() || 'Feedback';
    const ticketMessage = message.trim();

    // Persist the ticket and each attachment's bytes (tables come from schema.sql).
    await pool.query(
      `INSERT INTO support_tickets (id, name, email, subject, message, attachment_count, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'open')`,
      [ticketId, senderName, senderEmail, ticketSubject, ticketMessage, atts.length]
    );
    for (const a of atts) {
      await pool.query(
        `INSERT INTO support_ticket_attachments (id, ticket_id, filename, mime_type, size_bytes, data_base64)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        ['att_' + crypto.randomBytes(6).toString('hex'), ticketId, String(a.name || 'attachment').slice(0, 255), String(a.type || 'application/octet-stream').slice(0, 100), a.data ? Buffer.byteLength(a.data, 'base64') : (a.size || 0), a.data || null]
      );
    }

    // Notify the support inbox (best-effort; does not fail the request).
    sendSupportEmail({
      to: SUPPORT_INBOX,
      subject: `[Support] ${ticketSubject} — ${ticketId}`,
      text: `New support request ${ticketId}\nFrom: ${senderName} <${senderEmail}>\nSubject: ${ticketSubject}\nAttachments: ${atts.length}\n\n${ticketMessage}`,
      html: `<p><b>New support request</b> ${ticketId}</p><p>From: ${senderName} &lt;${senderEmail}&gt;<br>Subject: ${ticketSubject}<br>Attachments: ${atts.length}</p><pre style="white-space:pre-wrap">${ticketMessage.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c] || c))}</pre>`,
    }).catch(e => console.warn('Support notification email failed:', e?.message));

    console.log(`[SUPPORT] ${ticketId} from ${senderEmail} (${atts.length} attachment(s))`);
    return res.status(200).json({
      success: true,
      ticketId,
      attachmentsStored: atts.length,
      message: 'Support request received. Our team will follow up.',
    });
  } catch (err: any) {
    console.error('Error submitting support ticket:', err);
    return res.status(500).json({ error: 'Failed to submit support request. Please try again.' });
  }
};
