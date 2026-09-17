import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';

interface SupportTicketBody {
  name?: string;
  email?: string;
  userEmail?: string;
  subject?: string;
  message?: string;
  attachments?: Array<{ name: string; size: number; type: string; data?: string }>;
}

export const submitSupportTicket = async (req: Request, res: Response) => {
  try {
    const body: SupportTicketBody = req.body || {};
    const { name, email, userEmail, subject, message, attachments } = body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message content is required.' });
    }

    const ticketId = `qs_tkt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const senderEmail = email?.trim() || userEmail?.trim() || 'anonymous@quarkshield.ai';
    const senderName = name?.trim() || (senderEmail.includes('@') ? senderEmail.split('@')[0] : 'Workstation User');
    const ticketSubject = subject?.trim() || 'Feedback';
    const ticketMessage = message.trim();
    const attachmentCount = Array.isArray(attachments) ? attachments.length : 0;

    console.log(`📩 [SUPPORT TICKET RECEIVED] ID: ${ticketId} | Subject: [${ticketSubject}] | From: ${senderName} <${senderEmail}> | Attachments: ${attachmentCount}`);

    // Persist to Postgres database if table exists or create on the fly
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS support_tickets (
          id VARCHAR(100) PRIMARY KEY,
          name VARCHAR(255),
          email VARCHAR(255) NOT NULL,
          subject VARCHAR(255) NOT NULL,
          message TEXT NOT NULL,
          attachment_count INTEGER DEFAULT 0,
          status VARCHAR(50) DEFAULT 'open',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await pool.query(
        `INSERT INTO support_tickets (id, name, email, subject, message, attachment_count, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [ticketId, senderName, senderEmail, ticketSubject, ticketMessage, attachmentCount, 'open']
      );
    } catch (dbErr) {
      console.warn('⚠️ Could not insert support ticket into DB (logging only):', dbErr);
    }

    return res.status(200).json({
      success: true,
      ticketId,
      message: 'Support request received successfully. Our engineering and defense GRC team will follow up.'
    });
  } catch (err: any) {
    console.error('Error submitting support ticket:', err);
    return res.status(500).json({ error: 'Internal server error processing support ticket.' });
  }
};
