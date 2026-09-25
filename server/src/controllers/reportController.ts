import { Request, Response } from 'express';
import PDFDocument from 'pdfkit';
import { Document, Packer, Paragraph, HeadingLevel, Table, TableRow, TableCell, TextRun, WidthType, AlignmentType } from 'docx';
import pool from '../config/db';

/**
 * Executive PQC audit report export (DEF-47): server-side PDF and DOCX
 * generation of a tenant's cryptographic posture. GET /api/reports/executive
 * ?tenant=<t>&format=pdf|docx (authenticated, tenant-scoped).
 */

interface ReportData {
  tenant: string;
  generatedAt: string;
  totals: { machines: number; assets: number; vulnerable: number; pqcReady: number; avgRisk: number };
  byAlgorithm: Array<{ algorithm: string; count: number; vulnerable: number }>;
  topVulnerable: Array<{ name: string; algorithm: string; keySize: number; riskLevel: string; hostname: string }>;
}

const gatherReportData = async (tenant: string): Promise<ReportData> => {
  const like = `%${tenant}%`;
  const totalsQ = await pool.query(
    `SELECT
        (SELECT COUNT(*) FROM fleet_machines WHERE LOWER(tenant_name) LIKE LOWER($1))::int AS machines,
        COUNT(*)::int AS assets,
        COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable,
        COUNT(*) FILTER (WHERE NOT is_vulnerable)::int AS pqc_ready
     FROM assets WHERE LOWER(COALESCE(tenant_name,'')) LIKE LOWER($1)`,
    [like]
  );
  const riskQ = await pool.query(
    `SELECT COALESCE(ROUND(AVG(quantum_risk_score)),0)::int AS avg_risk FROM fleet_machines WHERE LOWER(tenant_name) LIKE LOWER($1)`,
    [like]
  );
  const byAlgoQ = await pool.query(
    `SELECT COALESCE(algorithm,'Unknown') AS algorithm, COUNT(*)::int AS count,
            COUNT(*) FILTER (WHERE is_vulnerable)::int AS vulnerable
     FROM assets WHERE LOWER(COALESCE(tenant_name,'')) LIKE LOWER($1)
     GROUP BY algorithm ORDER BY count DESC LIMIT 15`,
    [like]
  );
  const topVulnQ = await pool.query(
    `SELECT a.name, COALESCE(a.algorithm,'Unknown') AS algorithm, COALESCE(a.key_size,0)::int AS key_size,
            COALESCE(a.risk_level,'high') AS risk_level, COALESCE(m.hostname,'-') AS hostname
     FROM assets a LEFT JOIN fleet_machines m ON m.id = a.machine_id
     WHERE LOWER(COALESCE(a.tenant_name,'')) LIKE LOWER($1) AND a.is_vulnerable
     ORDER BY CASE LOWER(a.risk_level) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, a.key_size DESC
     LIMIT 25`,
    [like]
  );
  const t = totalsQ.rows[0] || {};
  return {
    tenant,
    generatedAt: new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC',
    totals: { machines: t.machines || 0, assets: t.assets || 0, vulnerable: t.vulnerable || 0, pqcReady: t.pqc_ready || 0, avgRisk: riskQ.rows[0]?.avg_risk || 0 },
    byAlgorithm: byAlgoQ.rows.map(r => ({ algorithm: r.algorithm, count: r.count, vulnerable: r.vulnerable })),
    topVulnerable: topVulnQ.rows.map(r => ({ name: r.name, algorithm: r.algorithm, keySize: r.key_size, riskLevel: r.risk_level, hostname: r.hostname })),
  };
};

const buildPdf = (d: ReportData, res: Response) => {
  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  doc.pipe(res);
  const cyan = '#0284c7', slate = '#475569', navy = '#0f172a';

  doc.fillColor(navy).fontSize(22).text('QuarkShield.ai', { continued: false });
  doc.fillColor(slate).fontSize(13).text('Executive Post-Quantum Cryptography Audit Report');
  doc.moveDown(0.5).fillColor(slate).fontSize(10).text(`Organization: ${d.tenant}`);
  doc.text(`Generated: ${d.generatedAt}`);
  doc.moveTo(50, doc.y + 6).lineTo(545, doc.y + 6).strokeColor(cyan).stroke();
  doc.moveDown(1);

  doc.fillColor(navy).fontSize(14).text('Summary');
  doc.moveDown(0.3).fillColor('#111').fontSize(10);
  const s = d.totals;
  const rows = [
    ['Endpoints scanned', String(s.machines)],
    ['Cryptographic assets discovered', String(s.assets)],
    ['Quantum-vulnerable assets', String(s.vulnerable)],
    ['Post-quantum / secure assets', String(s.pqcReady)],
    ['Average quantum risk score', `${s.avgRisk} / 100`],
  ];
  rows.forEach(([k, v]) => doc.text(`${k}:  `, { continued: true }).fillColor(cyan).text(v).fillColor('#111'));

  doc.moveDown(1).fillColor(navy).fontSize(14).text('Algorithms in use');
  doc.moveDown(0.3).fillColor('#111').fontSize(10);
  if (d.byAlgorithm.length === 0) doc.text('No assets discovered yet.');
  d.byAlgorithm.forEach(a => doc.text(`${a.algorithm}: ${a.count} (${a.vulnerable} vulnerable)`));

  doc.moveDown(1).fillColor(navy).fontSize(14).text('Top quantum-vulnerable assets');
  doc.moveDown(0.3).fillColor('#111').fontSize(9);
  if (d.topVulnerable.length === 0) doc.text('None found.');
  d.topVulnerable.forEach(a => doc.text(`[${a.riskLevel.toUpperCase()}] ${a.name} — ${a.algorithm}${a.keySize ? '-' + a.keySize : ''} @ ${a.hostname}`));

  doc.moveDown(1.5).fillColor(slate).fontSize(8).text('Prepared by QuarkShield.ai. Classical RSA/ECC assets are vulnerable to Shor’s algorithm on a CRQC; migrate to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) per CNSA 2.0 timelines.', { align: 'left' });
  doc.end();
};

const buildDocx = async (d: ReportData): Promise<Buffer> => {
  const s = d.totals;
  const cell = (t: string, bold = false) => new TableCell({ width: { size: 50, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: t, bold })] })] });
  const summaryTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [cell('Metric', true), cell('Value', true)] }),
      new TableRow({ children: [cell('Endpoints scanned'), cell(String(s.machines))] }),
      new TableRow({ children: [cell('Cryptographic assets discovered'), cell(String(s.assets))] }),
      new TableRow({ children: [cell('Quantum-vulnerable assets'), cell(String(s.vulnerable))] }),
      new TableRow({ children: [cell('Post-quantum / secure assets'), cell(String(s.pqcReady))] }),
      new TableRow({ children: [cell('Average quantum risk score'), cell(`${s.avgRisk} / 100`)] }),
    ],
  });
  const doc = new Document({
    sections: [{
      children: [
        new Paragraph({ text: 'QuarkShield.ai', heading: HeadingLevel.TITLE }),
        new Paragraph({ text: 'Executive Post-Quantum Cryptography Audit Report', heading: HeadingLevel.HEADING_2 }),
        new Paragraph(`Organization: ${d.tenant}`),
        new Paragraph(`Generated: ${d.generatedAt}`),
        new Paragraph({ text: 'Summary', heading: HeadingLevel.HEADING_1 }),
        summaryTable,
        new Paragraph({ text: 'Algorithms in use', heading: HeadingLevel.HEADING_1 }),
        ...(d.byAlgorithm.length ? d.byAlgorithm.map(a => new Paragraph(`${a.algorithm}: ${a.count} (${a.vulnerable} vulnerable)`)) : [new Paragraph('No assets discovered yet.')]),
        new Paragraph({ text: 'Top quantum-vulnerable assets', heading: HeadingLevel.HEADING_1 }),
        ...(d.topVulnerable.length ? d.topVulnerable.map(a => new Paragraph(`[${a.riskLevel.toUpperCase()}] ${a.name} — ${a.algorithm}${a.keySize ? '-' + a.keySize : ''} @ ${a.hostname}`)) : [new Paragraph('None found.')]),
        new Paragraph({ text: '' }),
        new Paragraph({ alignment: AlignmentType.LEFT, children: [new TextRun({ text: 'Prepared by QuarkShield.ai. Classical RSA/ECC assets are vulnerable to Shor’s algorithm on a CRQC; migrate to NIST FIPS 203/204 per CNSA 2.0.', italics: true, size: 16 })] }),
      ],
    }],
  });
  return Packer.toBuffer(doc);
};

export const exportExecutiveReport = async (req: Request, res: Response) => {
  try {
    const tenant = (req.query.tenant as string) || (req.user?.tenant || '');
    if (!tenant) return res.status(400).json({ error: 'A tenant is required.' });
    const format = String(req.query.format || 'pdf').toLowerCase();
    const data = await gatherReportData(tenant);
    const safeName = tenant.toLowerCase().replace(/[^a-z0-9]/g, '-');

    if (format === 'docx') {
      const buf = await buildDocx(data);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="quarkshield-report-${safeName}.docx"`);
      return res.send(buf);
    }
    if (format === 'pdf') {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="quarkshield-report-${safeName}.pdf"`);
      return buildPdf(data, res);
    }
    return res.status(400).json({ error: "Unsupported format. Use 'pdf' or 'docx'." });
  } catch (err: any) {
    console.error('Error generating executive report:', err);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to generate report.' });
  }
};
