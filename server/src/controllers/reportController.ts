import { Request, Response } from 'express';
import PDFDocument from 'pdfkit';
import { Document, Packer, Paragraph, HeadingLevel, Table, TableRow, TableCell, TextRun, WidthType, AlignmentType } from 'docx';
import pool from '../config/db';
import { isSuperRole } from '../middleware/auth';
import { sendSupportEmail } from './adminController';
import { buildRoadmapReport, generateNarrative, RoadmapReport, Priority } from '../lib/roadmapReport';

/**
 * Executive PQC Roadmap Report export.
 *   GET /api/reports/executive?tenant=<t|all>&format=pdf|docx|html&scope=collective
 * Per-tenant (any authorized user for their tenant) or collective/fleet-wide
 * (super-admin only). Sections: executive summary (deterministic + optional AI),
 * posture, top migration priorities, remediation recommendations, migration
 * roadmap, and a per-tenant breakdown for the collective view.
 */

const SEV_COLOR: Record<string, string> = { critical: '#b91c1c', high: '#c2410c', medium: '#a16207', low: '#475569' };

// ---------------------------------------------------------------- PDF --------
const buildPdf = (r: RoadmapReport, res: Response) => {
  const doc = new PDFDocument({ size: 'A4', margin: 50 });
  doc.pipe(res);
  const cyan = '#0284c7', slate = '#475569', navy = '#0f172a';
  const rule = () => { doc.moveTo(50, doc.y + 4).lineTo(545, doc.y + 4).strokeColor('#e2e8f0').stroke(); doc.moveDown(0.8); };
  const h = (t: string) => { doc.moveDown(0.8).fillColor(navy).fontSize(13).text(t); doc.moveDown(0.3); };

  // Header (with risk-grade badge on the right)
  const gradeColor = r.riskGrade[0] === 'F' ? '#b91c1c' : r.riskGrade[0] === 'D' ? '#c2410c' : r.riskGrade[0] === 'C' ? '#a16207' : r.riskGrade[0] === 'B' ? '#0369a1' : '#15803d';
  const topY = doc.y;
  doc.fillColor('#b91c1c').fontSize(8).text('CONFIDENTIAL', 50, topY);
  doc.fillColor(navy).fontSize(22).text('quarkshield', 50, doc.y + 2);
  doc.fillColor(cyan).fontSize(13).text('Executive Post-Quantum Cryptography Roadmap Report');
  doc.moveDown(0.4).fillColor(slate).fontSize(10)
    .text(`Prepared for: ${r.scopeLabel}${r.collective ? `  ·  ${r.totals.tenants} tenants` : ''}`)
    .text(`Generated: ${r.generatedAt}   ·   Report ID: ${r.reportId}`);
  // Grade badge, top-right
  doc.fillColor(gradeColor).fontSize(34).text(r.riskGrade, 470, topY + 6, { width: 75, align: 'right' });
  doc.fillColor(slate).fontSize(8).text('RISK GRADE', 470, topY + 44, { width: 75, align: 'right' });
  doc.moveTo(50, doc.y + 6).lineTo(545, doc.y + 6).strokeColor(cyan).stroke();
  doc.moveDown(1);

  // Executive summary
  h('Executive Summary');
  doc.fillColor('#111').fontSize(10).text(r.summary, { align: 'justify' });

  // Posture snapshot
  h('Cryptographic Posture');
  doc.fillColor('#111').fontSize(10);
  ([
    ['Endpoints scanned', String(r.totals.machines)],
    ['Cryptographic assets', String(r.totals.assets)],
    ['Quantum-vulnerable', `${r.totals.vulnerable} (${r.totals.vulnPct}%)`],
    ['Post-quantum / secure', String(r.totals.pqcReady)],
    ['Average quantum risk', `${r.totals.avgRisk} / 100`],
  ]).forEach(([k, v]) => doc.text(`${k}:  `, { continued: true }).fillColor(cyan).text(String(v)).fillColor('#111'));
  doc.moveDown(0.5);
  doc.fillColor(r.mosca.verdict === 'ON TRACK' ? '#15803d' : '#b91c1c').fontSize(11).text(`Mosca verdict (X + Y > Z): ${r.mosca.verdict}`);
  doc.fillColor(slate).fontSize(9).text(r.mosca.detail, { align: 'justify' });

  // Top priorities
  h('Top Migration Priorities');
  if (r.priorities.length === 0) doc.fillColor('#111').fontSize(10).text('No quantum-vulnerable assets identified.');
  r.priorities.forEach((p: Priority) => {
    doc.fillColor(SEV_COLOR[p.severity] || slate).fontSize(10).text(`P${p.rank}  [${p.severity.toUpperCase()}]  ${p.title}`, { continued: false });
    doc.fillColor('#333').fontSize(9).text(`     ${p.rationale}`);
    doc.moveDown(0.15);
  });

  // Remediation
  h('Remediation Recommendations');
  r.remediation.forEach((rem) => {
    doc.fillColor(navy).fontSize(10).text(`${rem.finding}  →  ${rem.replacement}`);
    doc.fillColor(slate).fontSize(9).text(`     Standard: ${rem.standard}   ·   Effort: ${rem.effort}`);
    doc.fillColor('#333').fontSize(9).text(`     ${rem.how}`);
    doc.moveDown(0.2);
  });

  // Roadmap
  h('Migration Roadmap');
  r.roadmap.forEach((ph) => {
    doc.fillColor(navy).fontSize(10).text(`${ph.phase}  (${ph.window})  —  ${ph.status}`);
    doc.fillColor(slate).fontSize(8).text(`     Mandate: ${ph.mandate}`);
    ph.actions.forEach(a => doc.fillColor('#333').fontSize(9).text(`     • ${a}`));
    doc.moveDown(0.2);
  });

  // Per-tenant (collective)
  if (r.collective && r.perTenant.length) {
    h('Per-Tenant Breakdown');
    doc.fillColor(slate).fontSize(9).text('Tenant                          Assets   Vulnerable   %     Top asset');
    rule();
    r.perTenant.forEach(t => {
      doc.fillColor('#111').fontSize(9).text(
        `${t.tenant.padEnd(30).slice(0, 30)}  ${String(t.assets).padStart(5)}   ${String(t.vulnerable).padStart(9)}   ${String(t.vulnPct).padStart(3)}   ${t.topRisk}`
      );
    });
  }

  doc.moveDown(1.2).fillColor(slate).fontSize(8).text(
    'Prepared by QuarkShield.ai. Migrate classical RSA/ECC to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) per NSA CNSA 2.0 and OMB M-23-02. Figures are computed from the tenant cryptographic inventory (CBOM).',
    { align: 'left' }
  );
  doc.end();
};

// --------------------------------------------------------------- DOCX --------
const cell = (t: string, bold = false, w = 25) => new TableCell({ width: { size: w, type: WidthType.PERCENTAGE }, children: [new Paragraph({ children: [new TextRun({ text: t, bold })] })] });

const buildDocx = async (r: RoadmapReport): Promise<Buffer> => {
  const posture = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [cell('Metric', true, 50), cell('Value', true, 50)] }),
      new TableRow({ children: [cell('Endpoints scanned', false, 50), cell(String(r.totals.machines), false, 50)] }),
      new TableRow({ children: [cell('Cryptographic assets', false, 50), cell(String(r.totals.assets), false, 50)] }),
      new TableRow({ children: [cell('Quantum-vulnerable', false, 50), cell(`${r.totals.vulnerable} (${r.totals.vulnPct}%)`, false, 50)] }),
      new TableRow({ children: [cell('Post-quantum / secure', false, 50), cell(String(r.totals.pqcReady), false, 50)] }),
      new TableRow({ children: [cell('Average quantum risk', false, 50), cell(`${r.totals.avgRisk} / 100`, false, 50)] }),
    ],
  });

  const remTable = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ children: [cell('Finding', true, 25), cell('Replacement', true, 30), cell('Standard', true, 25), cell('Effort', true, 20)] }),
      ...r.remediation.map(rem => new TableRow({ children: [cell(rem.finding, false, 25), cell(rem.replacement, false, 30), cell(rem.standard, false, 25), cell(rem.effort, false, 20)] })),
    ],
  });

  const children: any[] = [
    new Paragraph({ children: [new TextRun({ text: 'CONFIDENTIAL', bold: true, color: 'B91C1C', size: 16 })] }),
    new Paragraph({ text: 'QuarkShield', heading: HeadingLevel.TITLE }),
    new Paragraph({ text: 'Executive Post-Quantum Cryptography Roadmap Report', heading: HeadingLevel.HEADING_2 }),
    new Paragraph({ children: [new TextRun({ text: `Risk Grade: ${r.riskGrade}`, bold: true, size: 28 })] }),
    new Paragraph(`Prepared for: ${r.scopeLabel}${r.collective ? `  ·  ${r.totals.tenants} tenants` : ''}`),
    new Paragraph(`Generated: ${r.generatedAt}   ·   Report ID: ${r.reportId}`),
    new Paragraph({ text: 'Executive Summary', heading: HeadingLevel.HEADING_1 }),
    new Paragraph({ children: [new TextRun(r.summary)] }),
    new Paragraph({ text: 'Cryptographic Posture', heading: HeadingLevel.HEADING_1 }),
    posture,
    new Paragraph({ children: [new TextRun({ text: `Mosca verdict (X + Y > Z): ${r.mosca.verdict}`, bold: true })] }),
    new Paragraph(r.mosca.detail),
    new Paragraph({ text: 'Top Migration Priorities', heading: HeadingLevel.HEADING_1 }),
    ...(r.priorities.length ? r.priorities.map(p => new Paragraph({ children: [new TextRun({ text: `P${p.rank} [${p.severity.toUpperCase()}] ${p.title}`, bold: true }), new TextRun({ text: ` — ${p.rationale}` })] })) : [new Paragraph('No quantum-vulnerable assets identified.')]),
    new Paragraph({ text: 'Remediation Recommendations', heading: HeadingLevel.HEADING_1 }),
    remTable,
    ...r.remediation.map(rem => new Paragraph({ children: [new TextRun({ text: `${rem.finding}: `, bold: true }), new TextRun(rem.how)] })),
    new Paragraph({ text: 'Migration Roadmap', heading: HeadingLevel.HEADING_1 }),
    ...r.roadmap.flatMap(ph => [
      new Paragraph({ children: [new TextRun({ text: `${ph.phase} (${ph.window}) — ${ph.status}`, bold: true })] }),
      new Paragraph({ children: [new TextRun({ text: `Mandate: ${ph.mandate}`, italics: true })] }),
      ...ph.actions.map(a => new Paragraph({ text: a, bullet: { level: 0 } })),
    ]),
  ];

  if (r.collective && r.perTenant.length) {
    children.push(new Paragraph({ text: 'Per-Tenant Breakdown', heading: HeadingLevel.HEADING_1 }));
    children.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: [cell('Tenant', true, 40), cell('Assets', true, 15), cell('Vulnerable', true, 20), cell('%', true, 10), cell('Top asset', true, 15)] }),
        ...r.perTenant.map(t => new TableRow({ children: [cell(t.tenant, false, 40), cell(String(t.assets), false, 15), cell(String(t.vulnerable), false, 20), cell(String(t.vulnPct), false, 10), cell(t.topRisk, false, 15)] })),
      ],
    }));
  }

  children.push(new Paragraph({ text: '' }));
  children.push(new Paragraph({ alignment: AlignmentType.LEFT, children: [new TextRun({ text: 'Prepared by QuarkShield.ai. Migrate classical RSA/ECC to NIST FIPS 203/204 per NSA CNSA 2.0 and OMB M-23-02. Figures computed from the tenant CBOM.', italics: true, size: 16 })] }));

  const doc = new Document({ sections: [{ children }] });
  return Packer.toBuffer(doc);
};

// --------------------------------------------------------------- HTML --------
const esc = (s: string) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
const buildHtml = (r: RoadmapReport): string => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>QuarkShield PQC Roadmap — ${esc(r.scopeLabel)}</title>
<style>
:root{--navy:#0f172a;--cyan:#0284c7;--slate:#475569;--bg:#f8fafc;--card:#fff;--line:#e2e8f0}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#0f172a;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px}
.head{border-bottom:3px solid var(--cyan);padding-bottom:16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.wordmark{font-size:26px;font-weight:800;color:var(--navy);font-family:Georgia,'Times New Roman',serif;letter-spacing:-.5px}
.wordmark em{font-style:italic;color:var(--cyan);font-weight:600}
.head .sub{color:var(--cyan);font-weight:600;margin-top:2px}
.conf{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.08em;color:#b91c1c;border:1px solid #fecaca;background:#fef2f2;border-radius:4px;padding:2px 8px;margin-bottom:6px}
.grade{text-align:center;min-width:96px}
.grade .g{font-size:44px;font-weight:800;line-height:1;color:var(--navy)}
.grade .gl{font-size:10px;letter-spacing:.1em;color:var(--slate);text-transform:uppercase}
.grade.f .g{color:#b91c1c}.grade.d .g{color:#c2410c}.grade.c .g{color:#a16207}.grade.b .g{color:#0369a1}.grade.a .g{color:#15803d}
.meta{color:var(--slate);font-size:13px;margin:6px 0 0}
h2{color:var(--navy);font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:12px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .n{font-size:22px;font-weight:800;color:var(--navy)}.kpi .l{font-size:12px;color:var(--slate);text-transform:uppercase;letter-spacing:.04em}
.verdict{border-radius:10px;padding:12px 14px;margin:10px 0;font-weight:600}
.verdict.warn{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c}.verdict.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#15803d}
.verdict .d{font-weight:400;color:var(--slate);font-size:13px;margin-top:4px}
.pri{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--slate);border-radius:8px;padding:10px 12px;margin:8px 0}
.pri.critical{border-left-color:#b91c1c}.pri.high{border-left-color:#c2410c}.pri.medium{border-left-color:#a16207}
.pri .t{font-weight:700}.pri .sev{font-size:11px;font-weight:800;text-transform:uppercase;padding:1px 6px;border-radius:4px;background:#f1f5f9;color:var(--slate);margin-right:8px}
.pri .r{color:var(--slate);font-size:13px;margin-top:3px}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f1f5f9;color:var(--navy)}
.phase{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.phase h3{margin:0 0 2px;font-size:15px}.phase .m{color:var(--slate);font-size:12px;margin-bottom:6px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;background:#e0f2fe;color:#0369a1;margin-left:6px}
.foot{color:var(--slate);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff}.kpi,.pri,.phase{break-inside:avoid}}
</style></head><body><div class="wrap">
<div class="head">
<div>
<div class="conf">CONFIDENTIAL</div>
<div class="wordmark">quark<em>shield</em></div>
<div class="sub">Executive Post-Quantum Cryptography Roadmap Report</div>
<div class="meta">Prepared for: <strong>${esc(r.scopeLabel)}</strong>${r.collective ? ` · ${r.totals.tenants} tenants` : ''}<br>Generated: ${esc(r.generatedAt)} &nbsp;·&nbsp; Report ID: ${esc(r.reportId)}</div>
</div>
<div class="grade ${(r.riskGrade[0] || 'a').toLowerCase()}"><div class="g">${esc(r.riskGrade)}</div><div class="gl">Risk Grade</div></div>
</div>

<h2>Executive Summary</h2><p>${esc(r.summary)}</p>

<h2>Cryptographic Posture</h2>
<div class="kpis">
<div class="kpi"><div class="n">${r.totals.machines}</div><div class="l">Endpoints</div></div>
<div class="kpi"><div class="n">${r.totals.assets}</div><div class="l">Assets</div></div>
<div class="kpi"><div class="n">${r.totals.vulnerable} (${r.totals.vulnPct}%)</div><div class="l">Quantum-vulnerable</div></div>
<div class="kpi"><div class="n">${r.totals.pqcReady}</div><div class="l">PQC / Secure</div></div>
<div class="kpi"><div class="n">${r.totals.avgRisk}/100</div><div class="l">Avg risk</div></div>
</div>
<div class="verdict ${r.mosca.verdict === 'ON TRACK' ? 'ok' : 'warn'}">Mosca verdict (X + Y &gt; Z): ${esc(r.mosca.verdict)}<div class="d">${esc(r.mosca.detail)}</div></div>

<h2>Top Migration Priorities</h2>
${r.priorities.length ? r.priorities.map(p => `<div class="pri ${p.severity}"><div class="t"><span class="sev">${esc(p.severity)}</span>P${p.rank} · ${esc(p.title)}</div><div class="r">${esc(p.rationale)}</div></div>`).join('') : '<p>No quantum-vulnerable assets identified.</p>'}

<h2>Remediation Recommendations</h2>
<table><thead><tr><th>Finding</th><th>Replacement</th><th>Standard</th><th>Effort</th></tr></thead><tbody>
${r.remediation.map(rem => `<tr><td><strong>${esc(rem.finding)}</strong><div style="color:var(--slate);font-size:12px;margin-top:3px">${esc(rem.how)}</div></td><td>${esc(rem.replacement)}</td><td>${esc(rem.standard)}</td><td>${esc(rem.effort)}</td></tr>`).join('')}
</tbody></table>

<h2>Migration Roadmap</h2>
${r.roadmap.map(ph => `<div class="phase"><h3>${esc(ph.phase)} <span class="badge">${esc(ph.status)}</span></h3><div class="m">${esc(ph.window)} · ${esc(ph.mandate)}</div><ul>${ph.actions.map(a => `<li>${esc(a)}</li>`).join('')}</ul></div>`).join('')}

${r.collective && r.perTenant.length ? `<h2>Per-Tenant Breakdown</h2><table><thead><tr><th>Tenant</th><th>Assets</th><th>Vulnerable</th><th>%</th><th>Top asset</th></tr></thead><tbody>${r.perTenant.map(t => `<tr><td>${esc(t.tenant)}</td><td>${t.assets}</td><td>${t.vulnerable}</td><td>${t.vulnPct}</td><td>${esc(t.topRisk)}</td></tr>`).join('')}</tbody></table>` : ''}

<div class="foot">Prepared by QuarkShield.ai. Migrate classical RSA/ECC to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) per NSA CNSA 2.0 and OMB M-23-02. Figures are computed from the cryptographic inventory (CBOM). Tip: use your browser's Print → Save as PDF for a shareable copy.</div>
</div></body></html>`;

// ------------------------------------------------------------ handler --------
export const exportExecutiveReport = async (req: Request, res: Response) => {
  try {
    const format = String(req.query.format || 'pdf').toLowerCase();
    const tenantParam = (req.query.tenant as string) || '';
    const collective = String(req.query.scope || '').toLowerCase() === 'collective' || tenantParam.toLowerCase() === 'all';

    if (collective) {
      if (!isSuperRole(req.user?.role)) {
        return res.status(403).json({ error: 'Fleet-wide (collective) reports require a super-admin.' });
      }
    }
    const tenant = collective ? '' : (tenantParam || req.user?.tenant || '');
    if (!collective && !tenant) return res.status(400).json({ error: 'A tenant is required.' });

    const report = await buildRoadmapReport(collective ? { collective: true } : { collective: false, tenant });
    report.summary = await generateNarrative(report);

    const safeName = (collective ? 'fleet' : tenant).toLowerCase().replace(/[^a-z0-9]/g, '-');

    if (format === 'docx') {
      const buf = await buildDocx(report);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="quarkshield-pqc-roadmap-${safeName}.docx"`);
      return res.send(buf);
    }
    if (format === 'html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(buildHtml(report));
    }
    if (format === 'pdf') {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="quarkshield-pqc-roadmap-${safeName}.pdf"`);
      return buildPdf(report, res);
    }
    return res.status(400).json({ error: "Unsupported format. Use 'pdf', 'docx' or 'html'." });
  } catch (err: any) {
    console.error('Error generating executive roadmap report:', err);
    if (!res.headersSent) res.status(500).json({ error: 'Failed to generate report.' });
  }
};

// ------------------------------------------------ stakeholders + email --------
const STAKEHOLDER_KEY = 'report_stakeholders';
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const scopeKey = (collective: boolean, tenant: string) => (collective ? '__fleet__' : (tenant || '').toUpperCase());

const resolveScope = (req: Request, tenantIn?: string, scopeIn?: string) => {
  const collective = String(scopeIn || '').toLowerCase() === 'collective' || String(tenantIn || '').toLowerCase() === 'all';
  const tenant = collective ? '' : (tenantIn || req.user?.tenant || '');
  return { collective, tenant };
};

export const getReportStakeholders = async (req: Request, res: Response) => {
  try {
    const { collective, tenant } = resolveScope(req, req.query.tenant as string, req.query.scope as string);
    if (collective && !isSuperRole(req.user?.role)) return res.status(403).json({ error: 'Super-admin required for fleet stakeholders.' });
    if (!collective && !tenant) return res.status(400).json({ error: 'A tenant is required.' });
    const r = await pool.query('SELECT value FROM tenant_settings WHERE tenant_name = $1 AND key = $2', [scopeKey(collective, tenant), STAKEHOLDER_KEY]);
    let list: any[] = [];
    if (r.rows[0]?.value) { try { list = JSON.parse(r.rows[0].value); } catch { /* ignore */ } }
    return res.json({ stakeholders: Array.isArray(list) ? list : [] });
  } catch (err: any) {
    console.error('getReportStakeholders error:', err);
    res.status(500).json({ error: 'Failed to load stakeholders.' });
  }
};

export const saveReportStakeholders = async (req: Request, res: Response) => {
  try {
    const { tenant: tBody, scope, stakeholders } = req.body || {};
    const { collective, tenant } = resolveScope(req, tBody, scope);
    if (collective && !isSuperRole(req.user?.role)) return res.status(403).json({ error: 'Super-admin required for fleet stakeholders.' });
    if (!collective && !tenant) return res.status(400).json({ error: 'A tenant is required.' });
    const clean = (Array.isArray(stakeholders) ? stakeholders : [])
      .filter((s: any) => s && typeof s.email === 'string' && EMAIL_RE.test(s.email.trim()))
      .slice(0, 50)
      .map((s: any) => ({ name: String(s.name || '').slice(0, 120), email: s.email.trim().slice(0, 200), role: String(s.role || '').slice(0, 80) }));
    await pool.query(
      `INSERT INTO tenant_settings (tenant_name, key, value) VALUES ($1, $2, $3)
       ON CONFLICT (tenant_name, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [scopeKey(collective, tenant), STAKEHOLDER_KEY, JSON.stringify(clean)]
    );
    return res.json({ success: true, stakeholders: clean });
  } catch (err: any) {
    console.error('saveReportStakeholders error:', err);
    res.status(500).json({ error: 'Failed to save stakeholders.' });
  }
};

export const sendRoadmapReport = async (req: Request, res: Response) => {
  try {
    const { tenant: tBody, scope, recipients } = req.body || {};
    const { collective, tenant } = resolveScope(req, tBody, scope);
    if (collective && !isSuperRole(req.user?.role)) return res.status(403).json({ error: 'Super-admin required for fleet reports.' });
    if (!collective && !tenant) return res.status(400).json({ error: 'A tenant is required.' });

    let toList: { name?: string; email: string }[] = [];
    if (Array.isArray(recipients) && recipients.length) {
      toList = recipients.map((s: any) => ({ name: s?.name, email: String(s?.email || '').trim() }));
    } else {
      const r = await pool.query('SELECT value FROM tenant_settings WHERE tenant_name = $1 AND key = $2', [scopeKey(collective, tenant), STAKEHOLDER_KEY]);
      if (r.rows[0]?.value) { try { toList = JSON.parse(r.rows[0].value); } catch { /* ignore */ } }
    }
    toList = (toList || []).filter(s => s.email && EMAIL_RE.test(s.email));
    if (!toList.length) return res.status(400).json({ error: 'No valid recipients. Add stakeholders under Profile first.' });

    const report = await buildRoadmapReport(collective ? { collective: true } : { collective: false, tenant });
    report.summary = await generateNarrative(report);
    const html = buildHtml(report);
    const subject = `QuarkShield PQC Roadmap — ${report.scopeLabel} (Risk ${report.riskGrade})`;
    const text = `QuarkShield Executive PQC Roadmap Report for ${report.scopeLabel}. Risk grade ${report.riskGrade}. ${report.totals.vulnerable} of ${report.totals.assets} assets are quantum-vulnerable. This email contains the full report (priorities, remediation, migration roadmap).`;

    let sent = 0; const failed: string[] = [];
    for (const s of toList) {
      const r = await sendSupportEmail({ to: s.email, subject, html, text });
      if (r.success) sent++; else failed.push(s.email);
    }
    return res.json({ success: sent > 0, sent, failed, total: toList.length });
  } catch (err: any) {
    console.error('sendRoadmapReport error:', err);
    res.status(500).json({ error: 'Failed to send report.' });
  }
};
