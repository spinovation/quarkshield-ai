/**
 * POA&M Excel export (BILL-4d) — a FedRAMP/eMASS-style "Open POA&M Items" workbook,
 * generated from a project's control assessment + cryptographic posture. DoD/agency
 * assessors frequently want the spreadsheet alongside the OSCAL JSON.
 */
import ExcelJS from 'exceljs';
import { ProjectRecord, ControlRow, AssetRef, assetIdent } from './oscal';
import { FRAMEWORKS } from './controlCatalog';

const DETECTOR = 'QuarkShield (FedMitigate LLC)';
const fwLabel = (fw?: string | null) => FRAMEWORKS.find(f => f.id === fw)?.label || 'NIST SP 800-53 Rev 5';

const COLUMNS = [
  'POA&M Item ID', 'Controls', 'Weakness Name', 'Weakness Description',
  'Weakness Detector Source', 'Weakness Source Identifier', 'Asset Identifier',
  'Point of Contact', 'Resources Required', 'Overall Remediation Plan',
  'Original Detection Date', 'Scheduled Completion Date', 'Status',
  'Original Risk Rating', '% Complete', 'Comments',
];

const statusLabel = (s: string) => (s === 'non_compliant' ? 'Open' : s === 'in_progress' ? 'Ongoing' : s);

export const buildPOAMWorkbook = async (
  project: ProjectRecord,
  controls: ControlRow[],
  assets: AssetRef[],
): Promise<Buffer> => {
  const wb = new ExcelJS.Workbook();
  wb.creator = DETECTOR;
  wb.created = new Date();

  // ---- Summary sheet ----
  const sum = wb.addWorksheet('Summary');
  sum.columns = [{ width: 28 }, { width: 70 }];
  const open = controls.filter(c => c.status === 'non_compliant' || c.status === 'in_progress');
  const compliant = controls.filter(c => c.status === 'compliant').length;
  const rows: [string, string][] = [
    ['System / Boundary', project.name],
    ['Framework', fwLabel(project.framework)],
    ['FIPS-199 Impact', (project.impact_level || 'moderate')],
    ['Prepared By', DETECTOR],
    ['Date', new Date().toISOString().slice(0, 10)],
    ['Controls Assessed', String(controls.length)],
    ['Compliant', String(compliant)],
    ['Open POA&M Items', String(open.length)],
    ['Quantum-vulnerable assets in scope', String(assets.length)],
  ];
  rows.forEach(([k, v], i) => {
    const r = sum.addRow([k, v]);
    r.getCell(1).font = { bold: true };
    if (i === 0) r.getCell(2).font = { bold: true, size: 13 };
  });
  sum.insertRow(1, ['QuarkShield — Plan of Action & Milestones']);
  sum.getRow(1).getCell(1).font = { bold: true, size: 16, color: { argb: 'FF7C3AED' } };

  // ---- Open POA&M Items sheet ----
  const ws = wb.addWorksheet('Open POA&M Items');
  ws.addRow(COLUMNS);
  const header = ws.getRow(1);
  header.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F2937' } };
  header.alignment = { vertical: 'middle', horizontal: 'left', wrapText: true };
  header.height = 28;

  const assetIds = assets.slice(0, 25).map(assetIdent);
  const assetSummary = assetIds.length
    ? `${assetIds.slice(0, 10).join('; ')}${assets.length > 10 ? ` (+${assets.length - 10} more)` : ''}`
    : 'See CBOM';
  const today = new Date().toISOString().slice(0, 10);

  // A cell beginning with = + - @ is executed as a formula by Excel; prefix such
  // user-entered text so it is displayed, not evaluated.
  const safeCell = (v: unknown): string => {
    const t = String(v ?? '');
    return /^[=+\-@\t\r]/.test(t) ? `'${t}` : t;
  };
  open.forEach((c, i) => {
    ws.addRow([
      `V-${String(i + 1).padStart(4, '0')}`,
      c.control_id,
      `Quantum-vulnerable cryptography (${c.control_id})`,
      safeCell(`${c.title}. ${c.fips || ''}`.trim()),
      DETECTOR,
      `QS-${(c.control_key || 'CTRL')}-${String(i + 1).padStart(3, '0')}`,
      assetSummary,
      safeCell(c.owner || ''),
      'Software remediation + migration engineering',
      safeCell(c.comments || 'Migrate affected cryptography to NIST FIPS 203/204/205 (ML-KEM / ML-DSA / SLH-DSA).'),
      today,
      c.target_date ? String(c.target_date).slice(0, 10) : '',
      statusLabel(c.status),
      c.status === 'non_compliant' ? 'High' : 'Moderate',
      typeof c.percent_complete === 'number' ? c.percent_complete : 0,
      safeCell(c.comments || ''),
    ]);
  });
  if (open.length === 0) {
    ws.addRow(['—', '', 'No open items', 'All assessed controls are compliant or not applicable.', DETECTOR, '', '', '', '', '', today, '', 'Completed', 'Low', 100, '']);
  }

  // Column widths
  const widths = [14, 12, 30, 48, 26, 22, 40, 20, 28, 48, 16, 18, 12, 16, 10, 36];
  ws.columns.forEach((col, i) => { col.width = widths[i] || 18; });
  ws.autoFilter = { from: 'A1', to: { row: 1, column: COLUMNS.length } };
  ws.views = [{ state: 'frozen', ySplit: 1 }];

  return Buffer.from(await wb.xlsx.writeBuffer());
};
