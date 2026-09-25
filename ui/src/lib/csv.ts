/**
 * Safe CSV export (DEF-46).
 *
 * - Quotes every field and escapes embedded quotes ("" per RFC 4180), so commas,
 *   quotes and newlines in values can't break the row structure.
 * - Guards against spreadsheet formula injection: a value beginning with
 *   = + - @ (or tab/CR) is prefixed with a single quote so Excel/Sheets treats
 *   it as text, not a formula.
 * - Downloads via a Blob object URL rather than a `data:` URI built with
 *   encodeURI (which silently truncated content at the first `#`).
 */

const escapeCell = (value: unknown): string => {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // neutralize formula injection
  return '"' + s.replace(/"/g, '""') + '"';
};

/** Build a CSV string from a header row and data rows. */
export const buildCsv = (headers: string[], rows: (unknown[])[]): string => {
  const lines = [headers.map(escapeCell).join(',')];
  for (const row of rows) lines.push(row.map(escapeCell).join(','));
  return lines.join('\r\n');
};

/** Build the CSV and trigger a browser download via a Blob URL. */
export const downloadCsv = (filename: string, headers: string[], rows: (unknown[])[]): void => {
  const csv = buildCsv(headers, rows);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
