#!/usr/bin/env python3
"""Rebuild server/src/lib/cavpData.ts from saved NIST CMVP certificate pages.

Usage (from server/):
    python3 scripts/build-cavp-data.py <dir-with-saved-pages> [YYYY-MM-DD]

Save each certificate page first, one file per certificate, named so the certificate number
is the last run of digits before ".html" (5573.html, c5573.html, ...):
    https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/<id>

Only certificates named in cmvpModules.ts or hostCryptoModules.ts are read. A page with no
structured "Approved Algorithms" list (FIPS 140-2 certificates) is left out, which the
server reads as "not known". Nothing is fetched from the network by this script.
"""
import datetime, html, json, os, re, sys

here = os.path.dirname(os.path.abspath(__file__))
lib = os.path.join(here, '..', 'src', 'lib')
pages_dir = sys.argv[1]
read_on = sys.argv[2] if len(sys.argv) > 2 else datetime.date.today().isoformat()

wanted = set()
for f in ('cmvpModules.ts', 'hostCryptoModules.ts'):
    wanted |= set(re.findall(r"certId: '(\d+)'", open(os.path.join(lib, f)).read()))

pages = {}
for name in sorted(os.listdir(pages_dir)):
    m = re.search(r'(\d+)\.html$', name)
    if m and m.group(1) in wanted:
        pages.setdefault(m.group(1), os.path.join(pages_dir, name))

data, skipped = {}, []
for cert in sorted(wanted, key=int):
    if cert not in pages:
        skipped.append(f'#{cert}: no saved page'); continue
    t = open(pages[cert], errors='ignore').read()
    i = t.find('<span>Approved Algorithms</span>')
    if i < 0:
        skipped.append(f'#{cert}: page has no structured algorithm list'); continue
    j = t.find('<div class="row padrow">', i + 10)
    seg = t[i:j if j > 0 else len(t)]
    algos = {}
    for name, cell in re.findall(r'<div class="col-md-3">([^<]+)</div>\s*<div class="col-md-4">(.*?)</div>', seg, re.S):
        ids = [re.sub(r'\s+', ' ', x).strip() for x in re.findall(r'<a [^>]*>(.*?)</a>', cell, re.S)]
        bucket = algos.setdefault(html.unescape(name).strip(), [])
        bucket.extend(x for x in ids if x and x not in bucket)
    algos = {k: v for k, v in algos.items() if v}
    if algos:
        data[cert] = algos
    else:
        skipped.append(f'#{cert}: list parsed empty')

out = ['''/**
 * GENERATED DATA — do not edit by hand. Rebuild with server/scripts/build-cavp-data.py.
 *
 * The "Approved Algorithms" list from each module's NIST CMVP certificate page
 * (https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/<id>),
 * as read on the date in CAVP_DATA_READ. Each entry is the algorithm name exactly as NIST
 * prints it, with the CAVP validation numbers listed beside it.
 *
 * Only certificates whose page carries a structured list are here (FIPS 140-3 certificates).
 * A certificate that is absent has NO list in this file, which means "not known", never
 * "nothing approved". See cavpCoverage.ts for how the lists are used.
 */
export const CAVP_DATA_READ = '%s';

export const CAVP_BY_CERTIFICATE: Record<string, Record<string, string[]>> = {''' % read_on]
for cert in sorted(data, key=int):
    out.append(f"  '{cert}': {{")
    for a in sorted(data[cert]):
        out.append(f'    {json.dumps(a)}: {json.dumps(data[cert][a])},')
    out.append('  },')
out.append('};\n')
open(os.path.join(lib, 'cavpData.ts'), 'w').write('\n'.join(out))
print(f'{len(data)} certificates, {sum(len(v) for v in data.values())} algorithm entries written (read {read_on})')
for s in skipped:
    print('  left out', s)
