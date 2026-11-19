"""Builds docs/CMVP_FIPS_TEST_PLAN.pdf: the CMVP / FIPS test plan with fillable result fields."""
import re, sys
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                Preformatted, Flowable, KeepTogether, PageBreak)

OUT = sys.argv[1]
W = A4[0] - 36 * mm
INK = colors.HexColor('#0f172a'); MUTED = colors.HexColor('#475569'); RULE = colors.HexColor('#cbd5e1')
ACCENT = colors.HexColor('#0e7490'); SHADE = colors.HexColor('#f1f5f9')

body = ParagraphStyle('body', fontName='Helvetica', fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=5)
h1 = ParagraphStyle('h1', parent=body, fontName='Helvetica-Bold', fontSize=20, leading=24, spaceAfter=4)
h2 = ParagraphStyle('h2', parent=body, fontName='Helvetica-Bold', fontSize=13.5, leading=17, textColor=ACCENT, spaceBefore=12, spaceAfter=6)
h3 = ParagraphStyle('h3', parent=body, fontName='Helvetica-Bold', fontSize=11, leading=14, spaceBefore=9, spaceAfter=4)
small = ParagraphStyle('small', parent=body, fontSize=8.5, leading=11.5, textColor=MUTED)
cellp = ParagraphStyle('cell', parent=body, fontSize=8.8, leading=11.8, spaceAfter=0)
cellh = ParagraphStyle('cellh', parent=cellp, fontName='Helvetica-Bold')
li = ParagraphStyle('li', parent=body, leftIndent=14, bulletIndent=2, spaceAfter=2.5)
code = ParagraphStyle('code', fontName='Courier', fontSize=7.6, leading=10, textColor=INK,
                      backColor=SHADE, borderPadding=5, spaceBefore=3, spaceAfter=9, leftIndent=5, rightIndent=5)


def fmt(t):
    t = escape(t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'`(.+?)`', r'<font face="Courier" size="8.4">\1</font>', t)
    return t


def P(t, style=body): return Paragraph(fmt(t), style)
def H2(t): return Paragraph(fmt(t), h2)
def H3(t): return Paragraph(fmt(t), h3)
def steps(items): return [Paragraph(fmt(x), li, bulletText=f'{i}.') for i, x in enumerate(items, 1)]
def bullets(items): return [Paragraph(fmt(x), li, bulletText='•') for x in items]


def wrap_code(text, width=104):
    out = []
    for line in text.strip('\n').split('\n'):
        while len(line) > width:
            cut = line.rfind(' ', 0, width)
            cut = cut if cut > 20 else width
            out.append(line[:cut] + ' \\'); line = '    ' + line[cut:].lstrip()
        out.append(line)
    return Preformatted('\n'.join(out), code)


def table(rows, widths):
    data = [[Paragraph(fmt(c), cellh if r == 0 else cellp) for c in row] for r, row in enumerate(rows)]
    t = Table(data, colWidths=[W * w for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SHADE), ('GRID', (0, 0), (-1, -1), 0.5, RULE),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5), ('RIGHTPADDING', (0, 0), (-1, -1), 5)]))
    return [t, Spacer(1, 7)]


class Field(Flowable):
    """One labelled, fillable text field."""
    def __init__(self, name, label, height=16, multiline=False, tip=''):
        super().__init__(); self.name, self.label, self.h, self.multi, self.tip = name, label, height, multiline, tip
    def wrap(self, aw, ah): self.w = aw; return aw, self.h + 15
    def draw(self):
        c = self.canv
        c.setFont('Helvetica-Bold', 8.5); c.setFillColor(INK); c.drawString(0, self.h + 5, self.label)
        c.acroForm.textfield(name=self.name, tooltip=self.tip or self.label, x=0, y=0, width=self.w, height=self.h,
                             fontName='Helvetica', fontSize=9, borderWidth=0.5, borderColor=RULE, fillColor=colors.white,
                             textColor=INK, forceBorder=True, relative=True, fieldFlags='multiline' if self.multi else '')


class ResultRow(Flowable):
    """Test name, a Pass / Fail / Blocked choice, and a notes box."""
    H = 46
    def __init__(self, key, label, hint=''):
        super().__init__(); self.key, self.label, self.hint = key, label, hint
    def wrap(self, aw, ah): self.w = aw; return aw, self.H + 6
    def draw(self):
        c = self.canv; lw, cw = self.w * 0.30, 78
        c.setStrokeColor(RULE); c.setLineWidth(0.5); c.line(0, self.H + 3, self.w, self.H + 3)
        c.setFont('Helvetica-Bold', 9); c.setFillColor(INK); c.drawString(0, self.H - 10, self.label)
        if self.hint:
            c.setFont('Helvetica', 7.6); c.setFillColor(MUTED)
            y = self.H - 21
            for line in self.hint.split('\n'): c.drawString(0, y, line); y -= 9.5
        c.acroForm.choice(name=f'result_{self.key}', tooltip=f'{self.label}: result', value=' ',
                          options=[' ', 'Pass', 'Fail', 'Blocked'], x=lw, y=self.H - 18, width=cw, height=17,
                          fontName='Helvetica', fontSize=9, borderWidth=0.5, borderColor=RULE, fillColor=colors.white,
                          textColor=INK, forceBorder=True, relative=True)
        nx = lw + cw + 8
        c.acroForm.textfield(name=f'notes_{self.key}', tooltip=f'{self.label}: notes', x=nx, y=0, width=self.w - nx, height=self.H - 1,
                             fontName='Helvetica', fontSize=8.5, borderWidth=0.5, borderColor=RULE, fillColor=colors.white,
                             textColor=INK, forceBorder=True, relative=True, fieldFlags='multiline')


def result_box(key, label):
    return KeepTogether([Spacer(1, 4), ResultRow(key, f'Result: {label}', 'Pass, Fail or Blocked.\nNotes on the right.')])


S = []
S += [Paragraph('QuarkShield CMVP / FIPS Test Plan', h1),
      Paragraph('Version of 19 November 2026 &nbsp;·&nbsp; Console under test: https://spinovation.quarkshield.ai/ &nbsp;·&nbsp; '
                'This PDF is fillable: type results into the boxes and save.', small), Spacer(1, 6)]
S += [Field('tester_name', 'Tester name'), Field('tester_dates', 'Test dates (IST)'),
      Field('tester_hosts', 'Host names used (normal host, FIPS server)')]

S += [H2('Purpose and scope'),
      P('This plan checks the six CMVP / FIPS stages and three later additions on the live console. Each test case has numbered steps and an expected result. Record Pass, Fail or Blocked for every case.'),
      P('The product reports evidence as observed. It never certifies a system, and QuarkShield itself is not CMVP-validated. A result that says "module not validated" or "not determined" is often the correct result, so compare with the expected result and do not assume it is a defect.')]
S += table([['Stage', 'What it checks', 'Needs'],
            ['1', 'FIPS status of each algorithm', 'Setup A and B'],
            ['2', 'NIST quantum security level in the CycloneDX export', 'Setup B'],
            ['3', 'CMVP certificate for cloud KMS keys', 'Setup C'],
            ['4', 'Host cryptographic module identity', 'Setup A and B'],
            ['5', 'FIPS-mode gate and verdict', 'Setup B'],
            ['6', "Algorithm on the module's CAVP list", 'Setup B or C'],
            ['A1', 'Host keys tied to the system module, labelled as assumed', 'Setup B'],
            ['A2', '"Export FIPS / CMVP Evidence (CSV)" button', 'Setup A'],
            ['A3', 'Agent versions 2.3.2 and 2.3.3 on the download page', 'None']], [0.10, 0.62, 0.28])
S += [P('The tenant already holds about 900 assets from other hosts. Filter by your own host name in every test so you only judge your own rows.')]

S += [H2('Before you start'), P('You need four things. The first two come from the QuarkShield owner; the last two you create yourself.')]
S += table([['Item', 'Detail', 'Who provides it'],
            ['Console login', 'A user on the spinovation tenant, created under Settings > Team & 2FA', 'Owner'],
            ['Entitlements', 'The tenant must have the Risk Assurance add-on (for the evidence CSV) and the Integrations entitlement (for vault connectors)', 'Owner confirms'],
            ['AWS account', 'Any account where you can create an EC2 instance, a KMS key and an IAM user. Use region ap-south-1 (Mumbai)', 'Tester'],
            ['A normal host', 'Your own Windows, macOS or Linux machine with admin rights', 'Tester']], [0.20, 0.60, 0.20])
S += [P('Expected AWS cost is small: one t3.small instance for a few hours and three KMS keys at about 1 USD per key per month, charged pro rata. The section "Clean up" at the end removes all of it.'),
      P('**Never paste AWS secret keys, the enrollment token or your console password into this form, chat or email.**')]

S += [H2('Setup A: enroll a normal host'), P('This puts one ordinary machine (not in FIPS mode) into the console. It takes about 10 minutes.')]
S += steps(['Sign in at https://spinovation.quarkshield.ai/.',
            'Open **Fleet Overview** and click **Generate Fleet Token / Enroll Device**.',
            'In the dialog, click **Generate Token**.',
            'Pick the tab for your operating system (macOS, Windows (PS) or Linux) and click **Copy Command**.',
            'Run the copied command on your machine. macOS and Linux: in a terminal. Windows: in PowerShell opened as Administrator.',
            'Wait up to 5 minutes, then reload the console.',
            'If your host is not listed under **Enrolled Workstations**, click **Pull All** and reload after 2 minutes.',
            'Write down the host name exactly as the console shows it. You will filter by it in every test.'])
S += [P('**Expected:** your host appears under Enrolled Workstations as online, with an agent version of 2.3.2 or later and an asset count above zero.'),
      P('The one-line installer installs agent 2.3.2, which is the current default. Test case A3 covers 2.3.3.'), result_box('setup_a', 'Setup A')]

S += [H2('Setup B: a Linux host in FIPS mode'),
      P('This creates a Red Hat Enterprise Linux 9 server on AWS, switches it to FIPS mode and enrolls it. It takes about 30 minutes. Use RHEL 9, not RHEL 10: the commands below do not exist on RHEL 10.'),
      H3('B1. Create the server')]
S += steps(['Sign in to the AWS console and set the region to **Asia Pacific (Mumbai) ap-south-1**.',
            'Go to **EC2 > Instances > Launch instances**.', 'Name: `qs-fips-test`.',
            'Under Application and OS Images choose **Red Hat**, then **Red Hat Enterprise Linux 9 (HVM), SSD Volume Type**, architecture **64-bit (x86)**.',
            'Instance type: **t3.small**.',
            'Key pair: create a new one named `qs-fips-test`, type RSA, format .pem, and save the file.',
            'Network settings: allow SSH from **My IP** only.', 'Storage: leave the default.',
            'Click **Launch instance**, wait until its state is Running, and copy its public IPv4 address.',
            'Connect from your machine:'])
S += [wrap_code('chmod 400 qs-fips-test.pem\nssh -i qs-fips-test.pem ec2-user@<public-ip>'),
      H3('B2. Switch on FIPS mode'), wrap_code('sudo fips-mode-setup --enable\nsudo reboot'),
      P('Reconnect after about 2 minutes and run these four checks. Copy all four outputs into the box below.'),
      wrap_code('fips-mode-setup --check\ncat /proc/sys/crypto/fips_enabled\ncat /etc/crypto-policies/state/current\nopenssl list -providers'),
      P('**Expected:**')]
S += bullets(['First command prints `FIPS mode is enabled.`', 'Second prints `1`.', 'Third prints `FIPS`.',
              'Fourth lists a provider named `fips` with status `active` and a version such as `3.0.7-` followed by 16 characters. That version string decides the result of Stage 4, so record it exactly.'])
S += [Spacer(1, 4), Field('b2_outputs', 'B2: paste the four command outputs here', height=92, multiline=True),
      Field('b2_provider_version', 'B2: FIPS provider version string, exactly as printed'),
      H3('B3. Create test keys on the server'),
      wrap_code('sudo openssl req -x509 -newkey rsa:3072 -nodes -days 30 -subj "/CN=qs-fips-test" -keyout /etc/pki/tls/certs/qs-test-rsa.key -out /etc/pki/tls/certs/qs-test-rsa.crt\n'
                'sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=qs-fips-test-ec" -keyout /etc/pki/tls/certs/qs-test-ec.key -out /etc/pki/tls/certs/qs-test-ec.crt'),
      P('The keys go in `/etc/pki/tls/certs` on purpose: the agent scans that folder in every scan mode. These are throwaway test keys.'),
      P('**Expected:** both commands finish without an error and the four files exist.'),
      H3('B4. Enroll the server')]
S += steps(['In the console, repeat Setup A steps 2 to 4 and choose the **Linux** tab.',
            'Paste the copied command into the SSH session and run it.', 'Follow Setup A steps 6 to 8.'])
S += [P('**Expected:** a second host appears under Enrolled Workstations. Its name starts with `ip-` and ends with `.ap-south-1.compute.internal`.'),
      result_box('setup_b', 'Setup B')]

S += [H2('Setup C: AWS KMS keys and the console connector'),
      P('This creates three test keys in AWS KMS, a read-only IAM user, and a connector in the console. It takes about 20 minutes. The connector only lists and describes keys; it cannot use, change or delete them.'),
      H3('C1. Create three KMS keys'),
      P('In the AWS console, region **ap-south-1**, go to **Key Management Service > Customer managed keys > Create key**. Create the three keys below. For each one keep Key material origin as **KMS** and Regionality as **Single-Region**, and accept the defaults on the administrator and usage permission pages.')]
S += table([['Alias', 'Key type', 'Key usage', 'Key spec'],
            ['`qs-test-aes`', 'Symmetric', 'Encrypt and decrypt', 'SYMMETRIC_DEFAULT'],
            ['`qs-test-rsa3072`', 'Asymmetric', 'Sign and verify', 'RSA_3072'],
            ['`qs-test-ec256`', 'Asymmetric', 'Sign and verify', 'ECC_NIST_P256']], [0.27, 0.20, 0.27, 0.26])
S += [P('**Expected:** all three keys show status Enabled under Customer managed keys.'), H3('C2. Create a read-only IAM user')]
S += steps(['Go to **IAM > Policies > Create policy**, choose the **JSON** tab and paste the policy shown below.',
            'Name the policy `qs-kms-readonly` and create it.',
            'Go to **IAM > Users > Create user**. Name: `qs-kms-readonly`. Do not give console access.',
            'Choose **Attach policies directly**, select `qs-kms-readonly`, and create the user.',
            'Open the user, go to **Security credentials > Create access key**, choose **Third-party service**, and create it.',
            'Keep the Access key ID and Secret access key on screen for the next step. Do not save them anywhere else.'])
S += [wrap_code('{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Effect": "Allow",\n    "Action": ["kms:ListKeys", "kms:DescribeKey", "kms:ListAliases", "kms:GetKeyRotationStatus"],\n    "Resource": "*"\n  }]\n}'),
      H3('C3. Connect it in the console')]
S += steps(['In the console open **Integrations & Gateways**, then the **Enterprise PKI & Vaults** tab.',
            'Click **Add Vault Connector**.', 'Choose provider **AWS KMS**.',
            'Connector name: `AWS KMS test (ap-south-1)`.', 'AWS Region: `ap-south-1`.', 'IAM Role ARN: leave blank.',
            'Paste the Access Key ID and the Secret Access Key.', 'Click **Save & Execute Initial Sync**.'])
S += [P('**Expected:**')]
S += bullets(['A green message reads "Synchronized AWS KMS test (ap-south-1): Discovered N keys", where N is 3 or more. AWS-managed keys in the account are also counted.',
              'The connector card shows the same key count.',
              'The three aliases appear in the table "Discovered Cryptographic Key & Certificate Inventory".',
              'The secret key is never shown again anywhere in the console.'])
S += [P('If the message is an error, record its full text and mark Stage 3 as Blocked.'), result_box('setup_c', 'Setup C')]

S += [PageBreak(), H2('Test cases: Stages 1 to 6'),
      P('Unless a step says otherwise, work in **Cryptographic BOM (CBOM)** and type your host name in the search box first. Hover over any coloured chip to read its full explanation.'),
      H3('TC-1 Stage 1: FIPS status of each algorithm'), P('Needs Setup A and Setup B.')]
S += steps(['On your normal host (not the FIPS server), create a weak key in a folder the agent scans. Windows and macOS: your Documents folder. Linux: /etc/ssh (use sudo). Example for macOS: `openssl genrsa -out ~/Documents/qs-test-rsa1024.pem 1024`',
            'In the console click **Pull All** on Fleet Overview and wait 5 minutes.',
            'Open the CBOM tab and search for `qs-test`.', 'Read the FIPS chip on each row.'])
S += table([['Row', 'Expected FIPS chip'],
            ['`qs-test-rsa1024.pem` (normal host)', 'FIPS: disallowed'],
            ['`qs-test-rsa.key` and `qs-test-rsa.crt` (FIPS server, RSA 3072)', 'FIPS: approved, sunset. The hover text gives a disallowed-after date of 2035-12-31'],
            ['`qs-test-ec.key` and `qs-test-ec.crt` (FIPS server, P-256)', 'FIPS: approved, sunset']], [0.48, 0.52])
S += [P('Also expected: every row for your hosts carries exactly one FIPS chip. "FIPS: not determined" is allowed, but list each such row with its algorithm text in the notes.'),
      P('If `qs-test-rsa1024.pem` does not appear after two pulls, record the full path you used and mark that row Blocked.'), result_box('tc1', 'TC-1 Stage 1')]

S += [H3('TC-2 Stage 2: NIST quantum level in the CycloneDX export'), P('Needs Setup B. Setup C adds the last row.')]
S += steps(['On the CBOM tab click **Export Standard CBOM** and save the JSON file.',
            'Open it in a text editor and search for `qs-test-rsa`.',
            'In that component find `nistQuantumSecurityLevel` under `cryptoProperties`.',
            'Repeat for `qs-test-ec` and, if Setup C is done, `qs-test-aes`.'])
S += table([['Component', 'Expected `nistQuantumSecurityLevel`'], ['`qs-test-rsa` (RSA 3072)', '0'], ['`qs-test-ec` (P-256)', '0'], ['`qs-test-aes` (AES-256)', '5']], [0.5, 0.5])
S += [P('Also expected: the file opens as valid JSON, its `specVersion` is `1.6`, and each of these components has a property named `quarkshield:complianceVerdict`.'), result_box('tc2', 'TC-2 Stage 2')]

S += [H3('TC-3 Stage 3: CMVP certificate for cloud KMS keys'), P('Needs Setup C.')]
S += steps(['On the CBOM tab set the source filter to **Enterprise PKI** and search for `qs-test`.',
            'Read the module chip and the verdict chip on the three AWS rows.',
            'Hover over the module chip and read the text.',
            'Open https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4884 and compare.'])
S += table([['Row', 'Expected module chip', 'Expected verdict chip'],
            ['`qs-test-aes`', 'CMVP #4884 · FIPS 140-3 L3', 'Compliant · validated module'],
            ['`qs-test-rsa3072`', 'CMVP #4884 · FIPS 140-3 L3', 'Compliant · algorithm sunset'],
            ['`qs-test-ec256`', 'CMVP #4884 · FIPS 140-3 L3', 'Compliant · algorithm sunset']], [0.28, 0.36, 0.36])
S += [P('Also expected:')]
S += bullets(['The hover text names the module as AWS KMS HSM and says QuarkShield did not test the module.',
              'The NIST page for certificate 4884 shows status Active, FIPS 140-3, Level 3. If NIST shows anything else, record what it shows.',
              'The tile **In a Validated Module** on the CBOM tab shows a number of 3 or more.'])
S += [result_box('tc3', 'TC-3 Stage 3')]

S += [H3('TC-4 Stage 4: host module identity'), P('Needs Setup A and Setup B.')]
S += steps(['On **Fleet Overview** find each of your two hosts and read the cryptographic modules listed for it.',
            'For the FIPS server, compare the module version with the `openssl list -providers` output you saved in B2.',
            'On the CBOM tab search for `openssl` on the FIPS server and read the module chip on that package row.'])
S += [P('Expected on the normal host, by operating system:')]
S += table([['Operating system', 'Expected module'],
            ['Windows', 'The Windows CNG cryptographic primitives library, with the Windows build number as its version'],
            ['macOS', 'Apple corecrypto with the macOS version, and LibreSSL'], ['Linux', 'OpenSSL with the installed version']], [0.25, 0.75])
S += [P('No module on the normal host may show "FIPS mode confirmed".'),
      P('Expected on the FIPS server: a module named "Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider" whose version equals the string from B2. What follows depends on that string:')]
S += table([['Version from B2', 'Expected chip', 'Outcome'],
            ['`3.0.7-cda111b5812c30d4`', '... · CMVP #5573 · FIPS mode confirmed', 'Outcome 1'],
            ['`3.0.7-395c1a240fbfffd8`', '... · CMVP #4857 (historical) · FIPS mode confirmed', 'Outcome 1, historical'],
            ['`3.0.1-3f45e68ee408cd9c`', '... · CMVP #4746 (historical) · FIPS mode confirmed', 'Outcome 1, historical'],
            ['Any other string', '... · no certificate matched', 'Outcome 2']], [0.32, 0.46, 0.22])
S += [P('Outcome 2 is correct behaviour, not a defect: the product does not guess a certificate for a build it has no record of. Report the exact version string so the reference table can be checked against NIST. With Outcome 2, mark TC-5 steps 1 to 3, TC-6 part B and TC-A1 as Blocked.'),
      result_box('tc4', 'TC-4 Stage 4 (state Outcome 1 or 2)')]

S += [H3('TC-5 Stage 5: FIPS-mode gate and verdict'), P('Needs Setup B with Outcome 1. Step 4 onward works with either outcome.')]
S += steps(["On the FIPS server's `openssl` package row, hover over the module chip.", 'Read the FIPS mode line.',
            'Read the verdict chip on that row and on the SSH configuration rows of the same host.',
            'Now switch FIPS mode off on the server: `sudo fips-mode-setup --disable` then `sudo reboot`.',
            'After the reboot, click **Pull All**, wait 5 minutes and reload the CBOM tab.', 'Read the same chips again.',
            'Switch FIPS mode back on (`sudo fips-mode-setup --enable`, then `sudo reboot`), pull again, and confirm the chips return to the step 2 state.'])
S += [P('Expected in steps 1 to 3:')]
S += bullets(['The hover text says FIPS mode: confirmed, and quotes `/proc/sys/crypto/fips_enabled = 1` and a crypto policy of FIPS.',
              'Rows tied to the module with an approved algorithm show "Compliant · validated module", "Compliant · algorithm sunset" or "Validated module · algorithm not on its list". With certificate #4857 or #4746 they show "Module certificate historical" instead.',
              'No row with a "FIPS: disallowed" chip shows any Compliant verdict.'])
S += [P('Expected in step 6:')]
S += bullets(['No chip on this host says "FIPS mode confirmed". The module chip reads "candidate CMVP #..." instead.',
              'The same rows now show "Approved algorithm · module not validated".'])
S += [result_box('tc5', 'TC-5 Stage 5')]

S += [H3("TC-6 Stage 6: algorithm on the module's CAVP list"), P('Part A needs Setup C. Part B needs Setup B with Outcome 1 and FIPS mode on.'), P('**Part A**')]
S += steps(['Hover over the verdict chip on each of the three AWS rows.', 'Read the line that starts "Algorithm list (CAVP)".'])
S += [P('**Expected:** each of the three says covered.'), P('**Part B**')]
S += steps(['On the FIPS server search for `ssh_host_ed25519_key`.', 'Read its verdict chip and hover over it.'])
S += [P('**Expected:** the verdict is "Validated module · algorithm not on its list" and the hover text says not covered. Certificate #5573 does not list EdDSA, so this is the correct result. If the server has no Ed25519 host key, mark Part B Blocked.'),
      result_box('tc6', 'TC-6 Stage 6')]

S += [PageBreak(), H2('Test cases: additional components'),
      H3('TC-A1 Host keys tied to the system module, labelled as assumed'), P('Needs Setup B with Outcome 1 and FIPS mode on.'),
      P('A key file does not say which library uses it. On a host whose system module passed the FIPS-mode gate, the console ties key and certificate files to that module and labels the link as an assumption. This test checks the label is always present and that an assumption is never counted as compliant.')]
S += steps(['On the CBOM tab search for `qs-test-rsa.key` on the FIPS server.',
            'Read the module chip and the verdict chip, and hover over both.',
            'Repeat for `qs-test-rsa.crt`, `qs-test-ec.key` and `/etc/ssh/ssh_host_rsa_key`.',
            'Note the large number on the tile **In a Validated Module**, and the small line under it.',
            'Search your normal host for any chip that starts with "Assumed:".'])
S += [P('**Expected:**')]
S += bullets(['Each module chip in steps 1 to 3 starts with "Assumed:" followed by the Red Hat module name and "CMVP #5573 · FIPS mode confirmed".',
              'Each verdict chip reads "Approved algorithm · system module assumed". None reads "Compliant".',
              'The hover text says the link is assumed, not observed.',
              'The small line under the tile includes "system module assumed" with a count. Clicking it filters the list to those rows. The large number does not include them.',
              'Step 5 finds nothing: no row on the normal host is labelled "Assumed:".',
              'Source-code rows, package rows and the AWS rows are never labelled "Assumed:".'])
S += [result_box('tca1', 'TC-A1 Host attribution')]

S += [H3('TC-A2 Evidence CSV button'), P('Needs Setup A. Setup B and C add more rows to check.')]
S += steps(['On the CBOM tab click the green button **Export FIPS / CMVP Evidence (CSV)**. The download can take a minute.',
            'Open the file in a spreadsheet.', 'Filter the Host column to your hosts.'])
S += [P('**Expected:**')]
S += bullets(['The file name is `QuarkShield-FIPS-CMVP-Evidence-SPINOVATIONCORP-<date>.csv`.',
              'The first rows start with `# Report`, `# Tenant`, `# Generated` and three reference-table dates, then a row "# Reading this report" that contains the words "not a certification".',
              'The column header row has 30 columns, from Asset to Note.', 'No cell is run as a formula by the spreadsheet.',
              "Each row's Verdict matches the verdict chip you saw in the console for that asset."])
S += table([['Asset', 'Expected Module basis', 'Expected Verdict'],
            ['`qs-test-aes` (AWS)', 'provider-reported', 'compliant'], ['`qs-test-rsa3072` (AWS)', 'provider-reported', 'compliant_until'],
            ['`qs-test-rsa.key` (FIPS server, Outcome 1)', 'host-assumed', 'compliant_assumed_module'],
            ['`qs-test-rsa1024.pem` (normal host)', 'blank', 'noncompliant']], [0.44, 0.26, 0.30])
S += [P('For the AWS rows the CMVP certificate column reads `#4884` and "Algorithm on module CAVP list" reads `covered`.'), result_box('tca2', 'TC-A2 Evidence CSV')]

S += [H3('TC-A3 Agent versions on the download page'), P('Needs nothing.')]
S += steps(['Open https://quarkshield.ai/ and go to the downloads section.',
            'Read the version on the main button for each platform and on the "Also available" line.',
            'Download the 2.3.3 package for your operating system from the "Also available" line.',
            'On Windows, right-click the installer, open Properties > Digital Signatures and record the signer name. On macOS, open the disk image and confirm no "unidentified developer" warning appears.',
            'Install it over the existing agent and open its Help > About.',
            "Open the agent's Software BOM screen and read the headline.",
            'After 5 minutes, check the agent version shown for your host in the console.'])
S += [P('**Expected:**')]
S += bullets(['Main buttons read v2.3.2. The "Also available" line reads v2.3.3.',
              'The download completes and the file opens. Record the download time, because slow downloads were seen from one location.',
              'The Windows installer carries a valid digital signature. macOS opens the app without a security warning.',
              'About shows 2.3.3, and the console shows 2.3.3 for the host.',
              'The Software BOM headline reads "No Known-Vulnerable Package Versions Found". It does not say "PQC Ready" and does not claim a live NVD or CISA KEV lookup.'])
S += [result_box('tca3', 'TC-A3 Agent versions')]

S += [H2('Not built, so not in this test'), P('Do not raise these as defects. They are known gaps.')]
S += bullets(['The compliance verdict does not appear in the roadmap report, the executive report or the QSG posture feed.',
              'There is no PDF version of the evidence export.',
              'macOS hosts never reach "FIPS mode confirmed": the reference table has no approved-mode rule for Apple corecrypto.',
              'Keystore files (for example `.pfx`, `.jks`) are never tied to a module.',
              'Serverless workloads (AWS Lambda, Azure Functions, Cloud Functions) are not inventoried.',
              "The agent's Software BOM check uses built-in version rules, not a live vulnerability feed.",
              'Console push-upgrade of agents is built but is not part of this plan, because 2.3.2 is still the default version.',
              'Azure Key Vault, Google Cloud KMS and HashiCorp Vault connectors follow the same path as AWS KMS but are not covered here.'])

S += [H2('Reporting results'),
      P('Fill in the result box under each setup and test case, then save this PDF and send it back. For every Fail give the row or asset name, what you expected and what you saw. Send with it:')]
S += bullets(['A screenshot of each chip you judged, with the hover text visible where a step asked for it.',
              'The exported CycloneDX JSON and the evidence CSV.', 'The agent version and operating system of each host.',
              'The date and time (IST) of each sync, so server logs can be matched.'])
S += [P('Redact the AWS account number if you prefer. Never include access keys, the enrollment token or passwords.'),
      Spacer(1, 4), Field('overall_notes', 'Overall notes and defects found', height=110, multiline=True)]

S += [H2('Clean up'), P('Do this after the results are sent.')]
S += steps(['Console: on the Enterprise PKI & Vaults tab, delete the connector with the bin icon on its card.',
            'AWS IAM: delete the access key, then the user `qs-kms-readonly`, then the policy `qs-kms-readonly`.',
            'AWS KMS: for each of the three keys choose **Key actions > Schedule key deletion** with the minimum waiting period of 7 days.',
            'AWS EC2: terminate the instance `qs-fips-test`, then delete the key pair `qs-fips-test` and its security group.',
            'Your normal host: delete `qs-test-rsa1024.pem`. Uninstall the agent if you do not want to keep it.',
            'Tell the owner the names of your two hosts so they can be removed from the tenant and their seats released.'])


def footer(c, d):
    c.saveState(); c.setFont('Helvetica', 7.5); c.setFillColor(MUTED)
    c.drawString(18 * mm, 10 * mm, 'QuarkShield CMVP / FIPS Test Plan · evidence as observed, not a certification')
    c.drawRightString(A4[0] - 18 * mm, 10 * mm, f'Page {d.page}'); c.restoreState()


doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                        title='QuarkShield CMVP / FIPS Test Plan', author='QuarkShield', subject='Test cases and expected results, Stages 1 to 6')
doc.build(S, onFirstPage=footer, onLaterPages=footer)
