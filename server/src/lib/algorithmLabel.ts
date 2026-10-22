// Canonicalize the descriptive prose "algorithm" labels the agent emits.
//
// The Go agent sometimes stores a human sentence in the Algorithm field instead
// of a canonical crypto identity — e.g. "Classical TLS / KEX Protocol",
// "Legacy Protocol (SSL 2.0)", "OS Package / Security Runtime". That is fine for
// the agent's own console output, but once it lands in assets.algorithm it:
//   - looks inconsistent next to real names ("RSA-2048", "ECDSA-256", "AES-256-GCM"),
//   - fragments the CBOM / crypto-dependency inventory (every distinct sentence
//     becomes its own "algorithm"), and
//   - carries the real identity (the protocol/cipher) buried inside parentheses.
//
// This normalizer runs at INGEST so the fix applies without an agent rebuild
// (the agent-side source fix is a follow-up). It NEVER changes vulnerability
// classification — callers must still compute Shor/Grover/risk from the raw
// value. It only produces a clean, consistent label for storage and display.
//
// Design rules:
//   1. Never invent a specific algorithm that was not detected. Where the prose
//      is generic ("Classical TLS / KEX Protocol") we keep it generic but tidy.
//   2. Where a concrete identity is embedded in parentheses ("Legacy Protocol
//      (SSL 2.0)") we surface it ("SSL 2.0").
//   3. Already-canonical names (RSA-2048, ML-KEM-768, SHA-256, AES-256-GCM, ...)
//      pass through untouched.

// Exact-match prose → canonical label.
const EXACT: Record<string, string> = {
  'classical tls / kex protocol': 'TLS key exchange (classical)',
  'tls 1.3 / https network transport': 'TLS 1.3',
  'https client / tls 1.3 transport': 'TLS 1.3',
  'diffie-hellman (classical kex)': 'Diffie-Hellman',
  'aes-128 / symmetric cipher': 'AES-128',
  'symmetric/protocol config': 'Symmetric/protocol config',
  'pyca / openssl backend / classical & hybrid': 'OpenSSL/PyCA crypto backend',
  'pyca / openssl primitives': 'OpenSSL/PyCA crypto backend',
  'go cryptography / ssh / openpgp': 'Go crypto library',
  'os package / security runtime': 'Security runtime (OS package)',
  'openssl security level': 'OpenSSL security level',
  'legacy ssh cipher/kex': 'Legacy SSH cipher/KEX',
  'legacy tls protocol (tls 1.0/1.1)': 'TLS 1.0/1.1',
};

// Prefix-wrapped prose where the real identity sits in trailing parentheses:
// "<wrapper> (<detail>)" → canonicalize using <detail>.
const PAREN_WRAPPERS: { re: RegExp; render: (detail: string) => string }[] = [
  // "Legacy Protocol (SSL 2.0)" / "Legacy TLS Protocol (TLS 1.0/1.1)" → the protocol itself
  { re: /^legacy(?: tls)? protocol \((.+)\)$/i, render: (d) => d },
  // "Legacy Kernel Cipher (des_cbc)" → "des_cbc (kernel cipher)"
  { re: /^legacy kernel cipher \((.+)\)$/i, render: (d) => `${d} (kernel cipher)` },
  // "System Crypto Policy (LEGACY)" → "System crypto policy: LEGACY"
  { re: /^system crypto policy \((.+)\)$/i, render: (d) => `System crypto policy: ${d}` },
];

/**
 * Normalize a raw agent-supplied algorithm label to a clean, consistent form.
 * Returns the input unchanged when it is empty, already canonical, or unknown.
 */
export function canonicalizeAlgorithmLabel(raw: string | null | undefined): string {
  if (raw == null) return '';
  const value = String(raw).trim();
  if (!value) return '';

  const key = value.toLowerCase();

  if (EXACT[key]) return EXACT[key];

  for (const w of PAREN_WRAPPERS) {
    const m = value.match(w.re);
    if (m) return w.render(m[1].trim());
  }

  // Not a known prose label — leave real algorithm identities untouched.
  return value;
}
