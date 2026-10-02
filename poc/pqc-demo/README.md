# QuarkShield — Pure‑PQC PoC (Track 2)

A self‑contained proof‑of‑concept demonstrating **CNSA 2.0 pure post‑quantum data protection** on NIST‑standardized algorithms, aligned to the DoW "Software Based Encryption" RFI: **no hybrid, no pre‑shared keys, client‑side key custody.**

- **ML‑KEM‑1024** (FIPS 203) — key encapsulation (the RFI's required key transport)
- **ML‑DSA‑87** (FIPS 204) — signatures for authenticity / provenance
- **AES‑256‑GCM** — content encryption (128‑bit PQ security under Grover; CNSA 2.0 symmetric choice)
- Pure Go via Cloudflare **CIRCL** — no system crypto deps, runs anywhere Go runs.

## Run (demo)
```bash
cd poc/pqc-demo
go run .                      # encrypts a built-in sample message
go run . /path/to/file        # encrypts any file, round-trips it
```

Build a standalone binary for a cleaner live demo:
```bash
go build -o quarkshield-pqc-demo .
./quarkshield-pqc-demo
```

## What it proves (and the honesty line to say in a demo)
> "This is a proof‑of‑concept on the NIST FIPS 203/204 algorithms — pure ML‑KEM‑1024, no hybrid, no pre‑shared keys, keys held on the endpoints. The **production** product will run on **FIPS‑validated** modules (OpenSSL 3.5 FIPS provider / AWS‑LC‑FIPS) and pursue **ATLAS** authorization. It shows QuarkShield isn't just assessing crypto — it's building toward the pure‑PQC data protection the RFI describes."

## Not production
- CIRCL is **not** FIPS‑validated — PoC/demonstration only.
- No PKI binding yet (production ties the ML‑DSA identity to a PQC X.509 cert).
- See `Track2-PurePQC-SDE-Scoping.md` for the production architecture, validated‑module path, and ATLAS/FIPS timeline.
