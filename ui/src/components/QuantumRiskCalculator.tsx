import { useState } from 'react';

/**
 * Standalone lead-gen tool at /quantum-risk — the "Encryption Expiration Date"
 * calculator (Mosca's inequality). Rendered outside the console/landing view
 * shells (see main.tsx) so it has a clean, shareable URL.
 */

const NOW = 2026;
const SPAN = 30; // years shown on the axis
const CAL_LINK = 'https://cal.com/sridhar-ganapati-twnjrp/pqc-assessment';

const pct = (years: number) => Math.max(0, Math.min(100, (years / SPAN) * 100));

const CSS = `
.qrc { --bg:#0c0a14; --surface:#16121f; --surface-2:#1e1830; --fg:#f2eefb; --muted:#9a92ad;
  --line:#2a2340; --accent:#7c3aed; --accent-2:#c084fc; --accent-soft:#241a38; --safe:#0f9d6a;
  --warn:#d97706; --danger:#dc2626; --danger-soft:#351820;
  --font-display:'Sora',ui-sans-serif,system-ui,sans-serif;
  --font-body:'IBM Plex Sans',ui-sans-serif,system-ui,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,'SF Mono',monospace;
  background:var(--bg); color:var(--fg); font-family:var(--font-body); min-height:100vh; }
.qrc * { box-sizing:border-box; }
.qrc-top { display:flex; align-items:center; justify-content:space-between; gap:16px;
  max-width:820px; margin:0 auto; padding:20px 16px; }
.qrc-top a { color:var(--muted); text-decoration:none; font-size:14px; }
.qrc-top a:hover { color:var(--fg); }
.qrc-brand { font-family:var(--font-mono); font-size:14px; letter-spacing:1px; color:var(--accent-2); }
.qrc-wrap { max-width:720px; margin:0 auto; padding:12px 16px 56px; }
.qrc-eyebrow { font-family:var(--font-mono); font-size:12px; letter-spacing:.14em; text-transform:uppercase; color:var(--accent-2); margin:0 0 10px; }
.qrc h1 { font-family:var(--font-display); font-weight:700; font-size:clamp(28px,6vw,40px); line-height:1.08; letter-spacing:-.02em; margin:0 0 10px; }
.qrc .sub { color:var(--muted); font-size:15px; margin:0 0 28px; max-width:56ch; }
.qrc .card { background:var(--surface); border:1px solid var(--line); border-radius:16px; padding:22px; }
.qrc .controls { display:grid; gap:22px; }
.qrc .ctrl-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; margin-bottom:10px; }
.qrc .ctrl-label { font-weight:600; font-size:15px; }
.qrc .ctrl-hint { color:var(--muted); font-size:12.5px; margin-top:2px; font-weight:400; }
.qrc .ctrl-val { font-family:var(--font-mono); font-size:18px; font-weight:500; color:var(--accent-2); white-space:nowrap; font-variant-numeric:tabular-nums; }
.qrc input[type=range] { -webkit-appearance:none; appearance:none; width:100%; height:6px; border-radius:999px; background:var(--surface-2); outline:none; }
.qrc input[type=range]::-webkit-slider-thumb { -webkit-appearance:none; appearance:none; width:22px; height:22px; border-radius:50%; background:var(--accent-2); border:3px solid var(--surface); box-shadow:0 1px 4px rgba(0,0,0,.4); cursor:pointer; }
.qrc input[type=range]::-moz-range-thumb { width:22px; height:22px; border-radius:50%; background:var(--accent-2); border:3px solid var(--surface); cursor:pointer; }
.qrc .ticks { display:flex; justify-content:space-between; font-family:var(--font-mono); font-size:11px; color:var(--muted); margin-top:6px; }
.qrc .tl-card { margin-top:20px; }
.qrc .tl-title { font-family:var(--font-display); font-weight:600; font-size:15px; margin:0 0 16px; }
.qrc .track { position:relative; height:66px; margin:26px 0 8px; }
.qrc .axis { position:absolute; left:0; right:0; top:44px; height:2px; background:var(--line); }
.qrc .seg { position:absolute; top:30px; height:16px; border-radius:5px; transition:left .25s ease,width .25s ease; }
.qrc .seg-risk { background:linear-gradient(90deg,var(--accent),var(--accent-2)); }
.qrc .seg-exposed { background:var(--danger); }
.qrc .qday { position:absolute; top:8px; bottom:0; width:2px; background:var(--fg); transition:left .25s ease; }
.qrc .qflag { position:absolute; top:8px; width:7px; height:7px; border-radius:50%; background:var(--fg); transform:translate(-3px,-3px); transition:left .25s ease; }
.qrc .qlabel { position:absolute; top:-12px; transform:translateX(-50%); font-family:var(--font-mono); font-size:10px; letter-spacing:.08em; color:var(--fg); white-space:nowrap; transition:left .25s ease; }
.qrc .axis-labels { display:flex; justify-content:space-between; font-family:var(--font-mono); font-size:11px; color:var(--muted); }
.qrc .legend { display:flex; flex-wrap:wrap; gap:14px; margin-top:16px; font-size:12.5px; color:var(--muted); }
.qrc .legend span { display:inline-flex; align-items:center; gap:6px; }
.qrc .dot { width:11px; height:11px; border-radius:3px; display:inline-block; }
.qrc .verdict { margin-top:20px; border-radius:16px; padding:24px; border:1px solid var(--line); }
.qrc .verdict.exposed { background:var(--danger-soft); border-color:var(--danger); }
.qrc .verdict.safe { background:var(--accent-soft); }
.qrc .v-tag { font-family:var(--font-mono); font-size:12px; letter-spacing:.1em; text-transform:uppercase; margin:0 0 8px; font-weight:600; }
.qrc .verdict.exposed .v-tag { color:#f87171; }
.qrc .verdict.safe .v-tag { color:var(--safe); }
.qrc .v-head { font-family:var(--font-display); font-weight:700; font-size:clamp(20px,4.5vw,26px); line-height:1.15; margin:0 0 12px; }
.qrc .v-body { font-size:15px; color:var(--fg); margin:0; }
.qrc .bignum { font-family:var(--font-mono); font-variant-numeric:tabular-nums; }
.qrc .formula { margin-top:16px; font-family:var(--font-mono); font-size:13px; color:var(--muted); background:var(--surface-2); border-radius:10px; padding:12px 14px; text-align:center; }
.qrc .formula b { color:var(--fg); }
.qrc .cta { margin-top:24px; display:flex; flex-wrap:wrap; gap:12px; }
.qrc .btn { flex:1 1 200px; text-align:center; text-decoration:none; font-weight:600; font-size:15px; padding:14px 18px; border-radius:12px; }
.qrc .btn-primary { background:var(--accent); color:#fff; }
.qrc .btn-ghost { background:transparent; color:var(--fg); border:1px solid var(--line); }
.qrc .foot { margin-top:22px; font-size:12px; color:var(--muted); line-height:1.6; }
.qrc .foot a { color:var(--accent-2); }
`;

export default function QuantumRiskCalculator() {
  const [y, setY] = useState(10); // data secrecy lifetime
  const [x, setX] = useState(4);  // migration time
  const [z, setZ] = useState(9);  // years to Q-day

  const risk = x + y;
  const exposed = risk > z;
  const gap = risk - z;
  const margin = z - risk;
  const startBy = NOW - gap;

  return (
    <div className="qrc">
      <style>{CSS}</style>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" />

      <div className="qrc-top">
        <a href="/">&larr; QuarkShield.ai</a>
        <span className="qrc-brand">Quantum Readiness</span>
      </div>

      <div className="qrc-wrap">
        <p className="qrc-eyebrow">Mosca&rsquo;s inequality</p>
        <h1>Does your data have a quantum expiration date?</h1>
        <p className="sub">Move the three sliders. This shows whether the encryption you rely on today will still protect your data long enough &mdash; using the same math security planners use. No jargon required.</p>

        <div className="card controls">
          <div>
            <div className="ctrl-head">
              <div>
                <div className="ctrl-label">How long must your data stay secret?</div>
                <div className="ctrl-hint">Contracts, health records, IP, state secrets &mdash; pick the longest.</div>
              </div>
              <div className="ctrl-val">{y} yrs</div>
            </div>
            <input type="range" min={1} max={30} step={1} value={y} onChange={(e) => setY(+e.target.value)} aria-label="Years data must stay secret" />
            <div className="ticks"><span>1 yr</span><span>15 yrs</span><span>30 yrs</span></div>
          </div>

          <div>
            <div className="ctrl-head">
              <div>
                <div className="ctrl-label">How long to migrate to quantum-safe encryption?</div>
                <div className="ctrl-hint">Finding + replacing crypto across an org. Last big change took 10+ yrs.</div>
              </div>
              <div className="ctrl-val">{x} yrs</div>
            </div>
            <input type="range" min={1} max={12} step={1} value={x} onChange={(e) => setX(+e.target.value)} aria-label="Years to migrate" />
            <div className="ticks"><span>1 yr</span><span>6 yrs</span><span>12 yrs</span></div>
          </div>

          <div>
            <div className="ctrl-head">
              <div>
                <div className="ctrl-label">When could a quantum computer break today&rsquo;s encryption?</div>
                <div className="ctrl-hint">Citi / Global Risk Institute: 19&ndash;34% chance by 2034. Drag your assumption.</div>
              </div>
              <div className="ctrl-val">{NOW + z}</div>
            </div>
            <input type="range" min={4} max={25} step={1} value={z} onChange={(e) => setZ(+e.target.value)} aria-label="Years until Q-day" />
            <div className="ticks"><span>2030</span><span>2040</span><span>2051</span></div>
          </div>
        </div>

        <div className="card tl-card">
          <p className="tl-title">Your timeline, starting today</p>
          <div className="track">
            <div className="axis" />
            {exposed ? (
              <>
                <div className="seg seg-risk" style={{ left: '0%', width: `${pct(z)}%` }} />
                <div className="seg seg-exposed" style={{ left: `${pct(z)}%`, width: `${pct(risk) - pct(z)}%` }} />
              </>
            ) : (
              <div className="seg seg-risk" style={{ left: '0%', width: `${pct(risk)}%` }} />
            )}
            <div className="qlabel" style={{ left: `${pct(z)}%` }}>Q-DAY {NOW + z}</div>
            <div className="qday" style={{ left: `${pct(z)}%` }} />
            <div className="qflag" style={{ left: `${pct(z)}%` }} />
          </div>
          <div className="axis-labels"><span>{NOW}</span><span>{NOW + SPAN}</span></div>
          <div className="legend">
            <span><i className="dot" style={{ background: 'linear-gradient(90deg,var(--accent),var(--accent-2))' }} />Window your data must survive</span>
            <span><i className="dot" style={{ background: 'var(--danger)' }} />Exposed (past Q-day)</span>
            <span><i className="dot" style={{ background: 'var(--fg)' }} />Q-day</span>
          </div>
        </div>

        <div className={`verdict ${exposed ? 'exposed' : 'safe'}`}>
          {exposed ? (
            <>
              <p className="v-tag">&#9888; Already exposed</p>
              <p className="v-head">Data you encrypt today could be readable <span className="bignum">{gap}</span> {gap === 1 ? 'year' : 'years'} before you finish protecting it.</p>
              <p className="v-body">{startBy < NOW
                ? <>To be safe you would have needed to <strong>start migrating in {startBy}</strong> &mdash; {NOW - startBy} {NOW - startBy === 1 ? 'year' : 'years'} ago. Every month of delay adds more &ldquo;harvest-now, decrypt-later&rdquo; data you can&rsquo;t take back.</>
                : <>Your window is already this tight. Waiting only widens the exposed zone.</>}</p>
            </>
          ) : (
            <>
              <p className="v-tag">&#10003; Margin &mdash; if you start now</p>
              <p className="v-head">You have about <span className="bignum">{margin}</span> {margin === 1 ? 'year' : 'years'} of margin &mdash; but only if migration starts now.</p>
              <p className="v-body">Slide &ldquo;time to migrate&rdquo; up by {margin + 1} or shorten Q-day and you cross into the danger zone. The margin is thinner than it looks.</p>
            </>
          )}
          <div className="formula">Migrate <b>{x}</b> + Secrecy <b>{y}</b> = <b>{risk} yrs</b> {exposed ? '>' : '≤'} Q-day <b>{z} yrs</b></div>
        </div>

        <div className="cta">
          <a className="btn btn-primary" href="/#downloads">Find your encryption &mdash; free scan</a>
          <a className="btn btn-ghost" href={CAL_LINK} target="_blank" rel="noopener">Book a 15-min assessment</a>
        </div>

        <p className="foot">
          Mosca&rsquo;s inequality: if the time to migrate (X) plus how long your data must stay secret (Y) exceeds the time until quantum computers arrive (Z), some data you protect today is already at risk. Q-day probabilities from the <a href="https://www.citigroup.com/rcs/citigpa/storage/public/Citi_Institute_Quantum_Threat.pdf" target="_blank" rel="noopener">Citi Institute Quantum Threat report (Jan 2026)</a> and the Global Risk Institute. Quantum-safe standards: NIST FIPS 203/204/205. This is an educational estimate, not a security audit.
        </p>
      </div>
    </div>
  );
}
