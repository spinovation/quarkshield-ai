import { useState } from 'react';

/**
 * Standalone password-reset page. Rendered when the URL path is
 * /reset-password?token=... (the link emailed by /api/auth/forgot-password).
 * Submits the token + new password to /api/auth/reset-password.
 */
export default function ResetPasswordPage() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [status, setStatus] = useState<'idle' | 'submitting' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const goToSignIn = () => { window.location.href = '/'; };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage('');
    if (!token) { setStatus('error'); setMessage('This reset link is missing its token. Request a new one from the sign-in page.'); return; }
    if (password.length < 8) { setStatus('error'); setMessage('Password must be at least 8 characters.'); return; }
    if (password !== confirm) { setStatus('error'); setMessage('The two passwords do not match.'); return; }

    setStatus('submitting');
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token, newPassword: password }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        setStatus('success');
        setMessage(data.message || 'Your password has been updated.');
      } else {
        setStatus('error');
        setMessage(data.error || 'This reset link is invalid or has expired. Request a new one.');
      }
    } catch {
      setStatus('error');
      setMessage('Could not reach the server. Please try again.');
    }
  };

  const wrap: React.CSSProperties = {
    minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'radial-gradient(circle at 30% 20%, #0f172a 0%, #0b0f19 60%, #060913 100%)',
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", padding: 16,
  };
  const card: React.CSSProperties = {
    width: '100%', maxWidth: 440, background: 'rgba(15,23,42,0.85)', border: '1px solid #1e293b',
    borderRadius: 14, padding: 32, boxShadow: '0 20px 60px rgba(0,0,0,0.45)', color: '#e2e8f0',
  };
  const label: React.CSSProperties = { fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, color: '#94a3b8', marginBottom: 6, display: 'block' };
  const input: React.CSSProperties = {
    width: '100%', boxSizing: 'border-box', padding: '11px 12px', borderRadius: 8, border: '1px solid #334155',
    background: '#0b1220', color: '#f1f5f9', fontSize: 14, marginBottom: 14, outline: 'none',
  };
  const button: React.CSSProperties = {
    width: '100%', padding: '12px', borderRadius: 8, border: 'none', cursor: 'pointer', fontSize: 14, fontWeight: 700,
    background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)', color: '#fff',
  };
  const link: React.CSSProperties = { color: '#38bdf8', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, textDecoration: 'underline' };

  return (
    <div style={wrap}>
      <div style={card}>
        <div style={{ textAlign: 'center', marginBottom: 22 }}>
          <div style={{ fontSize: 22, fontWeight: 800, color: '#00f2fe', letterSpacing: 0.5 }}>QuarkShield</div>
          <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 4 }}>Reset your password</div>
        </div>

        {status === 'success' ? (
          <div style={{ textAlign: 'center' }}>
            <div style={{ background: 'rgba(21,128,61,0.15)', border: '1px solid #15803d', color: '#4ade80',
              borderRadius: 8, padding: 14, fontSize: 14, marginBottom: 18 }}>{message}</div>
            <button style={button} onClick={goToSignIn}>Go to sign in</button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <label style={label}>New password</label>
            <input style={input} type={show ? 'text' : 'password'} value={password}
              onChange={e => setPassword(e.target.value)} placeholder="At least 8 characters" autoFocus required />
            <label style={label}>Confirm new password</label>
            <input style={input} type={show ? 'text' : 'password'} value={confirm}
              onChange={e => setConfirm(e.target.value)} placeholder="Re-enter password" required />
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#94a3b8', marginBottom: 16 }}>
              <input type="checkbox" checked={show} onChange={e => setShow(e.target.checked)} /> Show password
            </label>

            {status === 'error' && (
              <div style={{ background: 'rgba(239,68,68,0.12)', borderLeft: '4px solid #ef4444', color: '#fca5a5',
                borderRadius: 4, padding: '10px 12px', fontSize: 13, marginBottom: 14 }}>{message}</div>
            )}

            <button style={{ ...button, opacity: status === 'submitting' ? 0.7 : 1 }} type="submit" disabled={status === 'submitting'}>
              {status === 'submitting' ? 'Updating…' : 'Update password'}
            </button>
            <div style={{ textAlign: 'center', marginTop: 16 }}>
              <button type="button" style={link} onClick={goToSignIn}>Back to sign in</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
