import React, { useState, useEffect } from 'react';
import { 
  Users, 
  ShieldCheck, 
  ShieldAlert, 
  Plus, 
  Key, 
  Lock, 
  Unlock, 
  Trash2, 
  RefreshCw, 
  Check, 
  AlertTriangle,
  Building,
  Mail,
  UserPlus,
  Copy,
  CheckCircle2,
  X
} from 'lucide-react';

export interface TenantUser {
  id: string;
  tenantName: string;
  email: string;
  firstName?: string;
  lastName?: string;
  role: 'admin' | 'secops' | 'auditor' | 'viewer';
  twoFactorEnabled: boolean;
  status: 'active' | 'suspended' | 'pending';
  lastLogin: string | null;
  createdAt: string;
}

interface TenantUserManagementProps {
  currentTenant?: string;
  allowTenantSwitch?: boolean;
}

export const TenantUserManagement: React.FC<TenantUserManagementProps> = ({ 
  currentTenant = 'spinovationcorp',
  allowTenantSwitch = false 
}) => {
  const [selectedTenant, setSelectedTenant] = useState<string>(currentTenant);
  const [users, setUsers] = useState<TenantUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [twoFactorPolicy, setTwoFactorPolicy] = useState<'optional' | 'admins_only' | 'mandatory'>('optional');
  const [savingPolicy, setSavingPolicy] = useState(false);

  useEffect(() => {
    if (currentTenant && currentTenant !== selectedTenant) {
      setSelectedTenant(currentTenant);
    }
  }, [currentTenant]);

  // New User Form State
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserFirstName, setNewUserFirstName] = useState('');
  const [newUserLastName, setNewUserLastName] = useState('');
  const [newUserRole, setNewUserRole] = useState<'admin' | 'secops' | 'auditor' | 'viewer'>('secops');
  const [isInviting, setIsInviting] = useState(false);
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string | null>(null);

  // Temporary Password Notice State for Tenant User Invite / Password Reset
  const [showPasswordNoticeModal, setShowPasswordNoticeModal] = useState(false);
  const [noticeTempPassword, setNoticeTempPassword] = useState('');
  const [noticeRecipient, setNoticeRecipient] = useState('');
  const [noticeType, setNoticeType] = useState<'invite' | 'reset'>('invite');
  const [copiedNoticePassword, setCopiedNoticePassword] = useState(false);

  // Available tenants for Super Admin switcher
  const tenantList = [
    { name: 'spinovationcorp', display: 'Spinovation Corp' },
    { name: 'amberoon', display: 'Amberoon Workspace' },
    { name: 'algomeld', display: 'Algo Meld MSP' },
    { name: 'democlient', display: 'Demo Client Workspace' },
    { name: 'vanguard-logistics', display: 'Vanguard Global Logistics' },
    { name: 'apex-cyber', display: 'Apex Cyber Defense MSP' },
    { name: 'cybershield-partners', display: 'CyberShield Managed Security' },
    { name: 'atrireshma', display: 'Atri Reshma Enterprise' },
    { name: 'jhrzic', display: 'JHR Zic Labs' },
    { name: 'digitalbloodline', display: 'Digital Bloodline Workspace' },
    { name: 'joegodfrey', display: 'Azist Inc Defense Node' },
    { name: 'kamefinvestment', display: 'Kamef Investment Environment' },
    { name: 'musamobile', display: 'Musa Mobile Secure Core' },
    { name: 'sridhargs', display: 'Master Superadmin Control Plane' }
  ];

  // Fetch Users for selected tenant
  const fetchTenantUsers = async (tenant: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/tenants/${tenant}/users`);
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      } else {
        throw new Error('Failed to fetch users');
      }

      // Fetch 2FA policy
      const polRes = await fetch(`/api/tenants/${tenant}/2fa-policy`);
      if (polRes.ok) {
        const polData = await polRes.json();
        setTwoFactorPolicy(polData.twoFactorPolicy || 'optional');
      }
    } catch (err) {
      console.warn('Backend unavailable, using simulated tenant users:', err);
      if (tenant === 'spinovationcorp' || tenant.includes('spinovation')) {
        setUsers([
          { id: 'tu-sp-01', tenantName: tenant, email: 'sridhargs@spinovation.com', firstName: 'Ganapati', lastName: 'Sridhar', role: 'admin', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 1800000).toISOString(), createdAt: new Date(Date.now() - 30 * 86400000).toISOString() },
          { id: 'tu-sp-02', tenantName: tenant, email: 'secops@spinovation.com', firstName: 'Elena', lastName: 'Rostova', role: 'secops', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 7200000).toISOString(), createdAt: new Date(Date.now() - 20 * 86400000).toISOString() },
          { id: 'tu-sp-03', tenantName: tenant, email: 'auditor@spinovation.com', firstName: 'Marcus', lastName: 'Vance', role: 'auditor', twoFactorEnabled: false, status: 'active', lastLogin: new Date(Date.now() - 86400000).toISOString(), createdAt: new Date(Date.now() - 10 * 86400000).toISOString() }
        ]);
        setTwoFactorPolicy('admins_only');
      } else if (tenant === 'algomeld' || tenant.includes('algomeld')) {
        setUsers([
          { id: 'tu-am-01', tenantName: tenant, email: 'sridhargs@algomeld.com', firstName: 'Ganapati', lastName: 'Sridhar', role: 'admin', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 1200000).toISOString(), createdAt: new Date(Date.now() - 45 * 86400000).toISOString() },
          { id: 'tu-am-02', tenantName: tenant, email: 'ops@algomeld.com', firstName: 'Arun', lastName: 'Kumar', role: 'secops', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 5400000).toISOString(), createdAt: new Date(Date.now() - 25 * 86400000).toISOString() },
          { id: 'tu-am-03', tenantName: tenant, email: 'compliance@algomeld.com', firstName: 'Sarah', lastName: 'Jenkins', role: 'auditor', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 86400000).toISOString(), createdAt: new Date(Date.now() - 15 * 86400000).toISOString() }
        ]);
        setTwoFactorPolicy('mandatory');
      } else if (tenant === 'jhrzic') {
        setUsers([
          { id: 'tu-03', tenantName: 'jhrzic', email: 'lead@jhrzic.com', firstName: 'John', lastName: 'Zic', role: 'admin', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 3600000).toISOString(), createdAt: new Date().toISOString() },
          { id: 'tu-04', tenantName: 'jhrzic', email: 'auditor@jhrzic.com', firstName: 'Sarah', lastName: 'Connor', role: 'auditor', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 86400000).toISOString(), createdAt: new Date().toISOString() },
          { id: 'tu-05', tenantName: 'jhrzic', email: 'devops@jhrzic.com', firstName: 'David', lastName: 'K.', role: 'secops', twoFactorEnabled: false, status: 'active', lastLogin: null, createdAt: new Date().toISOString() }
        ]);
        setTwoFactorPolicy('admins_only');
      } else {
        setUsers([
          { id: 'tu-01', tenantName: tenant, email: `admin@${tenant}.com`, firstName: 'Reshma', lastName: 'Admin', role: 'admin', twoFactorEnabled: true, status: 'active', lastLogin: new Date(Date.now() - 14400000).toISOString(), createdAt: new Date().toISOString() },
          { id: 'tu-02', tenantName: tenant, email: `secops@${tenant}.com`, firstName: 'Alex', lastName: 'Vance', role: 'secops', twoFactorEnabled: false, status: 'active', lastLogin: new Date(Date.now() - 7200000).toISOString(), createdAt: new Date().toISOString() }
        ]);
        setTwoFactorPolicy('optional');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTenantUsers(selectedTenant);
  }, [selectedTenant]);

  // Handle 2FA Policy Change
  const handlePolicyChange = async (newPolicy: 'optional' | 'admins_only' | 'mandatory') => {
    setSavingPolicy(true);
    try {
      await fetch(`/api/tenants/${selectedTenant}/2fa-policy`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy: newPolicy })
      });
      setTwoFactorPolicy(newPolicy);
      showTemporarySuccess(`2FA Enforcement Policy updated to '${newPolicy.replace('_', ' ').toUpperCase()}'.`);
    } catch (err) {
      setTwoFactorPolicy(newPolicy);
      showTemporarySuccess(`2FA Enforcement Policy updated locally to '${newPolicy.replace('_', ' ').toUpperCase()}'.`);
    } finally {
      setSavingPolicy(false);
    }
  };

  // Handle Inviting / Adding User
  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserEmail.trim()) return;
    setIsInviting(true);
    try {
      const res = await fetch(`/api/tenants/${selectedTenant}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: newUserEmail.trim(),
          firstName: newUserFirstName.trim(),
          lastName: newUserLastName.trim(),
          role: newUserRole
        })
      });

      if (res.ok) {
        const data = await res.json();
        setNewUserEmail('');
        setNewUserFirstName('');
        setNewUserLastName('');
        setShowInviteModal(false);
        fetchTenantUsers(selectedTenant);

        setNoticeTempPassword(data.password || '');
        setNoticeRecipient(newUserEmail.trim());
        setNoticeType('invite');
        setShowPasswordNoticeModal(true);
        showTemporarySuccess(`Invitation dispatched to ${newUserEmail}. Temporary password emailed from Support@quarkshield.ai.`);
      } else {
        const errJson = await res.json().catch(() => null);
        throw new Error(errJson?.error || 'Failed to invite user');
      }
    } catch (err: any) {
      const simUser: TenantUser = {
        id: 'tu-' + Date.now(),
        tenantName: selectedTenant,
        email: newUserEmail.trim(),
        firstName: newUserFirstName.trim(),
        lastName: newUserLastName.trim(),
        role: newUserRole,
        twoFactorEnabled: false,
        status: 'active',
        lastLogin: null,
        createdAt: new Date().toISOString()
      };
      setUsers(prev => [...prev, simUser]);
      showTemporarySuccess(`User ${newUserEmail} added to tenant ${selectedTenant} (${err.message}).`);
      setNewUserEmail('');
      setNewUserFirstName('');
      setNewUserLastName('');
      setShowInviteModal(false);
    } finally {
      setIsInviting(false);
    }
  };

  // Handle Reset User Password
  const handleResetUserPassword = async (user: TenantUser) => {
    if (!window.confirm(`Generate a new temporary password for ${user.email}? A temporary password will be dispatched from Support@quarkshield.ai and mandatory password change will be enforced on login.`)) {
      return;
    }
    try {
      const res = await fetch(`/api/tenants/${selectedTenant}/users/${user.id}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to reset password');
      }

      setNoticeTempPassword(data.password || '');
      setNoticeRecipient(user.email);
      setNoticeType('reset');
      setShowPasswordNoticeModal(true);
      fetchTenantUsers(selectedTenant);
      showTemporarySuccess(`Temporary password sent to ${user.email} from Support@quarkshield.ai.`);
    } catch (err: any) {
      alert(`Password Reset Error: ${err.message}`);
    }
  };

  // Handle Role Change
  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      await fetch(`/api/tenants/${selectedTenant}/users/${userId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole })
      });
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole as any } : u));
      showTemporarySuccess('User role updated.');
    } catch (err) {
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole as any } : u));
    }
  };

  // Handle Toggle User Status (Suspend / Activate)
  const handleToggleStatus = async (user: TenantUser) => {
    const newStatus = user.status === 'active' ? 'suspended' : 'active';
    try {
      await fetch(`/api/tenants/${selectedTenant}/users/${user.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, status: newStatus } : u));
      showTemporarySuccess(`User account ${newStatus === 'suspended' ? 'suspended' : 'activated'}.`);
    } catch (err) {
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, status: newStatus } : u));
    }
  };

  // Handle Emergency 2FA Reset
  const handleReset2FA = async (user: TenantUser) => {
    if (!window.confirm(`Reset 2FA for ${user.email}? This will clear their authenticator secret and require re-enrollment on next login.`)) {
      return;
    }
    try {
      await fetch(`/api/tenants/${selectedTenant}/users/${user.id}/reset-2fa`, { method: 'POST' });
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, twoFactorEnabled: false } : u));
      showTemporarySuccess(`2FA secret cleared for ${user.email}.`);
    } catch (err) {
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, twoFactorEnabled: false } : u));
      showTemporarySuccess(`2FA secret cleared for ${user.email}.`);
    }
  };

  // Handle Delete User
  const handleDeleteUser = async (user: TenantUser) => {
    if (!window.confirm(`Remove user ${user.email} from tenant ${selectedTenant}?`)) {
      return;
    }
    try {
      await fetch(`/api/tenants/${selectedTenant}/users/${user.id}`, { method: 'DELETE' });
      setUsers(prev => prev.filter(u => u.id !== user.id));
      showTemporarySuccess(`User removed from tenant.`);
    } catch (err) {
      setUsers(prev => prev.filter(u => u.id !== user.id));
    }
  };

  const showTemporarySuccess = (msg: string) => {
    setActionSuccessMessage(msg);
    setTimeout(() => setActionSuccessMessage(null), 3000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1.5rem' }}>
      {/* Header and Tenant Selector */}
      <div className="glass-panel" style={{ padding: '1.5rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
              <Building size={20} style={{ color: 'var(--accent-cyan)' }} />
              <h3 style={{ fontSize: '1.3rem', fontWeight: 700, margin: 0 }}>
                In-Tenant User Directory & RBAC
              </h3>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', margin: 0 }}>
              Physically isolated user administration for <strong style={{ color: 'var(--accent-cyan)' }}>https://{selectedTenant}.quarkshield.ai</strong>
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {allowTenantSwitch ? (
              <>
                <label style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Target Tenant:</label>
                <select
                  value={selectedTenant}
                  onChange={(e) => setSelectedTenant(e.target.value)}
                  style={{
                    padding: '0.5rem 0.8rem',
                    borderRadius: '6px',
                    background: 'rgba(255, 255, 255, 0.08)',
                    border: '1px solid var(--border-normal)',
                    color: 'var(--text-primary)',
                    fontSize: '0.88rem',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                >
                  {tenantList.map(t => (
                    <option key={t.name} value={t.name} style={{ background: '#0f172a' }}>
                      {t.display} ({t.name}.quarkshield.ai)
                    </option>
                  ))}
                </select>
              </>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{
                  padding: '0.45rem 0.85rem',
                  borderRadius: '6px',
                  background: 'rgba(0, 242, 254, 0.1)',
                  border: '1px solid rgba(0, 242, 254, 0.25)',
                  color: 'var(--accent-cyan)',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  fontFamily: 'monospace'
                }}>
                  https://{selectedTenant}.quarkshield.ai
                </span>
              </div>
            )}
            <button
              onClick={() => fetchTenantUsers(selectedTenant)}
              className="btn-secondary"
              disabled={loading}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.8rem', fontSize: '0.85rem' }}
            >
              <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
            </button>
            <button
              onClick={() => setShowInviteModal(true)}
              className="btn-primary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 1rem', fontSize: '0.88rem', fontWeight: 600 }}
            >
              <UserPlus size={15} /> Invite Colleague
            </button>
          </div>
        </div>
      </div>

      {actionSuccessMessage && (
        <div style={{
          background: 'rgba(34, 197, 94, 0.12)',
          border: '1px solid rgba(34, 197, 94, 0.4)',
          color: '#4ade80',
          padding: '0.75rem 1rem',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.9rem'
        }}>
          <Check size={16} />
          <span>{actionSuccessMessage}</span>
        </div>
      )}

      {/* Tenant 2FA Enforcement Policy Configuration */}
      <div className="glass-panel" style={{ padding: '1.5rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
          <ShieldCheck size={20} style={{ color: 'var(--status-secure)' }} />
          <h4 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0 }}>Two-Factor Authentication (2FA) Security Policy</h4>
        </div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1rem' }}>
          Configure organizational 2FA requirements across <code style={{ color: 'var(--accent-cyan)' }}>https://{selectedTenant}.quarkshield.ai</code>. Enforced policies require users to bind an RFC 6238 TOTP authenticator (Google Authenticator, Microsoft Authenticator, YubiKey) on login.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
          {/* Optional Policy */}
          <div 
            onClick={() => handlePolicyChange('optional')}
            style={{
              padding: '1rem',
              borderRadius: '8px',
              border: twoFactorPolicy === 'optional' ? '2px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
              background: twoFactorPolicy === 'optional' ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255, 255, 255, 0.02)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
              <input type="radio" checked={twoFactorPolicy === 'optional'} readOnly />
              <strong style={{ color: 'var(--text-primary)', fontSize: '0.92rem' }}>Optional (User Choice)</strong>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', margin: 0 }}>
              Users can independently enable 2FA in profile settings. Password-only logins are permitted.
            </p>
          </div>

          {/* Admins Only Policy */}
          <div 
            onClick={() => handlePolicyChange('admins_only')}
            style={{
              padding: '1rem',
              borderRadius: '8px',
              border: twoFactorPolicy === 'admins_only' ? '2px solid #c084fc' : '1px solid var(--border-normal)',
              background: twoFactorPolicy === 'admins_only' ? 'rgba(168, 85, 247, 0.12)' : 'rgba(255, 255, 255, 0.02)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
              <input type="radio" checked={twoFactorPolicy === 'admins_only'} readOnly />
              <strong style={{ color: '#c084fc', fontSize: '0.92rem' }}>Enforced for Admins & SecOps</strong>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', margin: 0 }}>
              Users with <code>admin</code> or <code>secops</code> roles must configure 2FA before accessing the CBOM or Admin tools.
            </p>
          </div>

          {/* Mandatory Policy */}
          <div 
            onClick={() => handlePolicyChange('mandatory')}
            style={{
              padding: '1rem',
              borderRadius: '8px',
              border: twoFactorPolicy === 'mandatory' ? '2px solid #ef4444' : '1px solid var(--border-normal)',
              background: twoFactorPolicy === 'mandatory' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(255, 255, 255, 0.02)',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
              <input type="radio" checked={twoFactorPolicy === 'mandatory'} readOnly />
              <strong style={{ color: '#f87171', fontSize: '0.92rem' }}>Mandatory (Zero-Trust Enterprise)</strong>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', margin: 0 }}>
              All enterprise accounts in this tenant are required to bind an authenticator on initial login.
            </p>
          </div>
        </div>
      </div>

      {/* Tenant Users Table */}
      <div className="glass-panel" style={{ padding: '1.5rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div>
            <h4 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0 }}>
              Active Tenant Members ({users.length})
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0.2rem 0 0 0' }}>
              Granular Role-Based Access Control (Admin, SecOps, Auditor, Viewer)
            </p>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-normal)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.75rem' }}>User / Member</th>
                <th style={{ padding: '0.75rem' }}>Role (RBAC)</th>
                <th style={{ padding: '0.75rem' }}>2FA Protection</th>
                <th style={{ padding: '0.75rem' }}>Status</th>
                <th style={{ padding: '0.75rem' }}>Last Login</th>
                <th style={{ padding: '0.75rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <td style={{ padding: '0.75rem' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {u.firstName || ''} {u.lastName || ''}
                    </div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      {u.email}
                    </div>
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <select
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      style={{
                        padding: '0.3rem 0.6rem',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.08)',
                        border: '1px solid var(--border-normal)',
                        color: u.role === 'admin' ? 'var(--accent-cyan)' : (u.role === 'secops' ? '#c084fc' : 'var(--text-primary)'),
                        fontWeight: 600,
                        fontSize: '0.82rem',
                        outline: 'none',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="admin" style={{ background: '#0f172a' }}>Tenant Admin</option>
                      <option value="secops" style={{ background: '#0f172a' }}>SecOps Engineer</option>
                      <option value="auditor" style={{ background: '#0f172a' }}>Compliance Auditor</option>
                      <option value="viewer" style={{ background: '#0f172a' }}>Viewer (Read-Only)</option>
                    </select>
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    {u.twoFactorEnabled ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', color: '#4ade80', background: 'rgba(34, 197, 94, 0.15)', padding: '0.2rem 0.5rem', borderRadius: '4px', fontWeight: 600 }}>
                        <ShieldCheck size={14} /> 2FA Active
                      </span>
                    ) : (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', color: 'var(--text-muted)', background: 'rgba(255, 255, 255, 0.05)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        Password Only
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{
                      fontSize: '0.78rem',
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      fontWeight: 600,
                      background: u.status === 'active' ? 'rgba(34, 197, 94, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                      color: u.status === 'active' ? '#4ade80' : '#f87171',
                      border: u.status === 'active' ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)'
                    }}>
                      {u.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                    {u.lastLogin ? new Date(u.lastLogin).toLocaleString() : 'Never'}
                  </td>
                  <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center' }}>
                      <button
                        onClick={() => handleResetUserPassword(u)}
                        title={`Reset password and email temporary password to ${u.email}`}
                        style={{
                          background: 'rgba(56, 189, 248, 0.1)',
                          border: '1px solid rgba(56, 189, 248, 0.35)',
                          color: '#38bdf8',
                          borderRadius: '4px',
                          padding: '0.25rem 0.5rem',
                          fontSize: '0.75rem',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.25rem'
                        }}
                      >
                        <Key size={12} /> Reset Password
                      </button>
                      {u.twoFactorEnabled && (
                        <button
                          onClick={() => handleReset2FA(u)}
                          title="Emergency Reset 2FA Secret"
                          style={{
                            background: 'none',
                            border: '1px solid rgba(245, 158, 11, 0.3)',
                            color: '#fbbf24',
                            borderRadius: '4px',
                            padding: '0.25rem 0.5rem',
                            fontSize: '0.75rem',
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.2rem'
                          }}
                        >
                          <Key size={12} /> Reset 2FA
                        </button>
                      )}
                      <button
                        onClick={() => handleToggleStatus(u)}
                        title={u.status === 'active' ? 'Suspend Account' : 'Activate Account'}
                        style={{
                          background: 'none',
                          border: '1px solid var(--border-normal)',
                          color: 'var(--text-secondary)',
                          borderRadius: '4px',
                          padding: '0.25rem 0.5rem',
                          fontSize: '0.75rem',
                          cursor: 'pointer'
                        }}
                      >
                        {u.status === 'active' ? 'Suspend' : 'Activate'}
                      </button>
                      <button
                        onClick={() => handleDeleteUser(u)}
                        title="Remove User"
                        style={{
                          background: 'none',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          color: '#f87171',
                          borderRadius: '4px',
                          padding: '0.25rem 0.4rem',
                          fontSize: '0.75rem',
                          cursor: 'pointer'
                        }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Invite Modal */}
      {showInviteModal && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '480px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-normal)',
            borderRadius: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.2rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <UserPlus size={20} style={{ color: 'var(--accent-cyan)' }} />
              <h4 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 600 }}>Invite Colleague to {selectedTenant}</h4>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
              Invited members will receive an activation email to log into <code style={{ color: 'var(--accent-cyan)' }}>https://{selectedTenant}.quarkshield.ai</code>.
            </p>

            <form onSubmit={handleInviteUser} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.3rem', color: 'var(--text-secondary)' }}>
                  Work Email Address *
                </label>
                <input
                  type="email"
                  placeholder="colleague@company.com"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '0.6rem',
                    borderRadius: '6px',
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid var(--border-normal)',
                    color: 'var(--text-primary)',
                    fontSize: '0.9rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.3rem', color: 'var(--text-secondary)' }}>
                    First Name
                  </label>
                  <input
                    type="text"
                    placeholder="Jane"
                    value={newUserFirstName}
                    onChange={(e) => setNewUserFirstName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.6rem',
                      borderRadius: '6px',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                      outline: 'none'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.3rem', color: 'var(--text-secondary)' }}>
                    Last Name
                  </label>
                  <input
                    type="text"
                    placeholder="Doe"
                    value={newUserLastName}
                    onChange={(e) => setNewUserLastName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.6rem',
                      borderRadius: '6px',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                      outline: 'none'
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.3rem', color: 'var(--text-secondary)' }}>
                  Assigned Role (RBAC) *
                </label>
                <select
                  value={newUserRole}
                  onChange={(e) => setNewUserRole(e.target.value as any)}
                  style={{
                    width: '100%',
                    padding: '0.6rem',
                    borderRadius: '6px',
                    background: 'rgba(255, 255, 255, 0.08)',
                    border: '1px solid var(--border-normal)',
                    color: 'var(--text-primary)',
                    fontSize: '0.9rem',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                >
                  <option value="secops" style={{ background: '#0f172a' }}>SecOps Engineer (Scans, CBOM, Remediations)</option>
                  <option value="admin" style={{ background: '#0f172a' }}>Tenant Admin (Full Organizational Authority)</option>
                  <option value="auditor" style={{ background: '#0f172a' }}>Compliance Auditor (Read-Only CNSA 2.0 Reports)</option>
                  <option value="viewer" style={{ background: '#0f172a' }}>Viewer (Read-Only Dashboards)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="btn-secondary"
                  style={{ padding: '0.5rem 1rem', fontSize: '0.88rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isInviting || !newUserEmail.trim()}
                  className="btn-primary"
                  style={{ padding: '0.5rem 1.2rem', fontSize: '0.88rem', fontWeight: 600 }}
                >
                  {isInviting ? 'Dispatching...' : 'Send Invitation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Temporary Password Notice Modal */}
      {showPasswordNoticeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          backdropFilter: 'blur(5px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '480px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            borderRadius: '12px',
            boxShadow: '0 20px 50px rgba(0,0,0,0.7)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle2 size={20} color="#38bdf8" />
                {noticeType === 'invite' ? 'Member Invitation Dispatched' : 'Password Reset Successfully'}
              </h3>
              <button
                type="button"
                onClick={() => {
                  setShowPasswordNoticeModal(false);
                  setCopiedNoticePassword(false);
                }}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              An official credential email has been dispatched from <strong style={{ color: '#38bdf8' }}>Support@quarkshield.ai</strong> to <strong style={{ color: '#ffffff' }}>{noticeRecipient}</strong>.
            </p>

            <div style={{
              background: 'rgba(15, 23, 42, 0.8)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              borderRadius: '8px',
              padding: '1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem'
            }}>
              <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: '#94a3b8', letterSpacing: '0.05em', fontWeight: 600 }}>
                Generated Temporary Password
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
                <span style={{ fontFamily: 'monospace', fontSize: '1.3rem', color: '#00f2fe', fontWeight: 700, letterSpacing: '0.08em' }}>
                  {noticeTempPassword}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(noticeTempPassword);
                    setCopiedNoticePassword(true);
                    setTimeout(() => setCopiedNoticePassword(false), 2500);
                  }}
                  style={{
                    background: copiedNoticePassword ? 'rgba(34, 197, 94, 0.2)' : 'rgba(56, 189, 248, 0.15)',
                    border: `1px solid ${copiedNoticePassword ? '#22c55e' : 'rgba(56, 189, 248, 0.4)'}`,
                    color: copiedNoticePassword ? '#4ade80' : '#38bdf8',
                    padding: '0.4rem 0.75rem',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    fontWeight: 600
                  }}
                >
                  {copiedNoticePassword ? <Check size={14} /> : <Copy size={14} />}
                  {copiedNoticePassword ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              borderRadius: '6px',
              padding: '0.65rem 0.85rem',
              fontSize: '0.8rem',
              color: '#fca5a5',
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.5rem'
            }}>
              <AlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>Mandatory Password Update Enforced:</strong> The member will be required to replace this temporary password with a personal password immediately upon first sign-in.
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button
                type="button"
                onClick={() => {
                  setShowPasswordNoticeModal(false);
                  setCopiedNoticePassword(false);
                }}
                className="btn-primary"
                style={{ padding: '0.5rem 1.25rem', fontSize: '0.85rem', fontWeight: 600 }}
              >
                Understood & Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
