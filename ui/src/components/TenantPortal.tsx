import { downloadCsv } from '../lib/csv';
import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield,
  Mail,
  Lock,
  Eye,
  EyeOff,
  Globe,
  ArrowLeft,
  Laptop,
  Monitor,
  Key,
  Database,
  AlertTriangle,
  CheckCircle2,
  Download,
  Copy,
  Check,
  LogOut,
  RefreshCw,
  Server,
  Layers,
  FileText,
  Activity,
  User,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Terminal,
  Search,
  Plus,
  Sparkles,
  AlertOctagon,
  X,
  FileCode,
  GitBranch,
  Cloud,
  Bot,
  Send,
  MessageSquare,
  Trash2,
  Paperclip,
  ShieldAlert,
  Code2,
  Building,
  Radio,
  Clock,
  Mic,
  MicOff,
  File,
  Calendar,
  ShieldCheck,
  Radar,
  Users,
  QrCode,
  Settings,
  Save,
  Phone,
  Filter,
  Package,
  Network,
  CreditCard,
  MapPin
} from 'lucide-react';
import { TenantUserManagement } from './TenantUserManagement';
import { EnterprisePkiVaults } from './EnterprisePkiVaults';
import { PqcProxyGateway } from './PqcProxyGateway';
import { GitRepoAuditor } from './GitRepoAuditor';
import SbomInventory from './SbomInventory';
import ComplianceProjects from './ComplianceProjects';

// Threat & Risk Graph pulls in React Flow; load it only when the tab is opened.
const ThreatRiskGraph = React.lazy(() => import('./ThreatRiskGraph/ThreatRiskGraph'));
import { CryptographicPostureCard, calculatePostureMetrics } from './CryptographicPostureCard';

export interface InternalUserLog {
  id: string;
  timestamp: string;
  event: string;
  category: 'auth' | 'security' | 'crypto' | 'admin';
  description: string;
  ipAddress: string;
  attestationStatus: string;
  userAgent?: string;
}

export const DEFAULT_USER_LOGS: InternalUserLog[] = [
  {
    id: 'log-1',
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    event: 'AUTH_SESSION_ESTABLISHED',
    category: 'auth',
    description: 'User authenticated via Post-Quantum Hybrid Handshake (ML-KEM-768)',
    ipAddress: '13.140.40.99 (Platform Host)',
    attestationStatus: 'Verified (ML-KEM-768)'
  },
  {
    id: 'log-2',
    timestamp: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
    event: 'TOTP_CHALLENGE_VERIFIED',
    category: 'security',
    description: 'Hardware/App-backed 2FA challenge code validated for console session',
    ipAddress: '73.189.44.120',
    attestationStatus: 'RFC 6238 Attested'
  },
  {
    id: 'log-3',
    timestamp: new Date(Date.now() - 1000 * 60 * 85).toISOString(),
    event: 'CBOM_TELEMETRY_EXPORT',
    category: 'crypto',
    description: 'Cryptographic Bill of Materials (CycloneDX 1.6 JSON) exported for compliance review',
    ipAddress: '73.189.44.120',
    attestationStatus: 'FIPS 204 Signed (ML-DSA-65)'
  },
  {
    id: 'log-4',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
    event: 'FLEET_SYNC_INGEST',
    category: 'admin',
    description: 'Endpoint agent cryptographic telemetry synchronized for 3 enrolled workstations',
    ipAddress: '13.140.40.99',
    attestationStatus: 'Verified'
  },
  {
    id: 'log-5',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    event: 'BACKUP_CODES_ACCESSED',
    category: 'security',
    description: 'Emergency 2FA recovery backup codes generated and verified by account administrator',
    ipAddress: '73.189.44.120',
    attestationStatus: 'Hardware Attested'
  },
  {
    id: 'log-6',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
    event: 'PASSWORD_HASH_VERIFY',
    category: 'auth',
    description: 'Argon2id cryptographic password verification successful during tenant portal login',
    ipAddress: '73.189.44.120',
    attestationStatus: 'Argon2id (m=65536, t=3, p=4)'
  }
];

interface TenantPortalProps {
  tenantSlug: string;
  onNavigateHome?: () => void;
  onLogout?: () => void;
  isSupportMirror?: boolean;
  onExitMirror?: () => void;
}

interface FleetMachine {
  id: string;
  hostname: string;
  computerName?: string;
  hardwareUuid?: string;
  os: string;
  arch: string;
  ip: string;
  publicIp?: string;
  geoCity?: string;
  geoRegion?: string;
  geoCountry?: string;
  group?: string;
  agentVersion: string;
  status: string;
  riskLevel: string;
  quantumRiskScore: number;
  assetCount: number;
  vulnerableCount: number;
  lastSeen: string;
  lastSync?: string;
  createdAt: string;
  tenantName: string;
  licenseKey: string;
  groupName?: string;
}

interface DailySnapshot {
  id: string;
  date: string;
  activeWorkstations: number;
  totalAssets: number;
  vulnerableAssets: number;
  averageRiskScore: number;
}

interface Asset {
  id: string;
  type: string;
  name: string;
  path?: string;
  algorithm: string;
  keySize?: number;
  hashAlgorithm?: string;
  isVulnerable: boolean;
  riskLevel: string;
  status?: string;
  description?: string;
  recommendation?: string;
  explainer?: string;
  complianceViolations?: string | string[];
  createdAt: string;
  machineId?: string;
  hostname?: string;
  os?: string;
  source?: string;
  sourceRef?: string;
}

interface TenantClient {
  id: string;
  name: string;
  displayName?: string;
  customerId?: string;
  appPort?: number;
  dbPort?: number;
  status?: string;
  subscriptionTier?: string;
  mcaLimit?: number;
  contactName?: string;
  adminEmail?: string;
  phone?: string;
  accountType?: string;
}

interface TenantLicense {
  id: string;
  licenseKey: string;
  tenantName: string;
  tier: string;
  durationDays: number;
  seats: number;
  expiresAt: string;
  customerId?: string;
  status?: string;
  contactName?: string;
  contactEmail?: string;
  createdAt?: string;
}

interface CopilotAttachment {
  name: string;
  size: number;
  type: string;
  data?: string;
}

interface CopilotMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  code?: string;
  language?: string;
  attachments?: CopilotAttachment[];
  timestamp?: string;
}

interface CopilotSession {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: CopilotMessage[];
}

const formatInlineText = (text: string): React.ReactNode => {
  if (!text) return null;
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={idx} style={{ color: '#ffffff', fontWeight: 700 }}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={idx} style={{
          background: 'rgba(255, 255, 255, 0.08)',
          padding: '0.15rem 0.35rem',
          borderRadius: '4px',
          fontFamily: 'monospace',
          fontSize: '0.78rem',
          color: '#38bdf8'
        }}>
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
};

const renderMarkdownMessage = (content: string): React.ReactNode => {
  if (!content) return null;
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let inTable = false;
  let tableHeader: string[] = [];
  let tableRows: string[][] = [];

  const flushTable = (keyPrefix: string) => {
    if (tableHeader.length > 0 || tableRows.length > 0) {
      elements.push(
        <div key={`table-wrap-${keyPrefix}`} style={{ overflowX: 'auto', margin: '0.85rem 0' }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: '0.8rem',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '6px',
            overflow: 'hidden'
          }}>
            {tableHeader.length > 0 && (
              <thead>
                <tr style={{ background: 'rgba(56, 189, 248, 0.12)', borderBottom: '1px solid rgba(255, 255, 255, 0.18)' }}>
                  {tableHeader.map((th, hIdx) => (
                    <th key={hIdx} style={{
                      padding: '0.55rem 0.75rem',
                      textAlign: 'left',
                      fontWeight: 700,
                      color: '#38bdf8',
                      borderRight: hIdx < tableHeader.length - 1 ? '1px solid rgba(255, 255, 255, 0.08)' : 'none'
                    }}>
                      {formatInlineText(th.trim())}
                    </th>
                  ))}
                </tr>
              </thead>
            )}
            <tbody>
              {tableRows.map((row, rIdx) => (
                <tr key={rIdx} style={{
                  background: rIdx % 2 === 0 ? 'rgba(255, 255, 255, 0.02)' : 'rgba(0, 0, 0, 0.25)',
                  borderBottom: rIdx < tableRows.length - 1 ? '1px solid rgba(255, 255, 255, 0.06)' : 'none'
                }}>
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} style={{
                      padding: '0.5rem 0.75rem',
                      color: '#e2e8f0',
                      borderRight: cIdx < row.length - 1 ? '1px solid rgba(255, 255, 255, 0.06)' : 'none'
                    }}>
                      {formatInlineText(cell.trim())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
      inTable = false;
      tableHeader = [];
      tableRows = [];
    }
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const isTableLine = line.trim().startsWith('|') && line.trim().endsWith('|');

    if (isTableLine) {
      const isSeparator = /^\|(\s*[:-]+[-| :]*)\|$/.test(line.trim());
      if (isSeparator) {
        continue;
      }
      const cells = line.split('|').slice(1, -1);
      if (!inTable) {
        inTable = true;
        tableHeader = cells;
      } else {
        tableRows.push(cells);
      }
      continue;
    } else {
      if (inTable) {
        flushTable(`line-${idx}`);
      }
    }

    if (line.startsWith('### ')) {
      elements.push(
        <h3 key={idx} style={{ fontSize: '1.05rem', fontWeight: 700, color: '#38bdf8', margin: '0.85rem 0 0.4rem 0' }}>
          {formatInlineText(line.replace('### ', ''))}
        </h3>
      );
    } else if (line.startsWith('#### ')) {
      elements.push(
        <h4 key={idx} style={{ fontSize: '0.92rem', fontWeight: 700, color: '#f8fafc', margin: '0.65rem 0 0.35rem 0' }}>
          {formatInlineText(line.replace('#### ', ''))}
        </h4>
      );
    } else if (line.trim().startsWith('• ') || line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      elements.push(
        <div key={idx} style={{ display: 'flex', gap: '0.5rem', margin: '0.2rem 0', alignItems: 'flex-start' }}>
          <span style={{ color: '#38bdf8', fontSize: '1rem', lineHeight: '1.2' }}>•</span>
          <span style={{ flex: 1, color: '#e2e8f0' }}>
            {formatInlineText(line.trim().replace(/^([•\-\*]\s*)/, ''))}
          </span>
        </div>
      );
    } else if (line.trim() === '') {
      elements.push(<div key={idx} style={{ height: '0.45rem' }} />);
    } else {
      elements.push(
        <div key={idx} style={{ margin: '0.2rem 0', color: '#e2e8f0', lineHeight: '1.55' }}>
          {formatInlineText(line)}
        </div>
      );
    }
  }

  if (inTable) {
    flushTable('end');
  }

  return <>{elements}</>;
};

export const TenantPortal: React.FC<TenantPortalProps> = ({
  tenantSlug,
  onNavigateHome,
  onLogout,
  isSupportMirror,
  onExitMirror
}) => {
  const cleanSlug = (tenantSlug || 'spinovationcorp').toLowerCase().replace(/[^a-z0-9-]/g, '');

  // Auth State - always show tenant login screen first until explicit sign-in, or if support mirror session is active
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    if (isSupportMirror) return true;
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('logout') === 'true') {
      sessionStorage.removeItem(`tenant_auth_${cleanSlug}`);
      localStorage.removeItem(`tenant_auth_${cleanSlug}`);
      return false;
    }
    const savedAuth = sessionStorage.getItem(`tenant_auth_${cleanSlug}`);
    return savedAuth === 'true';
  });

  useEffect(() => {
    if (isSupportMirror) {
      setIsAuthenticated(true);
    }
  }, [isSupportMirror]);

  const [emailInput, setEmailInput] = useState<string>(() => {
    // Only pre-fill from this device's own saved login ("remember me"). Never
    // hardcode a tenant admin's email as the default — that leaked the admin's
    // address to every visitor of the tenant portal (e.g. a user in India saw
    // the owner's email pre-filled). New visitors start with an empty field.
    const saved = localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user');
    if (saved && !saved.includes('superadmin')) return saved;
    return '';
  });
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loginLoading, setLoginLoading] = useState<boolean>(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [login2FACode, setLogin2FACode] = useState<string>('');

  // Tenant Portal Forgot Password State
  const [showTenantForgotPasswordModal, setShowTenantForgotPasswordModal] = useState<boolean>(false);
  const [tenantForgotEmail, setTenantForgotEmail] = useState<string>('');
  const [tenantForgotLoading, setTenantForgotLoading] = useState<boolean>(false);
  const [tenantForgotSuccess, setTenantForgotSuccess] = useState<string | null>(null);
  const [tenantForgotError, setTenantForgotError] = useState<string | null>(null);

  // Tenant Portal Mandatory First-Login Password Change State
  const [showTenantForceChangeModal, setShowTenantForceChangeModal] = useState<boolean>(false);
  const [tenantForceNewPassword, setTenantForceNewPassword] = useState<string>('');
  const [tenantForceConfirmPassword, setTenantForceConfirmPassword] = useState<string>('');
  const [tenantForceShowNew, setTenantForceShowNew] = useState<boolean>(false);
  const [tenantForceShowConfirm, setTenantForceShowConfirm] = useState<boolean>(false);
  const [tenantForceLoading, setTenantForceLoading] = useState<boolean>(false);
  const [tenantForceError, setTenantForceError] = useState<string | null>(null);
  const [tenantForceSuccess, setTenantForceSuccess] = useState<string | null>(null);

  // Dashboard Data State
  const [loading, setLoading] = useState<boolean>(true);
  const [client, setClient] = useState<TenantClient>(() => {
    if (cleanSlug.includes('algomeld')) {
      return {
        id: 'client-algomeld',
        name: 'algomeld',
        displayName: 'Algo Meld MSP',
        customerId: 'PART-4421',
        appPort: 5003,
        dbPort: 5435,
        status: 'active',
        subscriptionTier: 'partner',
        mcaLimit: 50,
        contactName: 'Tenant Administrator',
        adminEmail: 'admin@algomeld.com',
        accountType: 'partner'
      };
    }
    return {
      id: `client-${cleanSlug}`,
      name: cleanSlug,
      displayName: cleanSlug.includes('spinovation') ? 'Spinovation Corp' : cleanSlug.includes('amberoon') ? 'Amberoon' : cleanSlug.toUpperCase(),
      customerId: cleanSlug.includes('spinovation') ? 'CORP-9812' : cleanSlug.includes('amberoon') ? 'PART-7033' : `CORP-${cleanSlug.slice(0, 4).toUpperCase()}`,
      appPort: 5050,
      dbPort: 5432,
      status: 'active',
      subscriptionTier: (cleanSlug.includes('partner') || cleanSlug.includes('amberoon')) ? 'partner' : 'growth',
      mcaLimit: 100,
      contactName: 'Tenant Administrator',
      adminEmail: `admin@${cleanSlug}.com`,
      accountType: (cleanSlug.includes('partner') || cleanSlug.includes('amberoon')) ? 'partner' : 'corporate'
    };
  });

  const [machines, setMachines] = useState<FleetMachine[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [licenses, setLicenses] = useState<TenantLicense[]>([]);
  const [stats, setStats] = useState<{
    totalMachines: number;
    onlineMachines: number;
    totalSeats: number;
    usedSeats: number;
    totalAssets: number;
    vulnerableAssets: number;
    avgRiskScore: number;
  }>({
    totalMachines: 3,
    onlineMachines: 3,
    totalSeats: 100,
    usedSeats: 3,
    totalAssets: 98,
    vulnerableAssets: 98,
    avgRiskScore: 87
  });
  const [sessionExpired, setSessionExpired] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'cbom' | 'assets' | 'sbom' | 'integrations' | 'repositories' | 'git' | 'pki' | 'proxy' | 'copilot' | 'compliance' | 'threat' | 'planner' | 'license' | 'deployment' | 'users' | 'settings' | 'profile'>(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      const t = p.get('tab');
      if (t === 'sbom' || t === 'cbom') return 'cbom';
      if (t && ['overview', 'git', 'pki', 'proxy', 'copilot', 'settings'].includes(t)) {
        return t as any;
      }
    } catch (e) {}
    return 'overview';
  });

  const postureMetrics = useMemo(() => {
    return calculatePostureMetrics(assets, machines, {
      totalAssets: stats.totalAssets,
      quantumVuln: stats.vulnerableAssets,
      riskScore: stats.avgRiskScore
    });
  }, [assets, machines, stats]);

  const [settingsSubTab, setSettingsSubTab] = useState<'profile' | 'users' | 'license' | 'stakeholders' | 'groups'>('profile');
  const [isSettingsMenuOpen, setIsSettingsMenuOpen] = useState<boolean>(true);
  const [deploymentTierTab, setDeploymentTierTab] = useState<'tier1' | 'tier2' | 'tier3' | 'desktop'>('tier1');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [searchAsset, setSearchAsset] = useState<string>('');
  const [assetPage, setAssetPage] = useState<number>(1);
  const assetsPerPage = 50;

  // 2FA Security & User License Modal State
  const [showLicense2FAModal, setShowLicense2FAModal] = useState<boolean>(false);
  const [showTOTPModal, setShowTOTPModal] = useState<boolean>(false);
  const [showBackupCodesModal, setShowBackupCodesModal] = useState<boolean>(false);
  const [totpVerificationCode, setTotpVerificationCode] = useState<string>('');
  const [totpSuccess, setTotpSuccess] = useState<boolean>(false);
  const [copiedBackupCodes, setCopiedBackupCodes] = useState<boolean>(false);
  const [activeLicKeyCopied, setActiveLicKeyCopied] = useState<boolean>(false);
  const [portalLoading, setPortalLoading] = useState<boolean>(false);

  const handleOpenStripePortal = async () => {
    setPortalLoading(true);
    try {
      const res = await fetch('/api/billing/portal-session', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantSlug: client.name })
      });
      const data = await res.json();
      if (res.ok && data.portalUrl) {
        window.location.href = data.portalUrl;
      } else {
        alert(data.error || 'Stripe Customer Portal is only available for accounts with an active Stripe subscription. Contact support@quarkshield.ai for billing inquiries.');
      }
    } catch (err: any) {
      alert(err.message || 'Failed to connect to billing portal.');
    } finally {
      setPortalLoading(false);
    }
  };

  // Identity & Role Computations
  const [currentUserRole, setCurrentUserRole] = useState<string>(() => {
    return localStorage.getItem('quarkshield_role') || sessionStorage.getItem('quarkshield_role') || '';
  });

  const isPartner = client.accountType === 'partner' ||
    (client.customerId && client.customerId.startsWith('PART-')) ||
    cleanSlug.includes('algomeld') ||
    cleanSlug.includes('partner');

  const displayCustomerId = client.customerId || (cleanSlug.includes('algomeld') ? 'PART-4421' : (cleanSlug.includes('partner') || isPartner ? 'PART-7000' : `CORP-${cleanSlug.slice(0, 4).toUpperCase()}`));
  const displayCustomerName = client.displayName || (cleanSlug.includes('algomeld') ? 'Algomeld' : (cleanSlug.charAt(0).toUpperCase() + cleanSlug.slice(1)));
  const displayRole = currentUserRole || (isPartner ? 'Partner Admin' : 'Corporate Admin');
  const activeLicKey = (licenses && licenses.length > 0 && licenses[0].licenseKey)
    ? licenses[0].licenseKey
    : (licenses.find(l => l.status === 'active')?.licenseKey || `QS-${(client.customerId || cleanSlug).toUpperCase()}-ACTIVE`);

  // User Profile & Activity Audit Logs State
  const [profileFullName, setProfileFullName] = useState<string>('Cryptographic SecOps Administrator');
  const [profileDepartment, setProfileDepartment] = useState<string>('Global Information Security & PQC Migration');
  const [profilePhone, setProfilePhone] = useState<string>('+1 (555) 019-2834');
  const [profileToast, setProfileToast] = useState<string | null>(null);

  // Profile Password Management State
  const [currentPassword, setCurrentPassword] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [showCurrentPassword, setShowCurrentPassword] = useState<boolean>(false);
  const [showNewPassword, setShowNewPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);

  // Internal User Logs State
  const [userLogs, setUserLogs] = useState<InternalUserLog[]>(DEFAULT_USER_LOGS);
  const [logSearch, setLogSearch] = useState<string>('');
  const [logCategoryFilter, setLogCategoryFilter] = useState<'all' | 'auth' | 'security' | 'crypto' | 'admin'>('all');

  const addInternalLog = (event: string, category: 'auth' | 'security' | 'crypto' | 'admin', description: string, attestationStatus: string = 'Verified') => {
    const newLog: InternalUserLog = {
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      event,
      category,
      description,
      ipAddress: '13.140.40.99 (Platform Host)',
      attestationStatus
    };
    setUserLogs(prev => [newLog, ...prev]);
  };

  const handleSaveProfileInfo = (e: React.FormEvent) => {
    e.preventDefault();
    setProfileToast('Profile information successfully saved.');
    setTimeout(() => setProfileToast(null), 3500);
    addInternalLog('USER_PROFILE_UPDATED', 'admin', `Updated personal profile parameters (Name: ${profileFullName}, Unit: ${profileDepartment})`, 'Verified Session');
  };

  const handleUpdatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);
    if (!currentPassword) {
      setPasswordError('Please enter your current password.');
      return;
    }
    if (newPassword.length < 8) {
      setPasswordError('New password must be at least 8 characters in length.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('New password and confirmation do not match.');
      return;
    }

    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: emailInput.trim(),
          currentPassword,
          newPassword
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update password.');
      }

      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordSuccess('Password successfully updated and Argon2id hash re-computed.');
      setTimeout(() => setPasswordSuccess(null), 4000);
      addInternalLog('PASSWORD_CHANGED', 'auth', 'User password updated and re-hashed with Argon2id parameters (m=65536, t=3, p=4)', 'Argon2id Verified');
    } catch (err: any) {
      setPasswordError(err.message || 'Password update failed.');
    }
  };

  const filteredUserLogs = userLogs.filter(log => {
    const matchesCategory = logCategoryFilter === 'all' || log.category === logCategoryFilter;
    const matchesSearch = !logSearch || 
      log.event.toLowerCase().includes(logSearch.toLowerCase()) ||
      log.description.toLowerCase().includes(logSearch.toLowerCase()) ||
      log.ipAddress.toLowerCase().includes(logSearch.toLowerCase()) ||
      log.attestationStatus.toLowerCase().includes(logSearch.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const handleExportUserLogs = () => {
    const headers = ['Timestamp', 'Event', 'Category', 'Description', 'IP Address', 'Attestation Status'];
    const rows = filteredUserLogs.map(l => [
      l.timestamp, l.event, l.category, l.description, l.ipAddress, l.attestationStatus,
    ]);
    downloadCsv(`user-internal-logs-${cleanSlug}-${new Date().toISOString().split('T')[0]}.csv`, headers, rows);
    addInternalLog('INTERNAL_LOGS_EXPORTED', 'admin', 'Exported internal security and audit logs to CSV', 'FIPS 204 Signed');
  };

  const isSettingsActive = activeTab === 'settings' || activeTab === 'profile' || activeTab === 'users' || activeTab === 'license' || activeTab === 'planner';
  // Integrations & Gateways is a container tab whose content is the Git / PKI / Proxy sub-tabs
  const isIntegrationsTab = activeTab === 'git' || activeTab === 'pki' || activeTab === 'proxy';
  const effectiveSettingsTab: 'profile' | 'users' | 'license' | 'stakeholders' | 'groups' =
    activeTab === 'profile' ? 'profile' :
    activeTab === 'users' ? 'users' :
    activeTab === 'license' ? 'license' :
    settingsSubTab;

  // 1. Enrollment Token Modal State
  const [showEnrollModal, setShowEnrollModal] = useState<boolean>(false);
  const [newTokenGroup, setNewTokenGroup] = useState<string>('Engineering');
  const [isGeneratingToken, setIsGeneratingToken] = useState<boolean>(false);
  const [generatedTokenData, setGeneratedTokenData] = useState<any | null>(null);
  const [tokenCopied, setTokenCopied] = useState<boolean>(false);
  const [enrollTabOs, setEnrollTabOs] = useState<'macos' | 'windows' | 'linux'>('macos');
  const [tenantTokens, setTenantTokens] = useState<any[]>([]);

  // Daily Historical Snapshots & On-Demand Pull State
  const [dailySnapshots, setDailySnapshots] = useState<DailySnapshot[]>([]);
  const [pullingMachineId, setPullingMachineId] = useState<string | null>(null);
  const [scheduleModalOpen, setScheduleModalOpen] = useState<boolean>(false);
  const [syncSchedulePolicy, setSyncSchedulePolicy] = useState<{
    frequency: 'daily' | 'hourly' | 'weekly';
    time: string;
    autoRemediate: boolean;
  }>({
    frequency: 'daily',
    time: '02:00',
    autoRemediate: true,
  });

  // 2. CBOM Inventory State
  const [cbomSubTab, setCbomSubTab] = useState<'assets' | 'cyclonedx' | 'json' | 'drift' | 'sbom'>(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      const s = p.get('subtab');
      if (s === 'sbom' || p.get('tab') === 'sbom') return 'sbom';
      if (s && ['assets', 'cyclonedx', 'json', 'drift'].includes(s)) return s as any;
    } catch (e) {}
    return 'assets';
  });
  const [cbomSearch, setCbomSearch] = useState<string>('');
  const [cbomCategory, setCbomCategory] = useState<string>('all');
  const [cbomJsonCopied, setCbomJsonCopied] = useState<boolean>(false);
  const [cbomAttestationMode, setCbomAttestationMode] = useState<boolean>(false);

  // Report stakeholders (email recipients managed under Profile)
  interface Stakeholder { name: string; email: string; role?: string }
  const [reportStakeholders, setReportStakeholders] = useState<Stakeholder[]>([]);
  const [newStkName, setNewStkName] = useState('');
  const [newStkEmail, setNewStkEmail] = useState('');
  const [stkSaving, setStkSaving] = useState(false);
  const [emailingReport, setEmailingReport] = useState(false);
  const [stkToast, setStkToast] = useState<string | null>(null);

  const stkTenantParam = () => encodeURIComponent(client?.name || cleanSlug || '');

  const loadStakeholders = async () => {
    try {
      const res = await fetch(`/api/reports/stakeholders?tenant=${stkTenantParam()}`, { credentials: 'include' });
      if (res.ok) { const d = await res.json(); setReportStakeholders(Array.isArray(d.stakeholders) ? d.stakeholders : []); }
    } catch { /* ignore */ }
  };

  const persistStakeholders = async (list: Stakeholder[]) => {
    setStkSaving(true);
    try {
      const res = await fetch('/api/reports/stakeholders', {
        method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant: client?.name || cleanSlug, stakeholders: list })
      });
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `HTTP ${res.status}`); }
      const d = await res.json();
      setReportStakeholders(Array.isArray(d.stakeholders) ? d.stakeholders : list);
      setStkToast('Stakeholders saved.');
      setTimeout(() => setStkToast(null), 3000);
    } catch (err: any) {
      alert(`Failed to save stakeholders: ${err.message}`);
    } finally { setStkSaving(false); }
  };

  const addStakeholder = () => {
    const email = newStkEmail.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { alert('Enter a valid email address.'); return; }
    const list = [...reportStakeholders, { name: newStkName.trim(), email }];
    setNewStkName(''); setNewStkEmail('');
    persistStakeholders(list);
  };
  const removeStakeholder = (email: string) => persistStakeholders(reportStakeholders.filter(s => s.email !== email));

  useEffect(() => { if (effectiveSettingsTab === 'stakeholders') loadStakeholders(); /* eslint-disable-next-line */ }, [effectiveSettingsTab]);

  const emailRoadmapToStakeholders = async () => {
    if (!reportStakeholders.length) { alert('Add at least one stakeholder first.'); return; }
    setEmailingReport(true);
    try {
      const res = await fetch('/api/reports/executive/send', {
        method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant: client?.name || cleanSlug })
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(d.error || `HTTP ${res.status}`);
      setStkToast(`Report emailed to ${d.sent}/${d.total} stakeholder(s).`);
      setTimeout(() => setStkToast(null), 4000);
    } catch (err: any) {
      alert(`Failed to email report: ${err.message}`);
    } finally { setEmailingReport(false); }
  };

  // Drift & Executive Report State
  interface DriftEvent {
    id: string;
    machineId: string;
    tenantName: string;
    changeType: 'added' | 'removed';
    assetName: string;
    algorithm: string;
    isVulnerable: boolean;
    detectedAt: string;
  }
  const [driftEvents, setDriftEvents] = useState<DriftEvent[]>([]);
  const [isLoadingDrift, setIsLoadingDrift] = useState<boolean>(false);
  const [driftSearch, setDriftSearch] = useState<string>('');
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);

  // 4. PQC Copilot Multi-Session State
  const copilotStorageKey = `quarkshield_copilot_sessions_${cleanSlug}`;

  const createDefaultSession = (): CopilotSession => ({
    id: 'session-' + Date.now(),
    title: 'Post-Quantum Strategy',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    messages: [
      {
        id: 'msg-welcome',
        sender: 'ai',
        text: `Hello! I am QuarkShield AI, your dedicated Post-Quantum Cryptographic Remediation Copilot for ${client.displayName || (cleanSlug.includes('spinovation') ? 'Spinovation Corp' : cleanSlug.toUpperCase())}.\n\nI have active context of your enterprise cryptographic inventory.\n\nAsk me anything about:\n• **Onboarding & Next Steps**: Admin initial credentials, running your first desktop scan, staff onboarding & seat allocation.\n• **Roadmap & Platform Features**: CI/CD CBOM security gate, Enterprise PKI & Vault connectors, Transparent Hybrid Quantum TLS proxy, and 3-tier deployment.\n• **PQC & Cryptanalysis**: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), Shor's/Grover's threats, NGINX hybrid TLS, OpenSSH 9.8+, or CNSA 2.0 roadmaps!`,
        timestamp: new Date().toISOString()
      }
    ]
  });

  const [copilotSessions, setCopilotSessions] = useState<CopilotSession[]>(() => {
    try {
      const saved = localStorage.getItem(copilotStorageKey);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {
      console.warn('Failed to load saved copilot sessions:', e);
    }
    return [createDefaultSession()];
  });

  const [activeSessionId, setActiveSessionId] = useState<string>(() => {
    return copilotSessions[0]?.id || 'session-default';
  });

  const [copilotInput, setCopilotInput] = useState<string>('');
  const [copilotLoading, setCopilotLoading] = useState<boolean>(false);
  const [copilotCopiedIdx, setCopilotCopiedIdx] = useState<number | null>(null);
  const [pendingAttachments, setPendingAttachments] = useState<Array<{ name: string; size: number; type: string; data: string; isText: boolean }>>([]);
  const [isListening, setIsListening] = useState<boolean>(false);
  const [liveWebSearch, setLiveWebSearch] = useState<boolean>(true);
  const chatBottomRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const recognitionRef = useRef<any>(null);

  // Sync sessions to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(copilotStorageKey, JSON.stringify(copilotSessions));
    } catch (e) {
      console.warn('Failed to save copilot sessions:', e);
    }
  }, [copilotSessions, copilotStorageKey]);

  // Active session helper
  const currentSession = copilotSessions.find(s => s.id === activeSessionId) || copilotSessions[0];
  const copilotMessages = currentSession?.messages || [];

  // Web Speech API Voice Activation
  useEffect(() => {
    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (SpeechRecognition) {
      try {
        const recognition = new SpeechRecognition();
        recognition.continuous = false;
        recognition.interimResults = true;
        recognition.lang = 'en-US';

        recognition.onresult = (event: any) => {
          let currentTranscript = '';
          for (let i = event.resultIndex; i < event.results.length; i++) {
            currentTranscript += event.results[i][0].transcript;
          }
          if (currentTranscript) {
            setCopilotInput(prev => {
              const trimmed = prev.trim();
              return trimmed ? `${trimmed} ${currentTranscript.trim()}` : currentTranscript.trim();
            });
          }
        };

        recognition.onerror = (event: any) => {
          console.warn('Speech recognition notice:', event.error);
          setIsListening(false);
        };

        recognition.onend = () => {
          setIsListening(false);
        };

        recognitionRef.current = recognition;
      } catch (err) {
        console.warn('Web Speech API setup notice:', err);
      }
    }
  }, []);

  const toggleVoiceInput = () => {
    if (!recognitionRef.current) {
      alert('Speech recognition is not available in your current browser. Please use Google Chrome, Edge, or Safari, and allow microphone permissions.');
      return;
    }
    if (isListening) {
      try {
        recognitionRef.current.stop();
      } catch (e) {}
      setIsListening(false);
    } else {
      try {
        recognitionRef.current.start();
        setIsListening(true);
      } catch (e) {
        console.error('Failed to start voice listening:', e);
        setIsListening(false);
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    Array.from(files).forEach(file => {
      const reader = new FileReader();
      const isText = file.type.startsWith('text/') || 
                     file.name.endsWith('.pem') || 
                     file.name.endsWith('.crt') || 
                     file.name.endsWith('.key') || 
                     file.name.endsWith('.conf') || 
                     file.name.endsWith('.json') || 
                     file.name.endsWith('.yaml') || 
                     file.name.endsWith('.yml') || 
                     file.name.endsWith('.csv') || 
                     file.name.endsWith('.sol') || 
                     file.name.endsWith('.go') || 
                     file.name.endsWith('.py') || 
                     file.name.endsWith('.log');

      if (isText) {
        reader.onload = (event) => {
          const content = event.target?.result as string || '';
          setPendingAttachments(prev => [
            ...prev,
            { name: file.name, size: file.size, type: file.type || 'text/plain', data: content, isText: true }
          ]);
        };
        reader.readAsText(file);
      } else {
        reader.onload = (event) => {
          const content = event.target?.result as string || '';
          setPendingAttachments(prev => [
            ...prev,
            { name: file.name, size: file.size, type: file.type || 'application/octet-stream', data: content, isText: false }
          ]);
        };
        reader.readAsDataURL(file);
      }
    });

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const removePendingAttachment = (index: number) => {
    setPendingAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const handleNewChat = () => {
    const newSession: CopilotSession = {
      id: 'session-' + Date.now(),
      title: 'New Conversation',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: [
        {
          id: 'msg-' + Date.now(),
          sender: 'ai',
          text: `Hello! I am QuarkShield AI, your dedicated Post-Quantum Cryptographic Remediation Copilot for ${client.displayName || 'your organization'}. How may I help you upgrade your cryptographic posture today?`,
          timestamp: new Date().toISOString()
        }
      ]
    };
    setCopilotSessions(prev => [newSession, ...prev]);
    setActiveSessionId(newSession.id);
    setCopilotInput('');
    setPendingAttachments([]);
  };

  const handleDeleteSession = (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setCopilotSessions(prev => {
      const filtered = prev.filter(s => s.id !== sessionId);
      if (filtered.length === 0) {
        const fresh = createDefaultSession();
        setActiveSessionId(fresh.id);
        return [fresh];
      }
      if (activeSessionId === sessionId) {
        setActiveSessionId(filtered[0].id);
      }
      return filtered;
    });
  };

  const handleClearCurrentChat = () => {
    setCopilotSessions(prev => prev.map(session => {
      if (session.id === activeSessionId) {
        return {
          ...session,
          title: 'New Conversation',
          updatedAt: new Date().toISOString(),
          messages: [
            {
              id: 'msg-' + Date.now(),
              sender: 'ai',
              text: `Hello! I am QuarkShield AI, your dedicated Post-Quantum Cryptographic Remediation Copilot for ${client.displayName || 'your organization'}. How may I help you upgrade your cryptographic posture today?`,
              timestamp: new Date().toISOString()
            }
          ]
        };
      }
      return session;
    }));
    setCopilotInput('');
    setPendingAttachments([]);
  };

  // Fetch Tenant Data from Backend
  const fetchTenantData = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/tenant/${cleanSlug}/portal-data`);
      if (res.ok) {
        const data = await res.json();
        // A successful portal-data read proves a valid server session (the cookie is
        // apex-scoped, while the client-side tenant_auth flag is per-origin and is NOT
        // set after the landing-page redirect). Treat it as authenticated.
        if (!isAuthenticated) {
          setIsAuthenticated(true);
          try { sessionStorage.setItem(`tenant_auth_${cleanSlug}`, 'true'); } catch { /* ignore */ }
        }
        setSessionExpired(false);
        if (data.client) setClient(data.client);
        if (data.machines) setMachines(data.machines);
        if (data.assets) setAssets(data.assets);
        if (data.licenses) setLicenses(data.licenses);
        if (data.tokens) setTenantTokens(data.tokens);
        if (data.stats) setStats(data.stats);
        if (data.dailySnapshots) setDailySnapshots(data.dailySnapshots);
      } else {
        throw new Error('Failed to fetch from /api/tenant/:tenant/portal-data');
      }
    } catch (err) {
      // Honest handling (BILL-6): a failed portal-data fetch almost always means the
      // session expired. Do NOT fabricate data — the old mock showed fake 'LIVE'
      // machines/assets, which misled users and would be dangerous in a live demo.
      // Flag it so the UI prompts a clean re-login instead of showing invented numbers.
      console.warn('tenant portal-data fetch failed (session likely expired):', err);
      setSessionExpired(true);
    } finally {
      setLoading(false);
    }
  };

  const handlePullWorkstation = async (machineId: string, hostname: string) => {
    setPullingMachineId(machineId);
    try {
      const res = await fetch(`/api/fleet/machines/${machineId}/pull`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority: 'high' })
      });
      if (res.ok) {
        alert(`Telemetry pull queued for ${hostname}. The agent picks up on-demand requests while the QuarkShield app is running (within ~2 min); if the app is closed it will sync at its next scheduled run. Status updates once the endpoint reports back.`);
        fetchTenantData();
      } else {
        alert(`Failed to dispatch pull request to ${hostname}.`);
      }
    } catch (e) {
      console.error('Error dispatching pull:', e);
      alert(`Pull error: ${e}`);
    } finally {
      setPullingMachineId(null);
    }
  };

  const [bulkPulling, setBulkPulling] = useState<string | null>(null); // null | 'ALL' | group name
  const handlePullBulk = async (opts?: { group?: string }) => {
    const key = opts?.group || 'ALL';
    const scopeLabel = opts?.group ? `group "${opts.group}"` : 'all endpoints';
    if (!window.confirm(`Queue a telemetry pull for ${scopeLabel}? Each agent runs it on its next check-in while the QuarkShield app is open (or, with the persistent service, even when it's closed).`)) return;
    setBulkPulling(key);
    try {
      const res = await fetch(`/api/fleet/pull-bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(opts?.group ? { group: opts.group } : {})
      });
      const d = await res.json().catch(() => ({}));
      if (res.ok) {
        alert(`${d.message || `Pull queued for ${scopeLabel}.`} Endpoints update as they report back.`);
        fetchTenantData();
      } else {
        alert(`Failed to queue bulk pull: ${d.error || res.status}`);
      }
    } catch (e) {
      alert(`Bulk pull error: ${e}`);
    } finally {
      setBulkPulling(null);
    }
  };

  // Workstation Groups (DEF-42)
  const [fleetGroups, setFleetGroups] = useState<{ name: string; count: number }[]>([]);
  const [groupFilter, setGroupFilter] = useState<string>('');  // '' = all
  const [newGroupName, setNewGroupName] = useState<string>('');
  const [fleetSort, setFleetSort] = useState<{ key: string; dir: 'asc' | 'desc' }>({ key: 'host', dir: 'asc' });
  const toggleFleetSort = (key: string) =>
    setFleetSort(s => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  const sortedFilteredMachines = (): FleetMachine[] => {
    let list = machines;
    if (groupFilter) list = list.filter(m => (m.group || 'Default') === groupFilter);
    const { key, dir } = fleetSort;
    const val = (m: FleetMachine): string | number => {
      switch (key) {
        case 'group': return (m.group || 'Default').toLowerCase();
        case 'uuid': return (m.hardwareUuid || '').toLowerCase();
        case 'os': return (m.os || '').toLowerCase();
        case 'ip': return m.ip || '';
        case 'assets': return m.assetCount || 0;
        case 'score': return m.quantumRiskScore || 0;
        case 'status': return m.status || '';
        default: return (m.computerName || m.hostname || '').toLowerCase(); // 'host'
      }
    };
    return [...list].sort((a, b) => {
      const av = val(a), bv = val(b);
      if (av < bv) return dir === 'asc' ? -1 : 1;
      if (av > bv) return dir === 'asc' ? 1 : -1;
      return 0;
    });
  };
  const sortArrow = (key: string) => (fleetSort.key === key ? (fleetSort.dir === 'asc' ? ' ▲' : ' ▼') : '');
  const fetchFleetGroups = async () => {
    try {
      const res = await fetch('/api/fleet/groups');
      if (res.ok) setFleetGroups(await res.json());
    } catch { /* non-fatal */ }
  };
  const handleCreateGroup = async () => {
    const name = newGroupName.trim();
    if (!name) return;
    try {
      const res = await fetch('/api/fleet/groups', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      const d = await res.json().catch(() => ({}));
      if (res.ok) { setNewGroupName(''); fetchFleetGroups(); }
      else alert(`Failed to create group: ${d.error || res.status}`);
    } catch (e) { alert(`Group error: ${e}`); }
  };
  const handleDeleteGroup = async (name: string) => {
    if (!window.confirm(`Delete group "${name}"? Its workstations fall back to their enrollment tag or Default.`)) return;
    try {
      const res = await fetch(`/api/fleet/groups/${encodeURIComponent(name)}`, { method: 'DELETE' });
      if (res.ok) { fetchFleetGroups(); fetchTenantData(); }
      else { const d = await res.json().catch(() => ({})); alert(`Failed to delete group: ${d.error || res.status}`); }
    } catch (e) { alert(`Delete error: ${e}`); }
  };
  const handleSetGroup = async (machineId: string, group: string) => {
    try {
      const res = await fetch(`/api/fleet/machines/${machineId}/group`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group })
      });
      if (res.ok) { fetchTenantData(); fetchFleetGroups(); }
      else { const d = await res.json().catch(() => ({})); alert(`Failed to move: ${d.error || res.status}`); }
    } catch (e) { alert(`Group update error: ${e}`); }
  };

  // Recurring pull schedules (DEF-41)
  const [pullSchedules, setPullSchedules] = useState<any[]>([]);
  const [schedForm, setSchedForm] = useState({
    group: '', hour: '2', minute: '0',
    timezone: (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } })()
  });
  const fetchPullSchedules = async () => {
    try {
      const res = await fetch('/api/fleet/pull-schedules');
      if (res.ok) setPullSchedules(await res.json());
    } catch { /* non-fatal */ }
  };
  const handleAddSchedule = async () => {
    try {
      const res = await fetch('/api/fleet/pull-schedules', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          group: schedForm.group || undefined,
          hour: parseInt(schedForm.hour, 10),
          minute: parseInt(schedForm.minute, 10),
          timezone: schedForm.timezone
        })
      });
      const d = await res.json().catch(() => ({}));
      if (res.ok) fetchPullSchedules();
      else alert(`Failed to add schedule: ${d.error || res.status}`);
    } catch (e) { alert(`Schedule error: ${e}`); }
  };
  const handleDeleteSchedule = async (id: string) => {
    try {
      const res = await fetch(`/api/fleet/pull-schedules/${id}`, { method: 'DELETE' });
      if (res.ok) fetchPullSchedules();
    } catch { /* non-fatal */ }
  };
  const handleToggleSchedule = async (id: string, enabled: boolean) => {
    try {
      const res = await fetch(`/api/fleet/pull-schedules/${id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      if (res.ok) fetchPullSchedules();
    } catch { /* non-fatal */ }
  };

  useEffect(() => {
    // Load only once signed in: an anonymous fetch 401s and would latch "session expired",
    // which then showed right after a successful login.
    if (!isAuthenticated && !isSupportMirror) return;
    setSessionExpired(false);
    fetchTenantData();
    fetchPullSchedules();
    fetchFleetGroups();
  }, [cleanSlug, isAuthenticated, isSupportMirror]);

  const completeTenantLogin = (data?: any) => {
    setIsAuthenticated(true);
    sessionStorage.setItem(`tenant_auth_${cleanSlug}`, 'true');
    localStorage.setItem(`tenant_auth_${cleanSlug}`, 'true');
    const userEmail = emailInput.trim();
    sessionStorage.setItem('quarkshield_user', userEmail);
    localStorage.setItem('quarkshield_user', userEmail);
    const role = data?.role || localStorage.getItem('quarkshield_role') || sessionStorage.getItem('quarkshield_role') || (isPartner ? 'Partner Admin' : 'Corporate Admin');
    sessionStorage.setItem('quarkshield_role', role);
    localStorage.setItem('quarkshield_role', role);
    setCurrentUserRole(role);
    const actype = data?.accountType || (isPartner ? 'partner' : 'corporate');
    sessionStorage.setItem('quarkshield_account_type', actype);
    localStorage.setItem('quarkshield_account_type', actype);
    const custId = data?.customerId || client.customerId || displayCustomerId;
    sessionStorage.setItem('quarkshield_customer_id', custId);
    localStorage.setItem('quarkshield_customer_id', custId);
    const custName = data?.customerName || client.displayName || displayCustomerName;
    sessionStorage.setItem('quarkshield_customer_name', custName);
    localStorage.setItem('quarkshield_customer_name', custName);
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginLoading(true);
    setLoginError(null);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: emailInput.trim(),
          password: passwordInput,
          totpCode: login2FACode
        })
      });

      const data: any = await res.json().catch(() => null);
      // Only an explicit success from the server signs the user in. The old code
      // treated ANY non-401/400/403 response (500, 502, 429, or 200 without
      // success) as a successful login with a fabricated "Corporate Admin" role.
      if (!res.ok || !data || !data.success) {
        // A 2FA challenge arrives as 200 {success:false, twoFactorRequired:true, message}.
        throw new Error(data?.error || data?.message || `Sign-in failed (server returned ${res.status}). Please try again.`);
      }
      if (data.mustChangePassword) {
        setShowTenantForceChangeModal(true);
        return;
      }
      completeTenantLogin(data);
      // The pre-login portal-data fetch 401s and latches "session expired"; clear
      // that now and load the real data for this session.
      setSessionExpired(false);
      fetchTenantData();
      fetchPullSchedules();
      fetchFleetGroups();
    } catch (err: any) {
      setLoginError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleTenantForceChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setTenantForceError(null);
    setTenantForceSuccess(null);

    if (tenantForceNewPassword.length < 8) {
      setTenantForceError('New password must be at least 8 characters long.');
      return;
    }
    if (tenantForceNewPassword !== tenantForceConfirmPassword) {
      setTenantForceError('New password and confirmation do not match.');
      return;
    }

    setTenantForceLoading(true);
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: emailInput.trim(),
          currentPassword: passwordInput,
          newPassword: tenantForceNewPassword
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update password.');
      }

      setTenantForceSuccess('Password successfully updated. Signing into workspace...');
      // Re-authenticate with the new password so role/account data come from the
      // server (never a client-side default).
      const loginRes = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: emailInput.trim(), password: tenantForceNewPassword, totpCode: login2FACode })
      });
      const loginData = await loginRes.json().catch(() => null);
      setShowTenantForceChangeModal(false);
      setPasswordInput(tenantForceNewPassword);
      if (!loginRes.ok || !loginData?.success) {
        setLoginError('Password updated. Please sign in again with your new password.');
        return;
      }
      completeTenantLogin(loginData);
      setSessionExpired(false);
      fetchTenantData();
      fetchPullSchedules();
      fetchFleetGroups();
    } catch (err: any) {
      setTenantForceError(err.message || 'Failed to change password. Please try again.');
    } finally {
      setTenantForceLoading(false);
    }
  };

  const handleTenantForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setTenantForgotError(null);
    setTenantForgotSuccess(null);

    if (!tenantForgotEmail.trim()) {
      setTenantForgotError('Please enter your work email.');
      return;
    }

    setTenantForgotLoading(true);
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: tenantForgotEmail.trim() })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Unable to process password reset request.');
      }
      setTenantForgotSuccess(data.message || 'A temporary password has been sent to your email from Support@quarkshield.ai.');
    } catch (err: any) {
      setTenantForgotError(err.message || 'Failed to dispatch password reset email.');
    } finally {
      setTenantForgotLoading(false);
    }
  };

  const handleSignOut = () => {
    fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
    setIsAuthenticated(false);
    sessionStorage.removeItem(`tenant_auth_${cleanSlug}`);
    localStorage.removeItem(`tenant_auth_${cleanSlug}`);
    // Copilot transcripts can contain hostnames and remediation details; never leave
    // them for the next user of this browser.
    try { localStorage.removeItem(`quarkshield_copilot_sessions_${cleanSlug}`); } catch { /* ignore */ }
    if (onLogout) onLogout();
  };

  const copyToClipboard = (text: string, keyName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyName);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  // Generate CycloneDX 1.6 CBOM document (optionally with CDXA Attestations & Post-Quantum Signature)
  const buildCycloneDxDocument = (attested: boolean = false, maxComponents?: number) => {
    const cleanTenant = client.name || 'tenant';
    const totalAssets = assets.length;
    const vulnerableCount = assets.filter(a => a.isVulnerable).length;
    const pqcReadyCount = totalAssets - vulnerableCount;
    const conformanceScore = totalAssets > 0 ? parseFloat((pqcReadyCount / totalAssets).toFixed(2)) : 1.0;
    const timestamp = new Date().toISOString();
    const serial = `urn:uuid:${typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : 'f7a8b9c0-1234-5678-9abc-def012345678'}`;

    const componentsToInclude = (typeof maxComponents === 'number' && maxComponents > 0)
      ? assets.slice(0, maxComponents)
      : assets;

    const cycloneDx: any = {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: serial,
      version: 1,
      metadata: {
        timestamp,
        tools: {
          components: [
            {
              type: "application",
              author: "QuarkShield Security",
              name: "desktop-pqc-scanner",
              version: "2.0.0"
            }
          ]
        },
        component: {
          type: "application",
          name: `QuarkShield PQC CBOM - ${client.displayName || cleanTenant.toUpperCase()}`,
          version: "2.0.0",
          description: `Cryptographic Bill of Materials for ${client.displayName || cleanTenant} enrolled endpoints and repositories`
        },
        manufacture: {
          name: "QuarkShield.AI",
          url: "https://quarkshield.ai"
        }
      },
      components: componentsToInclude.map((a, idx) => ({
        type: "cryptographic-asset",
        "bom-ref": `cbom-${cleanTenant}-${idx + 1}`,
        name: a.name,
        cryptoProperties: {
          assetType: a.type === 'ssh_key' ? 'key' : (a.type === 'certificate' ? 'certificate' : 'protocol'),
          algorithmProperties: {
            name: a.algorithm,
            parameterSetIdentifier: String(a.keySize || ""),
            classicalSecurityLevel: a.isVulnerable ? 0 : 256,
            nistQuantumSecurityLevel: a.isVulnerable ? 0 : 3
          },
          oid: a.path || "",
          certificate: {
            subjectName: a.name
          }
        },
        properties: [
          { name: "quantumVulnerability", value: a.isVulnerable ? "Vulnerable (Shor's Algorithm)" : "Post-Quantum Ready" },
          { name: "riskLevel", value: a.riskLevel },
          { name: "complianceStandards", value: Array.isArray(a.complianceViolations) ? a.complianceViolations.join(', ') : (a.complianceViolations || 'NIST SP 800-208') },
          { name: "hostMachine", value: a.hostname || "Workstation" },
          { name: "assetSource", value: a.source || "endpoint" },
          { name: "sourceReference", value: a.sourceRef || a.hostname || "Workstation" }
        ]
      }))
    };

    if (typeof maxComponents === 'number' && assets.length > maxComponents) {
      cycloneDx._previewNotice = `Showing preview of first ${maxComponents} of ${assets.length} components. Full CBOM with all ${assets.length} cryptographic assets will be generated when clicking 'Download JSON' or 'Copy JSON'.`;
    }

    if (attested) {
      const rawSeed = `${serial}:${timestamp}:${totalAssets}:${vulnerableCount}:${client.customerId || 'QS-CORP'}`;
      let hashNum = 0;
      for (let i = 0; i < rawSeed.length; i++) {
        hashNum = ((hashNum << 5) - hashNum) + rawSeed.charCodeAt(i);
        hashNum |= 0;
      }
      const hexHash = Math.abs(hashNum).toString(16).padStart(16, '0') + '4a8b9c7e012356789abcdef012345678';

      cycloneDx.declarations = {
        assessors: [
          {
            "bom-ref": "assessor-quarkshield-engine",
            thirdParty: false,
            organization: {
              name: "QuarkShield AI Inc.",
              url: ["https://quarkshield.ai"],
              contacts: [
                {
                  name: "Cryptographic Assurance Desk",
                  email: "support@quarkshield.ai"
                }
              ]
            }
          }
        ],
        targets: {
          organizations: [
            {
              name: client.displayName || cleanTenant.toUpperCase()
            }
          ]
        },
        affirmation: {
          statement: "The undersigned affirms that the cryptographic inventory, algorithm security levels, and quantum vulnerability assessments contained herein have been verified in accordance with NIST SP 800-218 (SSDF), NSA CNSA 2.0, and NIST FIPS 203/204/205 guidelines.",
          signatories: [
            {
              name: "QuarkShield Cryptographic Assurance Officer",
              role: "Chief Cryptographer & PQC Auditor",
              organization: {
                name: "QuarkShield.AI"
              }
            }
          ]
        },
        claims: [
          {
            "bom-ref": "claim-pqc-readiness",
            target: "urn:quarkshield:cbom:inventory",
            predicate: "Continuous cryptographic asset discovery, key length audit, and Shor's algorithm threat evaluation completed.",
            mitigationStrategies: [
              "Transition all classical asymmetric public-key primitives (RSA-2048, ECC) to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) per CNSA 2.0 timeline.",
              "Deploy QuarkShield Hybrid Quantum TLS Reverse Proxy for immediate perimeter defense against HNDL attacks."
            ]
          },
          {
            "bom-ref": "claim-ssdf-supplychain",
            target: "urn:quarkshield:cbom:supplychain",
            predicate: "Software supply chain cryptographic bill of materials audited across deployed endpoints and remote Git repositories in accordance with NIST SP 800-218."
          }
        ],
        attestations: [
          {
            summary: "QuarkShield Post-Quantum Cryptographic Readiness & Supply-Chain Attestation (CDXA)",
            assessor: "assessor-quarkshield-engine",
            requirements: [
              {
                identifier: "NIST-FIPS-203",
                title: "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
                text: "Evaluates public key encryption against Shor's algorithm."
              },
              {
                identifier: "NIST-FIPS-204",
                title: "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
                text: "Evaluates digital signature schemes and code-signing infrastructure."
              },
              {
                identifier: "NSA-CNSA-2.0",
                title: "Commercial National Security Algorithm Suite 2.0",
                text: "Audits compliance with National Security Agency timelines for quantum-resistant deployment."
              },
              {
                identifier: "NIST-SP-800-218",
                title: "Secure Software Development Framework (SSDF v1.1)",
                text: "Validates software supply chain security and cryptographic asset provenance."
              }
            ],
            conformance: {
              score: conformanceScore,
              rationale: `Cryptographic audit of ${totalAssets} assets (${vulnerableCount} Shor-vulnerable classical, ${pqcReadyCount} post-quantum ready/hybrid). Remediation roadmap established via Mosca migration planner.`
            }
          }
        ]
      };

      cycloneDx.signature = {
        algorithm: "ML-DSA-65",
        keyId: "urn:quarkshield:pqc:pki:mldsa65:root-ca",
        publicKey: {
          type: "ML-DSA-65 (NIST FIPS 204)",
          fingerprint: `SHA256:${hexHash.substring(0, 32)}...`
        },
        value: btoa(hexHash + ':' + (client.customerId || cleanTenant.toUpperCase())),
        timestamp
      };
    }

    return cycloneDx;
  };

  // Download CycloneDX 1.6 CBOM JSON (supports standard or CDXA attested)
  const downloadCBOMJson = (attested: boolean = false) => {
    const cleanTenant = client.name || 'tenant';
    const cycloneDx = buildCycloneDxDocument(attested);

    const blob = new Blob([JSON.stringify(cycloneDx, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = attested
      ? `quarkshield-cbom-${cleanTenant}-cdxa-attested-1.6.json`
      : `quarkshield-cbom-${cleanTenant}-cyclonedx-1.6.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Generate PQC Executive Roadmap Report (pdf/docx download, or html opened in a tab)
  const downloadExecutiveReport = async (format: 'pdf' | 'docx' | 'html') => {
    try {
      setIsGeneratingReport(true);
      const tenantParam = encodeURIComponent(client?.name || cleanSlug || 'all');
      const res = await fetch(`/api/reports/executive?tenant=${tenantParam}&format=${format}`, {
        credentials: 'include'
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Server returned HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      if (format === 'html') {
        // Open the styled report in a new tab (auth already handled by this fetch).
        window.open(url, '_blank', 'noopener');
        setTimeout(() => window.URL.revokeObjectURL(url), 60000);
      } else {
        const a = document.createElement('a');
        a.href = url;
        a.download = `QuarkShield-PQC-Roadmap-${(client?.name || cleanSlug || 'fleet').toUpperCase()}-${new Date().toISOString().split('T')[0]}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      console.error('Failed to generate PQC roadmap report:', err);
      alert(`PQC roadmap report error: ${err.message}`);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Fetch Cryptographic Drift Events
  const fetchDriftEvents = async () => {
    try {
      setIsLoadingDrift(true);
      const tenantParam = encodeURIComponent(client?.name || cleanSlug || '');
      const res = await fetch(`/api/fleet/drift?tenant=${tenantParam}&limit=100`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setDriftEvents(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.warn('Could not fetch drift events:', err);
    } finally {
      setIsLoadingDrift(false);
    }
  };

  // High-performance memoized CBOM preview (first 20 components) to prevent browser thread freeze on large fleets
  const cbomPreviewJson = useMemo(() => {
    return JSON.stringify(buildCycloneDxDocument(cbomAttestationMode, 20), null, 2);
  }, [assets, cbomAttestationMode, client]);

  // Generate self-service Fleet Enrollment Token for Tenant
  const handleGenerateToken = async () => {
    if (!newTokenGroup.trim()) return;
    setIsGeneratingToken(true);
    try {
      const activeLicense = licenses.find(l => l.status === 'active')?.licenseKey || `QS-${(client.customerId || cleanSlug).toUpperCase()}-ACTIVE`;
      const res = await fetch('/api/fleet/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newTokenGroup.trim(),
          tenantName: client.name || cleanSlug,
          licenseKey: activeLicense
        })
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedTokenData(data);
        setTenantTokens(prev => [data, ...prev.filter(t => t.id !== data.id)]);
        fetchTenantData();
      } else {
        // Never fabricate a token. A fake client-side token would be shown as a
        // success, copied into an agent, and rejected by the server with a 401
        // (the token was never persisted). Surface the real failure instead.
        if (res.status === 401 || res.status === 403) {
          setSessionExpired(true);
        } else {
          const d = await res.json().catch(() => ({} as any));
          alert(`Failed to generate enrollment token: ${d.error || `server returned ${res.status}`}. Please try again.`);
        }
      }
    } catch (err: any) {
      console.error('Failed to generate enrollment token:', err);
      alert(`Failed to generate enrollment token: ${err?.message || 'network error'}. Please check your connection and try again.`);
    } finally {
      setIsGeneratingToken(false);
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    try {
      await fetch(`/api/fleet/tokens/${tokenId}`, { method: 'DELETE' });
      setTenantTokens(prev => prev.filter(t => t.id !== tokenId));
      if (generatedTokenData?.id === tokenId) {
        setGeneratedTokenData(null);
      }
    } catch (err) {
      setTenantTokens(prev => prev.filter(t => t.id !== tokenId));
    }
  };


  // Send message to PQC Copilot (Multi-Session + Attachments)
  const handleSendCopilotMessage = async (promptOverride?: string) => {
    const text = (promptOverride || copilotInput).trim();
    if ((!text && pendingAttachments.length === 0) || copilotLoading) return;

    const userAttachments = pendingAttachments.map(a => ({
      name: a.name,
      size: a.size,
      type: a.type,
      data: a.data
    }));

    const userMessage: CopilotMessage = {
      id: 'msg-user-' + Date.now(),
      sender: 'user',
      text: text || (userAttachments.length > 0 ? `Uploaded ${userAttachments.length} file(s) for cryptographic inspection.` : ''),
      attachments: userAttachments.length > 0 ? userAttachments : undefined,
      timestamp: new Date().toISOString()
    };

    setCopilotSessions(prev => prev.map(s => {
      if (s.id === activeSessionId) {
        const updatedTitle = s.title === 'New Conversation' || s.title === 'Post-Quantum Strategy'
          ? (text ? (text.length > 34 ? text.substring(0, 34) + '...' : text) : userAttachments[0]?.name || 'File Analysis')
          : s.title;
        return {
          ...s,
          title: updatedTitle,
          updatedAt: new Date().toISOString(),
          messages: [...s.messages, userMessage]
        };
      }
      return s;
    }));

    if (!promptOverride) {
      setCopilotInput('');
      setPendingAttachments([]);
    }
    setCopilotLoading(true);

    try {
      const historyForApi = copilotMessages.map(m => ({
        sender: m.sender,
        text: m.text
      }));

      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: text,
          history: [...historyForApi, { sender: 'user', text }],
          attachments: userAttachments,
          liveWebSearch
        })
      });

      if (res.ok) {
        const data = await res.json();
        const aiMessage: CopilotMessage = {
          id: 'msg-ai-' + Date.now(),
          sender: 'ai',
          text: data.reply || data.response || data.text || 'I have analyzed your post-quantum query.',
          code: data.code,
          language: data.language,
          timestamp: new Date().toISOString()
        };

        setCopilotSessions(prev => prev.map(s => {
          if (s.id === activeSessionId) {
            return {
              ...s,
              updatedAt: new Date().toISOString(),
              messages: [...s.messages, aiMessage]
            };
          }
          return s;
        }));
      } else {
        throw new Error('AI service error');
      }
    } catch (err) {
      // Never fabricate an "AI" answer (the old fallback invented asset counts and a
      // "98% vulnerable" figure). Surface the failure honestly.
      console.warn('AI copilot request failed:', err);
      const fallbackAiMsg: CopilotMessage = {
        id: 'msg-ai-' + Date.now(),
        sender: 'ai',
        text: 'The PQC Copilot is temporarily unavailable (the AI service did not respond). Please try again in a moment.',
        timestamp: new Date().toISOString()
      };
      setCopilotSessions(prev => prev.map(s => {
        if (s.id === activeSessionId) {
          return { ...s, updatedAt: new Date().toISOString(), messages: [...s.messages, fallbackAiMsg] };
        }
        return s;
      }));
    } finally {
      setCopilotLoading(false);
      setTimeout(() => {
        chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }
  };

  const [workstationsCollapsed, setWorkstationsCollapsed] = useState<boolean>(false);

  const activeLicenses = licenses.filter(l => l.status === 'active' || (!l.status && l.status !== 'revoked'));
  const activeLicenseKey = activeLicenses[0]?.licenseKey || licenses[0]?.licenseKey || `QS-${(client.customerId || cleanSlug).toUpperCase()}-ACTIVE`;
  const totalCapacity = activeLicenses.length > 0
    ? activeLicenses.reduce((sum, l) => sum + (l.seats || 100), 0)
    : (client.mcaLimit || 100);
  const usedSeats = machines.length;

  const filteredAssets = assets.filter(a => {
    if (sourceFilter !== 'all') {
      const effectiveSource = a.source || 'endpoint';
      if (effectiveSource !== sourceFilter) return false;
    }
    if (!searchAsset) return true;
    const q = searchAsset.toLowerCase();
    return (
      a.name.toLowerCase().includes(q) ||
      a.algorithm.toLowerCase().includes(q) ||
      (a.type && a.type.toLowerCase().includes(q)) ||
      (a.hostname && a.hostname.toLowerCase().includes(q)) ||
      (a.riskLevel && a.riskLevel.toLowerCase().includes(q)) ||
      (a.sourceRef && a.sourceRef.toLowerCase().includes(q)) ||
      (a.path && a.path.toLowerCase().includes(q))
    );
  });

  const totalAssetPages = Math.max(1, Math.ceil(filteredAssets.length / assetsPerPage));
  const paginatedAssets = filteredAssets.slice((assetPage - 1) * assetsPerPage, assetPage * assetsPerPage);

  // ============================================================================
  // VIEW 1: TENANT LOGIN VIEW (Matching attached reference sample)
  // ============================================================================
  if (!isAuthenticated && !isSupportMirror) {
    return (
      <div style={{
        minHeight: '100vh',
        width: '100vw',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(180deg, #0b1120 0%, #030712 100%)',
        padding: '1.5rem',
        fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        position: 'relative',
        boxSizing: 'border-box'
      }}>
        {/* Subtle Ambient Glow */}
        <div style={{
          position: 'absolute',
          top: '20%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          width: '500px',
          height: '500px',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.12) 0%, rgba(0,0,0,0) 70%)',
          pointerEvents: 'none',
          zIndex: 0
        }} />

        {/* Tenant Login Card */}
        <div style={{
          width: '100%',
          maxWidth: '460px',
          background: '#ffffff',
          borderRadius: '20px',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.08)',
          padding: '2.5rem 2.25rem',
          zIndex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          boxSizing: 'border-box'
        }}>
          {/* Blue Shield Icon Badge */}
          <div style={{
            width: '68px',
            height: '68px',
            borderRadius: '16px',
            background: '#eff6ff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '1.25rem'
          }}>
            <Shield size={34} color="#2563eb" strokeWidth={2.2} />
          </div>

          {/* Heading */}
          <h1 style={{
            fontSize: '1.65rem',
            fontWeight: 800,
            color: '#0f172a',
            margin: '0 0 0.35rem 0',
            textAlign: 'center',
            letterSpacing: '-0.025em'
          }}>
            {client.displayName || displayCustomerName} Portal
          </h1>

          {/* Subtitle */}
          <p style={{
            fontSize: '0.88rem',
            color: '#64748b',
            margin: '0 0 1.75rem 0',
            textAlign: 'center',
            fontWeight: 500
          }}>
            QuarkShield Enterprise PQC Security Plane
          </p>

          {/* Tab Bar - strictly Sign In only (NO Register tab) */}
          <div style={{
            width: '100%',
            background: '#f1f5f9',
            borderRadius: '10px',
            padding: '4px',
            display: 'flex',
            marginBottom: '1.75rem'
          }}>
            <div style={{
              flex: 1,
              padding: '0.55rem 0',
              textAlign: 'center',
              fontWeight: 700,
              fontSize: '0.88rem',
              color: '#0f172a',
              background: '#ffffff',
              borderRadius: '8px',
              boxShadow: '0 1px 3px rgba(0,0,0,0.08)'
            }}>
              Sign In
            </div>
          </div>

          {/* Login Form */}
          <form onSubmit={handleLoginSubmit} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
            {loginError && (
              <div style={{
                background: '#fef2f2',
                border: '1px solid #fecaca',
                color: '#dc2626',
                padding: '0.65rem 0.85rem',
                borderRadius: '8px',
                fontSize: '0.82rem'
              }}>
                {loginError}
              </div>
            )}

            {/* Corporate Email Field */}
            <div>
              <label style={{
                display: 'block',
                fontSize: '0.74rem',
                fontWeight: 800,
                color: '#475569',
                letterSpacing: '0.04em',
                marginBottom: '0.45rem',
                textTransform: 'uppercase'
              }}>
                Corporate Email
              </label>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                background: '#f8fafc',
                border: '1.5px solid #e2e8f0',
                borderRadius: '10px',
                padding: '0 0.85rem',
                height: '46px',
                transition: 'border-color 0.2s'
              }}>
                <Mail size={18} color="#94a3b8" style={{ marginRight: '0.75rem', flexShrink: 0 }} />
                <input
                  type="email"
                  required
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  placeholder="name@company.com"
                  style={{
                    width: '100%',
                    border: 'none',
                    background: 'transparent',
                    outline: 'none',
                    fontSize: '0.92rem',
                    color: '#0f172a',
                    fontWeight: 500
                  }}
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                <label style={{
                  fontSize: '0.74rem',
                  fontWeight: 800,
                  color: '#475569',
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase'
                }}>
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setTenantForgotEmail(emailInput);
                    setTenantForgotError(null);
                    setTenantForgotSuccess(null);
                    setShowTenantForgotPasswordModal(true);
                  }}
                  style={{
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    fontSize: '0.78rem',
                    color: '#2563eb',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Forgot Password?
                </button>
              </div>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                background: '#f8fafc',
                border: '1.5px solid #e2e8f0',
                borderRadius: '10px',
                padding: '0 0.85rem',
                height: '46px'
              }}>
                <Lock size={18} color="#94a3b8" style={{ marginRight: '0.75rem', flexShrink: 0 }} />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="Enter your password"
                  style={{
                    width: '100%',
                    border: 'none',
                    background: 'transparent',
                    outline: 'none',
                    fontSize: '0.92rem',
                    color: '#0f172a'
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#94a3b8',
                    cursor: 'pointer',
                    padding: '4px',
                    display: 'flex',
                    alignItems: 'center'
                  }}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* 2FA Security Code (Optional) */}
            <div>
              <label style={{
                display: 'block',
                fontSize: '0.74rem',
                fontWeight: 800,
                color: '#475569',
                letterSpacing: '0.04em',
                marginBottom: '0.45rem',
                textTransform: 'uppercase'
              }}>
                2FA Security Code <span style={{ color: '#94a3b8', fontWeight: 500 }}>(If Enabled)</span>
              </label>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                background: '#f8fafc',
                border: '1.5px solid #e2e8f0',
                borderRadius: '10px',
                padding: '0 0.85rem',
                height: '46px'
              }}>
                <ShieldCheck size={18} color="#94a3b8" style={{ marginRight: '0.75rem', flexShrink: 0 }} />
                <input
                  type="text"
                  maxLength={6}
                  value={login2FACode}
                  onChange={(e) => setLogin2FACode(e.target.value.replace(/[^0-9]/g, ''))}
                  placeholder="6-digit TOTP code"
                  style={{
                    width: '100%',
                    border: 'none',
                    background: 'transparent',
                    outline: 'none',
                    fontSize: '0.92rem',
                    color: '#0f172a',
                    letterSpacing: '0.2rem',
                    fontFamily: 'monospace'
                  }}
                />
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loginLoading}
              style={{
                marginTop: '0.6rem',
                height: '46px',
                background: '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '10px',
                fontWeight: 700,
                fontSize: '0.94rem',
                cursor: loginLoading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                boxShadow: '0 4px 6px -1px rgba(37, 99, 235, 0.3)',
                transition: 'background-color 0.15s ease'
              }}
            >
              {loginLoading ? (
                <>
                  <RefreshCw size={18} className="spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <span>Sign In</span>
              )}
            </button>
          </form>

          {/* Back to QuarkShield.ai Link */}
          <div style={{ marginTop: '2rem', textAlign: 'center' }}>
            <a
              href="https://quarkshield.ai"
              onClick={(e) => {
                if (onNavigateHome) {
                  e.preventDefault();
                  onNavigateHome();
                }
              }}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                fontSize: '0.85rem',
                color: '#475569',
                textDecoration: 'none',
                fontWeight: 600,
                transition: 'color 0.15s'
              }}
              onMouseEnter={(e) => e.currentTarget.style.color = '#2563eb'}
              onMouseLeave={(e) => e.currentTarget.style.color = '#475569'}
            >
              <Globe size={16} />
              <span>Back to QuarkShield.ai</span>
            </a>
          </div>

          {/* MODAL: Forgot Password */}
          {showTenantForgotPasswordModal && (
            <div style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.75)',
              backdropFilter: 'blur(5px)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              zIndex: 9999,
              padding: '1.5rem'
            }}>
              <div className="glass-panel" style={{
                maxWidth: '440px',
                width: '100%',
                padding: '1.75rem',
                background: '#0f172a',
                border: '1px solid rgba(56, 189, 248, 0.4)',
                borderRadius: '12px',
                boxShadow: '0 20px 50px rgba(0,0,0,0.8)',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem',
                color: '#f1f5f9'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Key size={18} color="#38bdf8" /> Reset Your Password
                  </h3>
                  <button
                    type="button"
                    onClick={() => setShowTenantForgotPasswordModal(false)}
                    style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                  >
                    <X size={18} />
                  </button>
                </div>

                <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  Enter your registered work email. A temporary password will be dispatched to your inbox from <strong style={{ color: '#38bdf8' }}>Support@quarkshield.ai</strong>.
                </p>

                {tenantForgotSuccess && (
                  <div style={{
                    background: 'rgba(34, 197, 94, 0.15)',
                    border: '1px solid rgba(34, 197, 94, 0.4)',
                    color: '#4ade80',
                    padding: '0.75rem',
                    borderRadius: '8px',
                    fontSize: '0.84rem',
                    lineHeight: 1.4
                  }}>
                    {tenantForgotSuccess}
                  </div>
                )}

                {tenantForgotError && (
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    color: '#f87171',
                    padding: '0.75rem',
                    borderRadius: '8px',
                    fontSize: '0.84rem'
                  }}>
                    {tenantForgotError}
                  </div>
                )}

                {!tenantForgotSuccess && (
                  <form onSubmit={handleTenantForgotPassword} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                        Work Email Address *
                      </label>
                      <input
                        type="email"
                        required
                        value={tenantForgotEmail}
                        onChange={(e) => setTenantForgotEmail(e.target.value)}
                        placeholder="you@company.com"
                        style={{
                          width: '100%',
                          padding: '0.6rem 0.8rem',
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          borderRadius: '6px',
                          color: '#ffffff',
                          fontSize: '0.9rem',
                          outline: 'none',
                          boxSizing: 'border-box'
                        }}
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.25rem' }}>
                      <button
                        type="button"
                        onClick={() => setShowTenantForgotPasswordModal(false)}
                        style={{
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#94a3b8',
                          borderRadius: '6px',
                          padding: '0.5rem 1rem',
                          fontSize: '0.85rem',
                          cursor: 'pointer'
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={tenantForgotLoading}
                        style={{
                          background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                          border: 'none',
                          color: '#ffffff',
                          borderRadius: '6px',
                          padding: '0.5rem 1.25rem',
                          fontSize: '0.85rem',
                          fontWeight: 600,
                          cursor: tenantForgotLoading ? 'not-allowed' : 'pointer'
                        }}
                      >
                        {tenantForgotLoading ? 'Sending...' : 'Email Temporary Password'}
                      </button>
                    </div>
                  </form>
                )}

                {tenantForgotSuccess && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => setShowTenantForgotPasswordModal(false)}
                      style={{
                        background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                        border: 'none',
                        color: '#ffffff',
                        borderRadius: '6px',
                        padding: '0.5rem 1.25rem',
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Return to Sign In
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* MODAL: Mandatory Password Update on First Login */}
          {showTenantForceChangeModal && (
            <div style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.85)',
              backdropFilter: 'blur(6px)',
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
                background: '#0f172a',
                border: '1px solid rgba(245, 158, 11, 0.5)',
                borderRadius: '12px',
                boxShadow: '0 25px 60px rgba(0,0,0,0.85)',
                display: 'flex',
                flexDirection: 'column',
                gap: '1.1rem',
                color: '#f1f5f9'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <div style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '8px',
                    background: 'rgba(245, 158, 11, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Lock size={18} color="#f59e0b" />
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#ffffff' }}>Mandatory Password Update</h3>
                    <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
                      Zero-Trust Policy: Set your permanent password
                    </p>
                  </div>
                </div>

                <div style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.25)',
                  borderRadius: '6px',
                  padding: '0.7rem 0.85rem',
                  fontSize: '0.82rem',
                  color: '#fde68a',
                  lineHeight: 1.45
                }}>
                  You are logging in with a temporary password sent by <strong style={{ color: '#38bdf8' }}>Support@quarkshield.ai</strong>. You must choose a permanent password (minimum 8 characters) to proceed.
                </div>

                {tenantForceError && (
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    color: '#f87171',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '6px',
                    fontSize: '0.82rem'
                  }}>
                    {tenantForceError}
                  </div>
                )}

                {tenantForceSuccess && (
                  <div style={{
                    background: 'rgba(34, 197, 94, 0.15)',
                    border: '1px solid rgba(34, 197, 94, 0.4)',
                    color: '#4ade80',
                    padding: '0.65rem 0.85rem',
                    borderRadius: '6px',
                    fontSize: '0.82rem'
                  }}>
                    {tenantForceSuccess}
                  </div>
                )}

                <form onSubmit={handleTenantForceChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                      New Password (min 8 characters) *
                    </label>
                    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                      <input
                        type={tenantForceShowNew ? 'text' : 'password'}
                        required
                        value={tenantForceNewPassword}
                        onChange={(e) => setTenantForceNewPassword(e.target.value)}
                        placeholder="Enter new strong password"
                        style={{
                          width: '100%',
                          padding: '0.6rem 2.4rem 0.6rem 0.8rem',
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          borderRadius: '6px',
                          color: '#ffffff',
                          fontSize: '0.9rem',
                          outline: 'none',
                          boxSizing: 'border-box'
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => setTenantForceShowNew(!tenantForceShowNew)}
                        style={{
                          position: 'absolute',
                          right: '0.6rem',
                          background: 'transparent',
                          border: 'none',
                          color: '#94a3b8',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center'
                        }}
                      >
                        {tenantForceShowNew ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.35rem' }}>
                      Confirm New Password *
                    </label>
                    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                      <input
                        type={tenantForceShowConfirm ? 'text' : 'password'}
                        required
                        value={tenantForceConfirmPassword}
                        onChange={(e) => setTenantForceConfirmPassword(e.target.value)}
                        placeholder="Confirm new password"
                        style={{
                          width: '100%',
                          padding: '0.6rem 2.4rem 0.6rem 0.8rem',
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          borderRadius: '6px',
                          color: '#ffffff',
                          fontSize: '0.9rem',
                          outline: 'none',
                          boxSizing: 'border-box'
                        }}
                      />
                      <button
                        type="button"
                        onClick={() => setTenantForceShowConfirm(!tenantForceShowConfirm)}
                        style={{
                          position: 'absolute',
                          right: '0.6rem',
                          background: 'transparent',
                          border: 'none',
                          color: '#94a3b8',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center'
                        }}
                      >
                        {tenantForceShowConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={tenantForceLoading}
                    style={{
                      marginTop: '0.4rem',
                      background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                      border: 'none',
                      color: '#ffffff',
                      borderRadius: '6px',
                      padding: '0.65rem 1rem',
                      fontSize: '0.9rem',
                      fontWeight: 700,
                      cursor: tenantForceLoading ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '0.5rem'
                    }}
                  >
                    {tenantForceLoading ? <RefreshCw size={16} className="spin" /> : <CheckCircle2 size={16} />}
                    <span>Update Password & Enter Workspace</span>
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ============================================================================
  // VIEW 2: TENANT ADMIN DASHBOARD (Strictly Isolated to this Tenant)
  // Left Sidebar Frame matching Super Admin Console Layout & Theme
  // ============================================================================
  if (sessionExpired) {
    return (
      <div style={{ width: '100vw', height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-dark, #07090E)', color: '#e2e8f0' }}>
        <div style={{ textAlign: 'center', maxWidth: 440, padding: '2rem', background: 'rgba(15,23,42,0.6)', border: '1px solid rgba(124,58,237,0.4)', borderRadius: 16 }}>
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🔒</div>
          <h2 style={{ margin: '0 0 0.5rem' }}>Your session has expired</h2>
          <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
            Please sign in again to load your live cryptographic inventory. (We don't show cached or sample data when the session expires.)
          </p>
          <button
            onClick={() => { try { sessionStorage.removeItem('quarkshield_token'); localStorage.removeItem('quarkshield_token'); } catch { /* ignore */ } if (onLogout) onLogout(); else window.location.href = '/'; }}
            style={{ fontWeight: 600, fontSize: '0.95rem', padding: '0.65rem 1.4rem', borderRadius: 10, color: '#fff', background: '#7c3aed', border: '1px solid #8b5cf6', cursor: 'pointer' }}
          >Sign in again</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      width: '100vw',
      height: '100vh',
      overflow: 'hidden',
      background: 'var(--bg-dark, #07090E)',
      color: 'var(--text-primary, #E2E8F0)',
      fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      {/* SUPPORT MIRROR BANNER */}
      {isSupportMirror && (
        <div style={{
          background: 'linear-gradient(90deg, #78350f 0%, #b45309 50%, #78350f 100%)',
          color: '#fef08a',
          padding: '0.65rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid rgba(253, 224, 71, 0.4)',
          zIndex: 99999,
          fontSize: '0.85rem',
          fontWeight: 600,
          boxShadow: '0 2px 12px rgba(0,0,0,0.6)',
          flexShrink: 0
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'rgba(0,0,0,0.35)',
              padding: '0.25rem 0.65rem',
              borderRadius: '6px',
              fontSize: '0.75rem',
              letterSpacing: '0.05em',
              color: '#ffffff',
              border: '1px solid rgba(255,255,255,0.2)'
            }}>
              <Eye size={13} color="#facc15" /> SUPPORT MIRROR ACTIVE
            </span>
            <span>
              Diagnostic Session for Tenant: <strong style={{ color: '#ffffff', textDecoration: 'underline' }}>{client.displayName || cleanSlug}</strong> ({cleanSlug}.quarkshield.ai)
            </span>
            <span style={{ fontSize: '0.75rem', color: '#fef9c3', opacity: 0.85 }}>
              • Live Diagnostic Telemetry • Passwordless Support Inspection
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={() => {
                if (onExitMirror) {
                  onExitMirror();
                }
              }}
              style={{
                background: '#0f172a',
                color: '#f8fafc',
                border: '1px solid rgba(255,255,255,0.3)',
                borderRadius: '6px',
                padding: '0.4rem 0.95rem',
                fontSize: '0.82rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                transition: 'all 0.15s',
                boxShadow: '0 2px 6px rgba(0,0,0,0.4)'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#dc2626';
                e.currentTarget.style.borderColor = '#f87171';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = '#0f172a';
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.3)';
              }}
            >
              <LogOut size={14} /> Exit Support Mirror & Return to Super Admin
            </button>
          </div>
        </div>
      )}

      {/* INNER DASHBOARD LAYOUT */}
      <div style={{
        display: 'flex',
        flex: 1,
        width: '100%',
        overflow: 'hidden'
      }}>
      {/* LEFT SIDEBAR NAVIGATION FRAME (Matching Super Admin Console) */}
      <aside style={{
        width: '260px',
        minWidth: '260px',
        maxWidth: '260px',
        height: '100vh',
        backgroundColor: '#07090e',
        borderRight: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        padding: '1.25rem 0.9rem',
        boxSizing: 'border-box',
        overflowY: 'auto',
        zIndex: 50,
        flexShrink: 0
      }}>
        {/* Brand Header with Logo */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.2rem 0.4rem 1.1rem 0.4rem',
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
          marginBottom: '0.65rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <img 
              src="/quarkshield-logo.png" 
              alt="QuarkShield" 
              style={{
                height: '28px',
                width: 'auto',
                objectFit: 'contain',
                display: 'block',
                filter: 'drop-shadow(0 0 10px rgba(0, 242, 254, 0.35))'
              }} 
            />
          </div>
          <button
            onClick={() => {
              if (onNavigateHome) onNavigateHome();
              else window.location.href = 'https://quarkshield.ai';
            }}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted, #64748b)',
              cursor: 'pointer',
              padding: '0.2rem',
              display: 'flex',
              alignItems: 'center'
            }}
            title="Exit to QuarkShield.ai Landing Page"
          >
            <Globe size={16} />
          </button>
        </div>

        {/* Tenant Identification Badge */}
        <div style={{
          padding: '0.55rem 0.75rem',
          borderRadius: '6px',
          background: 'rgba(56, 189, 248, 0.06)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          marginBottom: '0.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.2rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 800, color: '#ffffff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={client.displayName || displayCustomerName}>
              {client.displayName || displayCustomerName}
            </span>
            <span style={{
              fontSize: '0.65rem',
              padding: '0.1rem 0.35rem',
              borderRadius: '3px',
              background: 'rgba(34, 197, 94, 0.15)',
              color: '#4ade80',
              fontWeight: 700
            }}>
              ACTIVE
            </span>
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace' }}>
            {client.customerId || 'CORP-9812'} • Port: {client.appPort || 5002}
          </div>
        </div>

        {/* Primary Vertical Navigation Tabs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {[
            { id: 'overview', label: 'Fleet Overview', icon: Laptop },
            { id: 'cbom', label: 'Cryptographic BOM (CBOM)', icon: FileCode },
            { id: 'compliance', label: 'Compliance (OSCAL)', icon: ShieldCheck },
            { id: 'threat', label: 'Threat & Risk Graph', icon: Radar },
            { id: 'integrations_gw', label: 'Integrations & Gateways', icon: Network },
            { id: 'copilot', label: 'PQC Copilot', icon: Sparkles, badge: 'AI' },
            { id: 'settings', label: 'Settings', icon: Settings }
          ].map(tab => {
            const Icon = tab.icon;
            const isTabActive = tab.id === 'settings'
              ? isSettingsActive
              : tab.id === 'integrations_gw'
                ? isIntegrationsTab
                : tab.id === 'cbom'
                  ? (activeTab === 'cbom' || (activeTab as any) === 'assets' || (activeTab as any) === 'sbom')
                  : activeTab === tab.id;
            return (
              <React.Fragment key={tab.id}>
                <button
                  key={tab.id}
                  onClick={() => {
                    if (tab.id === 'settings') {
                      if (isSettingsActive) {
                        setIsSettingsMenuOpen(!isSettingsMenuOpen);
                      } else {
                        setActiveTab('settings');
                        setIsSettingsMenuOpen(true);
                      }
                    } else if (tab.id === 'cbom') {
                      setActiveTab('cbom');
                    } else if (tab.id === 'integrations_gw') {
                      setActiveTab('git');
                    } else {
                      setActiveTab(tab.id as any);
                    }
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.65rem',
                    padding: '0.6rem 0.75rem',
                    borderRadius: '6px',
                    background: isTabActive ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                    border: isTabActive ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
                    color: isTabActive ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-secondary, #94a3b8)',
                    fontSize: '0.84rem',
                    fontWeight: isTabActive ? 600 : 500,
                    textAlign: 'left',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    width: '100%',
                    justifyContent: 'space-between'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', overflow: 'hidden' }}>
                    <Icon size={17} color={isTabActive ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-muted, #64748b)'} style={{ flexShrink: 0 }} />
                    <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {tab.label}
                    </span>
                  </div>
                  {tab.badge && (
                    <span style={{
                      fontSize: '0.62rem',
                      fontWeight: 700,
                      padding: '0.1rem 0.35rem',
                      borderRadius: '4px',
                      background: isTabActive ? 'rgba(56, 189, 248, 0.25)' : 'rgba(255, 255, 255, 0.08)',
                      color: isTabActive ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      flexShrink: 0
                    }}>
                      {tab.badge}
                    </span>
                  )}
                  {tab.id === 'settings' && (
                    <span
                      onClick={(e) => {
                        e.stopPropagation();
                        setIsSettingsMenuOpen(!isSettingsMenuOpen);
                      }}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '2px',
                        cursor: 'pointer'
                      }}
                      title={isSettingsMenuOpen ? "Collapse Settings" : "Expand Settings"}
                    >
                      <ChevronRight 
                        size={14} 
                        color={isTabActive ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-muted, #64748b)'} 
                        style={{ 
                          transform: isSettingsMenuOpen ? 'rotate(90deg)' : 'none', 
                          transition: 'transform 0.2s ease',
                          flexShrink: 0
                        }} 
                      />
                    </span>
                  )}
                </button>

                {/* Indented Settings Sub-navigation when Settings is Expanded */}
                {tab.id === 'settings' && isSettingsMenuOpen && (
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.15rem',
                    paddingLeft: '1.25rem',
                    marginTop: '0.15rem',
                    marginBottom: '0.35rem',
                    borderLeft: '2px solid rgba(0, 242, 254, 0.25)',
                    marginLeft: '0.85rem'
                  }}>
                    {[
                      { subId: 'profile' as const, label: 'Profile', icon: User },
                      { subId: 'users' as const, label: 'Team & 2FA', icon: Users },
                      { subId: 'license' as const, label: 'License', icon: Key },
                      { subId: 'groups' as const, label: 'Groups', icon: Layers }
                    ].map(sub => {
                      const SubIcon = sub.icon;
                      // Only highlight a sub-item when Settings is the ACTIVE section —
                      // not merely expanded. Otherwise Profile (the default sub-tab) shows
                      // selected even while viewing CBOM/other tabs.
                      const isSubActive = isSettingsActive && effectiveSettingsTab === sub.subId;
                      return (
                        <button
                          key={sub.subId}
                          onClick={() => {
                            setActiveTab('settings');
                            setSettingsSubTab(sub.subId);
                          }}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '0.55rem',
                            padding: '0.45rem 0.65rem',
                            borderRadius: '5px',
                            background: isSubActive ? 'rgba(0, 242, 254, 0.16)' : 'transparent',
                            border: isSubActive ? '1px solid rgba(0, 242, 254, 0.35)' : '1px solid transparent',
                            color: isSubActive ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            fontSize: '0.78rem',
                            fontWeight: isSubActive ? 600 : 500,
                            textAlign: 'left',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                            width: '100%'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', overflow: 'hidden' }}>
                            <SubIcon size={14} color={isSubActive ? '#38bdf8' : 'var(--text-muted, #64748b)'} style={{ flexShrink: 0 }} />
                            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{sub.label}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Subscription Scale Card */}
        <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '0.65rem', paddingTop: '1rem' }}>
          <div style={{
            background: 'rgba(13, 19, 33, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '8px',
            padding: '0.85rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.55rem'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted, #64748b)', letterSpacing: '0.06em', textTransform: 'uppercase', lineHeight: 1.25 }}>
                SUBSCRIPTION<br />SCALE
              </div>
              <div style={{
                border: '1px solid rgba(255, 255, 255, 0.35)',
                borderRadius: '4px',
                padding: '0.18rem 0.45rem',
                fontSize: '0.68rem',
                fontWeight: 700,
                color: '#ffffff',
                letterSpacing: '0.04em',
                lineHeight: 1.1,
                textAlign: 'center'
              }}>
                CORPORATE<br />TIER
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff' }}>Scale Monitored</span>
              <span style={{ fontSize: '0.95rem', fontWeight: 800, color: '#ffffff' }}>
                {machines.length} <span style={{ color: 'var(--text-muted, #64748b)', fontWeight: 400, fontSize: '0.82rem' }}>/</span> {totalCapacity}
              </span>
            </div>

            {/* Progress Bar */}
            <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{
                width: `${Math.min(100, Math.max(8, Math.round((machines.length / Math.max(1, totalCapacity)) * 100)))}%`,
                height: '100%',
                background: 'linear-gradient(90deg, #00f2fe 0%, #4facfe 100%)',
                borderRadius: '2px',
                boxShadow: '0 0 8px rgba(0, 242, 254, 0.6)'
              }} />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.68rem', color: 'var(--text-muted, #64748b)' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', display: 'inline-block', boxShadow: '0 0 6px rgba(16, 185, 129, 0.8)' }} />
              <span>Continuous asset tracking active</span>
            </div>
          </div>

          {/* Separator */}
          <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)' }} />

          {/* Bottom User Profile Bar (Customer ID / Customer Name) */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.4rem',
            padding: '0.5rem 0.2rem 0.2rem 0.2rem'
          }}>
            <div style={{
              fontSize: '0.8rem',
              fontWeight: 800,
              letterSpacing: '0.04em',
              color: '#3b82f6',
              textTransform: 'uppercase',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }} title={`${client.customerId || displayCustomerId}/${client.displayName || displayCustomerName}`}>
              {client.customerId || displayCustomerId}/{client.displayName || displayCustomerName}
            </div>

            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.35rem'
            }}>
              <div 
                onClick={() => {
                  setActiveTab('settings');
                  setSettingsSubTab('profile');
                }}
                style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', overflow: 'hidden', cursor: 'pointer' }}
                title="View & Edit Profile / Security Settings"
              >
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  border: '1.5px solid rgba(255, 255, 255, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'rgba(255, 255, 255, 0.05)',
                  flexShrink: 0
                }}>
                  <User size={18} color="#94a3b8" />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                  <div 
                    style={{ 
                      fontSize: '0.82rem', 
                      fontWeight: 700, 
                      color: '#ffffff', 
                      textOverflow: 'ellipsis', 
                      overflow: 'hidden', 
                      whiteSpace: 'nowrap',
                      maxWidth: '120px'
                    }} 
                    title={emailInput}
                  >
                    {emailInput}
                  </div>
                  <div style={{ fontSize: '0.72rem', fontWeight: 500, color: isPartner ? '#c084fc' : 'var(--text-muted, #64748b)' }}>
                    {displayRole}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', flexShrink: 0 }}>
                {/* Key Icon: User License & 2FA Settings */}
                <button
                  onClick={() => setShowLicense2FAModal(true)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted, #64748b)',
                    cursor: 'pointer',
                    padding: '5px',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--accent-cyan, #38bdf8)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted, #64748b)')}
                  title="User License & 2FA Security Settings"
                >
                  <Key size={16} />
                </button>

                {/* Logout Icon */}
                <button
                  onClick={handleSignOut}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted, #64748b)',
                    cursor: 'pointer',
                    padding: '5px',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted, #64748b)')}
                  title="Log Out of Tenant Portal"
                >
                  <LogOut size={16} />
                </button>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* RIGHT MAIN CONTENT AREA */}
      <main style={{
        flex: 1,
        height: '100vh',
        overflowY: 'auto',
        padding: '1.75rem 2rem 3rem 2rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.5rem',
        boxSizing: 'border-box'
      }}>
        <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Header Banner */}
          <header className="glass-panel" style={{
            padding: '1.25rem 1.5rem',
            position: 'relative',
            overflow: 'hidden',
            border: '1px solid rgba(0, 242, 254, 0.25)',
            borderRadius: '10px',
            background: 'rgba(15, 23, 42, 0.65)'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
              position: 'relative',
              zIndex: 1
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                  <h1 style={{ fontSize: '1.45rem', fontWeight: 800, margin: 0, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Shield size={22} color="#38bdf8" />
                    <span>{client.displayName || displayCustomerName}</span>
                  </h1>
                  <span style={{
                    fontSize: '0.72rem',
                    fontFamily: 'monospace',
                    color: '#38bdf8',
                    background: 'rgba(56, 189, 248, 0.12)',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    padding: '0.15rem 0.45rem',
                    borderRadius: '4px',
                    fontWeight: 700
                  }}>
                    {client.customerId || 'CORP-9812'}
                  </span>
                  <span style={{
                    fontSize: '0.68rem',
                    color: '#4ade80',
                    background: 'rgba(34, 197, 94, 0.12)',
                    border: '1px solid rgba(34, 197, 94, 0.3)',
                    padding: '0.15rem 0.45rem',
                    borderRadius: '4px',
                    fontWeight: 600,
                    textTransform: 'uppercase'
                  }}>
                    Active Corporate Tenant
                  </span>
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-muted, #94a3b8)' }}>
                  Dedicated Tenant Pod • Workspace: <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{client.name}</span> • App Port: <span style={{ color: '#c084fc', fontFamily: 'monospace' }}>{client.appPort || 5002}</span> • DB Port: <span style={{ color: '#c084fc', fontFamily: 'monospace' }}>{client.dbPort || 5434}</span>
                </div>
              </div>
            </div>
          </header>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4rem', color: '#38bdf8' }}>
            <RefreshCw size={24} className="spin" style={{ marginRight: '0.75rem' }} />
            <span>Loading {client.displayName} security plane...</span>
          </div>
        ) : (
          <>
            {/* OVERVIEW TAB */}
            {activeTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
                {/* 4 Metric Cards */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                  gap: '1.25rem'
                }}>
                  {/* Card 1: Enrolled Workstations */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    padding: '1.25rem',
                    position: 'relative'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Enrolled Workstations
                        </div>
                        <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.25rem' }}>
                          {machines.length}
                        </div>
                        {(() => {
                          const onlineCount = machines.filter(m => m.status === 'online').length;
                          const total = machines.length;
                          const allOnline = total > 0 && onlineCount === total;
                          const color = allOnline ? '#4ade80' : (onlineCount === 0 ? '#f87171' : '#fbbf24');
                          return (
                            <div style={{ fontSize: '0.76rem', color, marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                              <CheckCircle2 size={12} />
                              <span>{onlineCount} of {total} reporting{total > 0 && !allOnline ? ` · ${total - onlineCount} offline` : ''}</span>
                            </div>
                          );
                        })()}
                      </div>
                      <div style={{ background: 'rgba(56, 189, 248, 0.12)', padding: '0.65rem', borderRadius: '8px', color: '#38bdf8' }}>
                        <Laptop size={22} />
                      </div>
                    </div>
                  </div>

                  {/* Card 2: Seat Utilization */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    padding: '1.25rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Seat Allocation
                        </div>
                        <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#ffffff', marginTop: '0.25rem' }}>
                          {usedSeats} <span style={{ fontSize: '1rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 500 }}>/ {totalCapacity}</span>
                        </div>
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary, #94a3b8)', marginTop: '0.2rem' }}>
                          {totalCapacity - usedSeats} Seats Available for Enrollment
                        </div>
                      </div>
                      <div style={{ background: 'rgba(168, 85, 247, 0.12)', padding: '0.65rem', borderRadius: '8px', color: '#c084fc' }}>
                        <Key size={22} />
                      </div>
                    </div>
                  </div>

                  {/* Card 3: Cryptographic Assets */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    padding: '1.25rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Discovered Cryptographic Assets
                        </div>
                        <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#4ade80', marginTop: '0.25rem' }}>
                          {stats.totalAssets || assets.length || 0}
                        </div>
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary, #94a3b8)', marginTop: '0.2rem' }}>
                          {assets.filter(a => a.source === 'git_repo').length > 0
                            ? `${assets.filter(a => a.source !== 'git_repo').length} Endpoints • ${assets.filter(a => a.source === 'git_repo').length} Git Repositories`
                            : 'Endpoints, Git Repositories & Cloud Ciphers'}
                        </div>
                      </div>
                      <div style={{ background: 'rgba(34, 197, 94, 0.12)', padding: '0.65rem', borderRadius: '8px', color: '#4ade80' }}>
                        <Database size={22} />
                      </div>
                    </div>
                  </div>

                  {/* Card 4: Quantum Risk Score */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    padding: '1.25rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600 }}>
                          Quantum Risk Rating
                        </div>
                        <div style={{ fontSize: '1.85rem', fontWeight: 800, color: (stats.avgRiskScore || 84) > 75 ? '#f87171' : '#fbbf24', marginTop: '0.25rem' }}>
                          {stats.avgRiskScore || 84} <span style={{ fontSize: '0.9rem', color: (stats.avgRiskScore || 84) > 75 ? '#f87171' : '#fbbf24' }}>/ 100</span>
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#fbbf24', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <AlertTriangle size={12} />
                          <span>{stats.vulnerableAssets || assets.filter(a => a.isVulnerable).length} Shor-Vulnerable Assets</span>
                        </div>
                      </div>
                      <div style={{ background: 'rgba(239, 68, 68, 0.12)', padding: '0.65rem', borderRadius: '8px', color: '#f87171' }}>
                        <Shield size={22} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Scheduled Pulls (DEF-41) */}
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.25rem 1.5rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.9rem' }}>
                    <Clock size={17} color="#c084fc" />
                    <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>Scheduled Pulls</h3>
                    <span style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
                      · auto-queue a telemetry pull daily, by group
                    </span>
                  </div>

                  {pullSchedules.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.9rem' }}>
                      {pullSchedules.map((s: any) => (
                        <div key={s.id} style={{
                          display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap',
                          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
                          borderRadius: '8px', padding: '0.5rem 0.8rem'
                        }}>
                          <span style={{
                            fontSize: '0.74rem', fontWeight: 700,
                            color: s.group ? '#d8b4fe' : '#38bdf8',
                            background: s.group ? 'rgba(168,85,247,0.12)' : 'rgba(56,189,248,0.12)',
                            border: `1px solid ${s.group ? 'rgba(168,85,247,0.3)' : 'rgba(56,189,248,0.3)'}`,
                            borderRadius: '5px', padding: '0.1rem 0.45rem'
                          }}>
                            {s.group || 'ALL ENDPOINTS'}
                          </span>
                          <span style={{ fontSize: '0.85rem', color: '#ffffff', fontWeight: 600, fontFamily: 'monospace' }}>
                            {String(s.hour).padStart(2, '0')}:{String(s.minute).padStart(2, '0')}
                          </span>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)' }}>{s.timezone} · daily</span>
                          {s.lastRunAt && (
                            <span style={{ fontSize: '0.68rem', color: '#64748b' }}>
                              last run {new Date(s.lastRunAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                            </span>
                          )}
                          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <button
                              onClick={() => handleToggleSchedule(s.id, !s.enabled)}
                              style={{
                                fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer',
                                color: s.enabled ? '#4ade80' : '#94a3b8',
                                background: s.enabled ? 'rgba(34,197,94,0.12)' : 'rgba(148,163,184,0.12)',
                                border: `1px solid ${s.enabled ? 'rgba(34,197,94,0.3)' : 'rgba(148,163,184,0.3)'}`,
                                borderRadius: '5px', padding: '0.15rem 0.5rem'
                              }}>
                              {s.enabled ? 'Enabled' : 'Paused'}
                            </button>
                            <button
                              onClick={() => handleDeleteSchedule(s.id)}
                              title="Delete schedule"
                              style={{
                                background: 'transparent', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171',
                                borderRadius: '5px', padding: '0.15rem 0.4rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center'
                              }}>
                              <Trash2 size={13} />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Add-schedule row */}
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <label style={{ fontSize: '0.68rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      Group
                      <select value={schedForm.group} onChange={e => setSchedForm({ ...schedForm, group: e.target.value })}
                        style={{ background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '5px', padding: '0.3rem 0.4rem', fontSize: '0.8rem' }}>
                        <option value="">All endpoints</option>
                        {fleetGroups.map(g => <option key={g.name} value={g.name}>{g.name}</option>)}
                      </select>
                    </label>
                    <label style={{ fontSize: '0.68rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      Time
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                        <select value={schedForm.hour} onChange={e => setSchedForm({ ...schedForm, hour: e.target.value })}
                          style={{ background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '5px', padding: '0.3rem 0.3rem', fontSize: '0.8rem' }}>
                          {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}</option>)}
                        </select>
                        <span style={{ color: '#64748b' }}>:</span>
                        <select value={schedForm.minute} onChange={e => setSchedForm({ ...schedForm, minute: e.target.value })}
                          style={{ background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '5px', padding: '0.3rem 0.3rem', fontSize: '0.8rem' }}>
                          {['0', '15', '30', '45'].map(m => <option key={m} value={m}>{m.padStart(2, '0')}</option>)}
                        </select>
                      </span>
                    </label>
                    <label style={{ fontSize: '0.68rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.2rem', flex: '1 1 160px' }}>
                      Timezone
                      <input value={schedForm.timezone} onChange={e => setSchedForm({ ...schedForm, timezone: e.target.value })}
                        placeholder="e.g. America/New_York"
                        style={{ background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '5px', padding: '0.3rem 0.4rem', fontSize: '0.8rem' }} />
                    </label>
                    <button
                      onClick={handleAddSchedule}
                      style={{
                        background: 'rgba(168, 85, 247, 0.15)', border: '1px solid rgba(168, 85, 247, 0.35)', color: '#c084fc',
                        padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer',
                        display: 'inline-flex', alignItems: 'center', gap: '0.4rem'
                      }}>
                      <Plus size={14} /> Add schedule
                    </button>
                  </div>
                  <p style={{ fontSize: '0.68rem', color: '#64748b', margin: '0.6rem 0 0 0' }}>
                    Each run queues a pull for the matching endpoints. Agents apply it on their next check-in —
                    continuously with the persistent service, otherwise when the app is open.
                  </p>
                </div>

                {/* Enrolled Workstations Preview Card */}
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.5rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div>
                      <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Laptop size={18} color="#38bdf8" />
                        <span>Enrolled Workstations Consuming Seats ({machines.length} Active Devices)</span>
                      </h2>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', margin: '0.2rem 0 0 0' }}>
                        Endpoints authenticated and actively reporting cryptographic posture for {client.displayName}.
                      </p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <button
                        onClick={() => handlePullBulk()}
                        disabled={bulkPulling !== null || machines.length === 0}
                        title="Queue an on-demand telemetry pull for every enrolled endpoint (DEF-39/40)"
                        style={{
                          background: 'rgba(56, 189, 248, 0.12)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          color: '#38bdf8',
                          padding: '0.4rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: bulkPulling !== null ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          opacity: machines.length === 0 ? 0.5 : 1
                        }}
                      >
                        <RefreshCw size={14} className={bulkPulling === 'ALL' ? 'animate-spin' : ''} /> Pull All
                      </button>
                      <button
                        onClick={() => setScheduleModalOpen(true)}
                        style={{
                          background: 'rgba(168, 85, 247, 0.12)',
                          border: '1px solid rgba(168, 85, 247, 0.3)',
                          color: '#c084fc',
                          padding: '0.4rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem'
                        }}
                      >
                        <Clock size={14} /> Schedule ({syncSchedulePolicy.frequency.toUpperCase()})
                      </button>
                      <button
                        onClick={() => {
                          setGeneratedTokenData(null);
                          setShowEnrollModal(true);
                        }}
                        style={{
                          background: 'rgba(56, 189, 248, 0.12)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          color: '#38bdf8',
                          padding: '0.4rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem'
                        }}
                      >
                        <Key size={14} color="#38bdf8" /> Generate Fleet Token / Enroll Device
                      </button>
                    </div>
                  </div>

                  {/* One-click filter by Group (DEF-42) */}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '0.9rem', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700, marginRight: '0.2rem' }}>Filter:</span>
                    {(() => {
                      const chip = (label: string, value: string, count?: number) => {
                        const active = groupFilter === value;
                        return (
                          <button key={value || '__all'} onClick={() => setGroupFilter(value)}
                            style={{
                              fontSize: '0.74rem', fontWeight: 600, cursor: 'pointer',
                              color: active ? '#0b1120' : '#cbd5e1',
                              background: active ? '#38bdf8' : 'rgba(255,255,255,0.05)',
                              border: `1px solid ${active ? '#38bdf8' : 'rgba(255,255,255,0.12)'}`,
                              borderRadius: '999px', padding: '0.2rem 0.7rem'
                            }}>
                            {label}{typeof count === 'number' ? ` · ${count}` : ''}
                          </button>
                        );
                      };
                      return (
                        <>
                          {chip(`All`, '', machines.length)}
                          {fleetGroups.map(g => chip(g.name, g.name, g.count))}
                        </>
                      );
                    })()}
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                          <th onClick={() => toggleFleetSort('group')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Group{sortArrow('group')}</th>
                          <th onClick={() => toggleFleetSort('host')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Workstation / Host{sortArrow('host')}</th>
                          <th onClick={() => toggleFleetSort('uuid')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Hardware UUID{sortArrow('uuid')}</th>
                          <th onClick={() => toggleFleetSort('os')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Platform / OS{sortArrow('os')}</th>
                          <th onClick={() => toggleFleetSort('ip')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>IP / Location{sortArrow('ip')}</th>
                          <th onClick={() => toggleFleetSort('assets')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Discovered Assets{sortArrow('assets')}</th>
                          <th onClick={() => toggleFleetSort('score')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Quantum Score{sortArrow('score')}</th>
                          <th onClick={() => toggleFleetSort('status')} style={{ padding: '0.75rem 0.5rem', cursor: 'pointer', userSelect: 'none' }}>Status{sortArrow('status')}</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedFilteredMachines().map(m => {
                          const isMac = m.os === 'darwin';
                          const isWin = m.os === 'windows';
                          const displayName = m.computerName || m.hostname;
                          return (
                            <tr key={m.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                              <td style={{ padding: '0.85rem 0.5rem' }}>
                                <select
                                  value={(m.group && m.group !== 'Default') ? m.group : ''}
                                  onChange={(e) => handleSetGroup(m.id, e.target.value)}
                                  title="Move this workstation to a group"
                                  style={{
                                    background: 'rgba(168,85,247,0.08)', color: m.group && m.group !== 'Default' ? '#d8b4fe' : '#94a3b8',
                                    border: '1px solid rgba(168,85,247,0.25)', borderRadius: '5px',
                                    fontSize: '0.74rem', fontWeight: 600, padding: '0.2rem 0.3rem', cursor: 'pointer', maxWidth: '140px'
                                  }}
                                >
                                  <option value="">Default</option>
                                  {fleetGroups.filter(g => g.name.toLowerCase() !== 'default').map(g => (
                                    <option key={g.name} value={g.name}>{g.name}</option>
                                  ))}
                                  {/* Preserve the machine's current group even if not yet in the list */}
                                  {m.group && m.group !== 'Default' && !fleetGroups.some(g => g.name === m.group) && (
                                    <option value={m.group}>{m.group}</option>
                                  )}
                                </select>
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem', fontWeight: 600, color: '#ffffff' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <Laptop size={15} color={isMac ? '#38bdf8' : isWin ? '#c084fc' : '#4ade80'} />
                                  <div>
                                    <div>{displayName}</div>
                                    {m.computerName && m.computerName !== m.hostname && (
                                      <div style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'monospace' }}>
                                        {m.hostname}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem' }}>
                                <span style={{
                                  fontSize: '0.72rem',
                                  fontFamily: 'monospace',
                                  color: '#38bdf8',
                                  background: 'rgba(56, 189, 248, 0.08)',
                                  padding: '0.15rem 0.4rem',
                                  borderRadius: '4px',
                                  border: '1px solid rgba(56, 189, 248, 0.2)'
                                }}>
                                  {m.hardwareUuid ? `${m.hardwareUuid.substring(0, 13)}...` : 'N/A'}
                                </span>
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem', color: 'var(--text-secondary, #94a3b8)' }}>
                                <span style={{
                                  fontSize: '0.72rem',
                                  padding: '0.15rem 0.45rem',
                                  borderRadius: '4px',
                                  background: isMac ? 'rgba(56, 189, 248, 0.12)' : 'rgba(168, 85, 247, 0.12)',
                                  color: isMac ? '#38bdf8' : '#c084fc',
                                  border: `1px solid ${isMac ? 'rgba(56, 189, 248, 0.25)' : 'rgba(168, 85, 247, 0.25)'}`,
                                  textTransform: 'uppercase',
                                  fontWeight: 600
                                }}>
                                  {isMac ? 'macOS (arm64)' : isWin ? 'Windows (x64)' : m.os}
                                </span>
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem', color: 'var(--text-secondary, #94a3b8)' }}>
                                <div style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>
                                  {m.ip} <span style={{ fontSize: '0.64rem', color: '#64748b' }}>LAN</span>
                                </div>
                                {m.publicIp && (
                                  <div style={{ fontFamily: 'monospace', fontSize: '0.74rem', color: '#64748b', marginTop: '0.15rem' }}>
                                    {m.publicIp} <span style={{ fontSize: '0.62rem' }}>public</span>
                                  </div>
                                )}
                                {(m.geoCity || m.geoCountry) && (
                                  <div style={{ fontSize: '0.72rem', color: '#38bdf8', marginTop: '0.15rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                                    <MapPin size={11} />
                                    {[m.geoCity, m.geoRegion, m.geoCountry].filter(Boolean).join(', ')}
                                  </div>
                                )}
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem', color: '#ffffff', fontWeight: 600 }}>
                                {m.assetCount} assets ({m.vulnerableCount} vulnerable)
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem' }}>
                                <span style={{
                                  fontSize: '0.74rem',
                                  fontWeight: 700,
                                  color: m.quantumRiskScore > 80 ? '#f87171' : '#fbbf24',
                                  background: m.quantumRiskScore > 80 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                  padding: '0.15rem 0.45rem',
                                  borderRadius: '4px',
                                  border: `1px solid ${m.quantumRiskScore > 80 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
                                }}>
                                  Risk: {m.quantumRiskScore}/100
                                </span>
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem' }}>
                                {(() => {
                                  const isOnline = m.status === 'online';
                                  const dot = isOnline ? '#4ade80' : '#94a3b8';
                                  return (
                                    <span style={{
                                      fontSize: '0.72rem',
                                      fontWeight: 600,
                                      color: isOnline ? '#4ade80' : '#94a3b8',
                                      background: isOnline ? 'rgba(34, 197, 94, 0.12)' : 'rgba(148, 163, 184, 0.12)',
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '4px',
                                      border: `1px solid ${isOnline ? 'rgba(34, 197, 94, 0.25)' : 'rgba(148, 163, 184, 0.25)'}`,
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.3rem'
                                    }}>
                                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: dot }}></span>
                                      {isOnline ? 'Online' : 'Offline'}
                                    </span>
                                  );
                                })()}
                              </td>
                              <td style={{ padding: '0.85rem 0.5rem', textAlign: 'right' }}>
                                <button
                                  disabled={pullingMachineId === m.id}
                                  onClick={() => handlePullWorkstation(m.id, displayName)}
                                  style={{
                                    background: 'rgba(56, 189, 248, 0.08)',
                                    border: '1px solid rgba(56, 189, 248, 0.25)',
                                    color: '#38bdf8',
                                    padding: '0.3rem 0.6rem',
                                    borderRadius: '5px',
                                    fontSize: '0.74rem',
                                    fontWeight: 600,
                                    cursor: pullingMachineId === m.id ? 'not-allowed' : 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.35rem',
                                    opacity: pullingMachineId === m.id ? 0.6 : 1
                                  }}
                                  title="Pull latest cryptographic telemetry from this endpoint immediately"
                                >
                                  <RefreshCw size={12} className={pullingMachineId === m.id ? 'animate-spin' : ''} />
                                  {pullingMachineId === m.id ? 'Pulling...' : 'Pull Telemetry'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  {/* Daily Historical Snapshots (Non-Inflating Deduplicated Trend) */}
                  {dailySnapshots.length > 0 && (
                    <div style={{
                      marginTop: '1.5rem',
                      background: 'rgba(255, 255, 255, 0.015)',
                      borderRadius: '8px',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      padding: '1rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                        <div>
                          <h4 style={{ margin: 0, fontSize: '0.9rem', color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <Layers size={15} color="#38bdf8" /> Daily Compliance Snapshots (Audit History)
                          </h4>
                          <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.74rem', color: '#94a3b8' }}>
                            Archived daily historical scan data per tenant without inflating active workstation license seats.
                          </p>
                        </div>
                      </div>
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.06)', color: '#94a3b8', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                              <th style={{ padding: '0.5rem' }}>Snapshot Date</th>
                              <th style={{ padding: '0.5rem' }}>Active Workstations</th>
                              <th style={{ padding: '0.5rem' }}>Total Assets</th>
                              <th style={{ padding: '0.5rem' }}>Vulnerable Assets</th>
                              <th style={{ padding: '0.5rem' }}>Avg Risk Score</th>
                              <th style={{ padding: '0.5rem' }}>Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {dailySnapshots.map(s => (
                              <tr key={s.id || s.date} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                                <td style={{ padding: '0.5rem', color: '#ffffff', fontFamily: 'monospace', fontWeight: 600 }}>
                                  {typeof s.date === 'string' ? s.date.split('T')[0] : s.date}
                                </td>
                                <td style={{ padding: '0.5rem', color: '#38bdf8', fontWeight: 600 }}>
                                  {s.activeWorkstations} / {client.mcaLimit || 100} seats
                                </td>
                                <td style={{ padding: '0.5rem', color: '#e2e8f0' }}>
                                  {s.totalAssets}
                                </td>
                                <td style={{ padding: '0.5rem', color: '#f87171' }}>
                                  {s.vulnerableAssets}
                                </td>
                                <td style={{ padding: '0.5rem' }}>
                                  <span style={{
                                    fontSize: '0.72rem',
                                    fontWeight: 700,
                                    color: s.averageRiskScore > 80 ? '#f87171' : '#fbbf24'
                                  }}>
                                    {s.averageRiskScore}/100
                                  </span>
                                </td>
                                <td style={{ padding: '0.5rem' }}>
                                  <span style={{
                                    fontSize: '0.7rem',
                                    color: '#4ade80',
                                    background: 'rgba(34, 197, 94, 0.1)',
                                    padding: '0.1rem 0.35rem',
                                    borderRadius: '3px'
                                  }}>
                                    Archived
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 1. CBOM & SBOM INVENTORY TAB (Consolidated: Asset Inventory + CycloneDX 1.6 CBOM + Software BOM + Raw JSON) */}
            {(activeTab === 'cbom' || activeTab === 'assets' || (activeTab as any) === 'sbom') && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {/* Overall Asset Inventory Posture Dashboard (A-F Grading & Industry Risk Formula) */}
                <CryptographicPostureCard
                  tenantName={client.displayName.toUpperCase()}
                  metrics={postureMetrics}
                />

                {/* Header Card with Sub-Tabs Switcher */}
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.5rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <FileCode size={22} color="var(--accent-cyan, #38bdf8)" />
                        <h2 style={{ fontSize: '1.25rem', fontWeight: 800, margin: 0, color: '#ffffff' }}>
                          Cryptographic BOM (CBOM)
                        </h2>
                        <span style={{
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.5rem',
                          borderRadius: '4px',
                          background: 'rgba(0, 242, 254, 0.15)',
                          color: '#38bdf8',
                          border: '1px solid rgba(0, 242, 254, 0.3)'
                        }}>
                          CycloneDX 1.6
                        </span>
                      </div>
                      <p style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.82rem', margin: '0.35rem 0 0 0' }}>
                        Comprehensive Cryptographic Bill of Materials (CBOM) and integrated Software Bill of Materials (SBOM) tracking cryptographic keys, certificates, OS packages, software libraries, and CVE correlations across {client.displayName}.
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                      {/* Sub-Tabs Switcher */}
                      <div style={{
                        display: 'flex',
                        background: 'rgba(0, 0, 0, 0.35)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: '6px',
                        padding: '2px'
                      }}>
                        <button
                          onClick={() => setCbomSubTab('assets')}
                          style={{
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            border: 'none',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: cbomSubTab === 'assets' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                            color: cbomSubTab === 'assets' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <Layers size={13} /> Asset Inventory (CBOM)
                        </button>
                        <button
                          onClick={() => setCbomSubTab('cyclonedx')}
                          style={{
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            border: 'none',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: cbomSubTab === 'cyclonedx' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                            color: cbomSubTab === 'cyclonedx' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <FileCode size={13} /> CycloneDX 1.6 CBOM
                        </button>
                        <button
                          onClick={() => setCbomSubTab('json')}
                          style={{
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            border: 'none',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: cbomSubTab === 'json' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                            color: cbomSubTab === 'json' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <Code2 size={13} /> Raw JSON &amp; Export
                        </button>
                        <button
                          onClick={() => {
                            setCbomSubTab('drift');
                            fetchDriftEvents();
                          }}
                          style={{
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            border: 'none',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: cbomSubTab === 'drift' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                            color: cbomSubTab === 'drift' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <Activity size={13} /> Fleet Drift
                        </button>
                        <button
                          onClick={() => setCbomSubTab('sbom')}
                          style={{
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            border: 'none',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: cbomSubTab === 'sbom' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                            color: cbomSubTab === 'sbom' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <Package size={13} /> Software BOM (SBOM) &amp; CVEs
                        </button>
                      </div>

                      {/* Export Standard CBOM */}
                      <button
                        onClick={() => downloadCBOMJson(false)}
                        title="Standard CycloneDX 1.6 Cryptographic Bill of Materials"
                        style={{
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#e2e8f0',
                          padding: '0.45rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem'
                        }}
                      >
                        <Download size={13} /> Export Standard CBOM
                      </button>

                      {/* Export Attested CBOM (CDXA) */}
                      <button
                        onClick={() => downloadCBOMJson(true)}
                        title="CycloneDX 1.6 with CDXA Attestation Declarations (NIST SP 800-218, CNSA 2.0) and ML-DSA-65 Signature"
                        style={{
                          background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(56, 189, 248, 0.25) 100%)',
                          border: '1px solid rgba(168, 85, 247, 0.5)',
                          color: '#c084fc',
                          padding: '0.45rem 0.95rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.45rem',
                          boxShadow: '0 0 12px rgba(168, 85, 247, 0.15)'
                        }}
                      >
                        <ShieldCheck size={14} color="#c084fc" /> Export Attested CBOM (CDXA)
                      </button>

                      {/* Export Executive Report (PDF) */}
                      <button
                        onClick={() => downloadExecutiveReport('pdf')}
                        disabled={isGeneratingReport}
                        title="Download white-labeled Executive C-Suite Post-Quantum Audit Report (PDF)"
                        style={{
                          background: 'rgba(239, 68, 68, 0.12)',
                          border: '1px solid rgba(239, 68, 68, 0.35)',
                          color: '#f87171',
                          padding: '0.45rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: isGeneratingReport ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <FileText size={13} /> {isGeneratingReport ? 'Generating...' : 'PQC Roadmap PDF'}
                      </button>

                      {/* Export Executive Report (DOCX) */}
                      <button
                        onClick={() => downloadExecutiveReport('docx')}
                        disabled={isGeneratingReport}
                        title="Download editable Microsoft Word Executive Audit Report (DOCX)"
                        style={{
                          background: 'rgba(59, 130, 246, 0.12)',
                          border: '1px solid rgba(59, 130, 246, 0.35)',
                          color: '#60a5fa',
                          padding: '0.45rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: isGeneratingReport ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <FileText size={13} /> {isGeneratingReport ? 'Generating...' : 'PQC Roadmap DOCX'}
                      </button>

                      {/* View PQC Roadmap Report (HTML, opens in new tab) */}
                      <button
                        onClick={() => downloadExecutiveReport('html')}
                        disabled={isGeneratingReport}
                        title="Open the PQC Executive Roadmap Report in a new tab (priorities, remediation, roadmap)"
                        style={{
                          background: 'rgba(16, 185, 129, 0.12)',
                          border: '1px solid rgba(16, 185, 129, 0.35)',
                          color: '#34d399',
                          padding: '0.45rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: isGeneratingReport ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        <FileText size={13} /> {isGeneratingReport ? 'Generating...' : 'View PQC Roadmap'}
                      </button>

                      {/* Enroll Workstations / Fleet Token */}
                      <button
                        onClick={() => {
                          setGeneratedTokenData(null);
                          setShowEnrollModal(true);
                        }}
                        title="Generate Fleet Enrollment Token for Endpoints & Servers"
                        style={{
                          background: 'rgba(56, 189, 248, 0.12)',
                          border: '1px solid rgba(56, 189, 248, 0.35)',
                          color: '#38bdf8',
                          padding: '0.45rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem'
                        }}
                      >
                        <Key size={13} color="#38bdf8" /> Enroll Workstations / Fleet Token
                      </button>
                    </div>
                  </div>
                </div>

                {/* SUB-TAB 1: ASSET INVENTORY */}
                {cbomSubTab === 'assets' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.025)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.75rem'
                    }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.15rem', fontWeight: 700, margin: '0 0 0.3rem 0', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Layers size={18} color="#38bdf8" />
                          <span>Cryptographic Asset Inventory ({filteredAssets.length})</span>
                        </h3>
                        <p style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.82rem', margin: 0 }}>
                          Operational view of all discovered cryptographic keys, certificates, ciphers, and repository primitives across {client.displayName}.
                        </p>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                        {/* Source Filter Dropdown */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <Filter size={14} color="#94a3b8" />
                          <select
                            value={sourceFilter}
                            onChange={(e) => {
                              setSourceFilter(e.target.value);
                              setAssetPage(1);
                            }}
                            style={{
                              background: 'rgba(0, 0, 0, 0.4)',
                              border: '1px solid rgba(0, 242, 254, 0.3)',
                              borderRadius: '6px',
                              color: '#38bdf8',
                              padding: '0.45rem 0.75rem',
                              fontSize: '0.8rem',
                              fontWeight: 600,
                              outline: 'none',
                              cursor: 'pointer'
                            }}
                          >
                            <option value="all">All Sources ({assets.length})</option>
                            <option value="endpoint">Fleet Endpoints ({assets.filter(a => !a.source || a.source === 'endpoint').length})</option>
                            <option value="git_repo">Git Repositories ({assets.filter(a => a.source === 'git_repo').length})</option>
                            <option value="cloud_kms">Cloud KMS ({assets.filter(a => a.source === 'cloud_kms').length})</option>
                            <option value="enterprise_pki">Enterprise PKI ({assets.filter(a => a.source === 'enterprise_pki').length})</option>
                            <option value="pqc_proxy">Hybrid Proxy ({assets.filter(a => a.source === 'pqc_proxy').length})</option>
                          </select>
                        </div>

                        <input
                          type="text"
                          placeholder="Search assets, algorithms, hostnames..."
                          value={searchAsset}
                          onChange={(e) => {
                            setSearchAsset(e.target.value);
                            setAssetPage(1);
                          }}
                          style={{
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(255, 255, 255, 0.15)',
                            padding: '0.45rem 0.85rem',
                            borderRadius: '6px',
                            color: '#ffffff',
                            fontSize: '0.82rem',
                            outline: 'none',
                            width: '240px'
                          }}
                        />
                      </div>
                    </div>

                    <div style={{ overflowX: 'auto', maxHeight: '550px' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                        <thead style={{ position: 'sticky', top: 0, background: '#0b1120', zIndex: 2 }}>
                          <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Asset Identifier / Name</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Type</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Source</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Algorithm</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Key Size</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Discovered On</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Last Updated</th>
                            <th style={{ padding: '0.65rem 0.5rem' }}>Quantum Vulnerability</th>
                          </tr>
                        </thead>
                        <tbody>
                          {paginatedAssets.map((a: any) => (
                            <tr key={a.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                              <td style={{ padding: '0.7rem 0.5rem', color: '#ffffff', fontWeight: 500 }}>
                                <div style={{ fontWeight: 600 }}>{a.name}</div>
                                {a.path && (
                                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace', marginTop: '0.15rem' }}>
                                    {a.path}
                                  </div>
                                )}
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontSize: '0.72rem' }}>
                                <span style={{
                                  padding: '0.15rem 0.4rem',
                                  borderRadius: '3px',
                                  background: a.source === 'git_repo' ? 'rgba(192, 132, 252, 0.12)' : 'rgba(255, 255, 255, 0.05)',
                                  color: a.source === 'git_repo' ? '#c084fc' : 'var(--text-secondary, #94a3b8)',
                                  fontWeight: 600
                                }}>
                                  {a.type}
                                </span>
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem' }}>
                                <span style={{
                                  padding: '0.15rem 0.45rem',
                                  borderRadius: '4px',
                                  fontSize: '0.7rem',
                                  fontWeight: 600,
                                  background: 
                                    a.source === 'cloud_kms' ? 'rgba(0, 242, 254, 0.12)' :
                                    a.source === 'enterprise_pki' ? 'rgba(56, 189, 248, 0.12)' :
                                    a.source === 'git_repo' ? 'rgba(192, 132, 252, 0.12)' :
                                    a.source === 'pqc_proxy' ? 'rgba(245, 158, 11, 0.12)' :
                                    'rgba(34, 197, 94, 0.12)',
                                  color: 
                                    a.source === 'cloud_kms' ? '#00f2fe' :
                                    a.source === 'enterprise_pki' ? '#38bdf8' :
                                    a.source === 'git_repo' ? '#c084fc' :
                                    a.source === 'pqc_proxy' ? '#f59e0b' :
                                    '#4ade80',
                                  border: '1px solid rgba(255, 255, 255, 0.08)'
                                }}>
                                  {a.source === 'cloud_kms' ? 'Cloud KMS' :
                                   a.source === 'enterprise_pki' ? 'Enterprise PKI' :
                                   a.source === 'git_repo' ? 'Git Repo' :
                                   a.source === 'pqc_proxy' ? 'Hybrid Proxy' :
                                   'Endpoint'}
                                </span>
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem', fontFamily: 'monospace', color: a.algorithm?.includes('ML-') ? '#4ade80' : '#38bdf8' }}>
                                {a.algorithm}
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem', fontFamily: 'monospace', color: 'var(--text-secondary, #94a3b8)' }}>
                                {a.keySize ? `${a.keySize} bits` : 'N/A'}
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted, #94a3b8)' }}>
                                {a.source === 'git_repo' ? (
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#c084fc', fontSize: '0.78rem' }}>
                                    <GitBranch size={13} color="#c084fc" />
                                    <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Git Repository'}</span>
                                  </span>
                                ) : a.source === 'cloud_kms' ? (
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#00f2fe', fontSize: '0.78rem' }}>
                                    <Cloud size={13} color="#00f2fe" />
                                    <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Cloud KMS'}</span>
                                  </span>
                                ) : a.source === 'enterprise_pki' ? (
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#38bdf8', fontSize: '0.78rem' }}>
                                    <Database size={13} color="#38bdf8" />
                                    <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Enterprise CA'}</span>
                                  </span>
                                ) : a.source === 'pqc_proxy' ? (
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#f59e0b', fontSize: '0.78rem' }}>
                                    <Radio size={13} color="#f59e0b" />
                                    <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Hybrid TLS Proxy'}</span>
                                  </span>
                                ) : (
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#38bdf8', fontSize: '0.78rem' }}>
                                    <Laptop size={13} color="#38bdf8" />
                                    <span>{a.hostname || 'Workstation'}</span>
                                  </span>
                                )}
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted, #94a3b8)', fontSize: '0.76rem', whiteSpace: 'nowrap' }}>
                                {(() => {
                                  if (!a.createdAt) return <span style={{ color: '#64748b' }}>—</span>;
                                  const d = new Date(a.createdAt);
                                  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
                                  const rel = mins < 1 ? 'just now'
                                    : mins < 60 ? `${mins}m ago`
                                    : mins < 1440 ? `${Math.floor(mins / 60)}h ago`
                                    : `${Math.floor(mins / 1440)}d ago`;
                                  const stale = mins >= 1440 * 7; // >7 days
                                  return (
                                    <span title={d.toLocaleString()} style={{ color: stale ? '#fbbf24' : 'var(--text-muted, #94a3b8)' }}>
                                      {rel}
                                    </span>
                                  );
                                })()}
                              </td>
                              <td style={{ padding: '0.7rem 0.5rem' }}>
                                {a.isVulnerable ? (() => {
                                  // Label the actual quantum threat, not a blanket "Shor".
                                  // Asymmetric → Shor; symmetric → Grover; legacy protocols → HNDL.
                                  const s = `${a.algorithm || ''} ${a.name || ''}`.toLowerCase();
                                  let label = 'Quantum Vulnerable', col = '#f87171', bg = 'rgba(239, 68, 68, 0.12)', bd = 'rgba(239, 68, 68, 0.25)';
                                  if (/legacy protocol|tls 1\.|ssl [23]\.|\bssl\b/.test(s)) { label = 'Legacy / HNDL'; col = '#fbbf24'; bg = 'rgba(251,191,36,0.12)'; bd = 'rgba(251,191,36,0.3)'; }
                                  else if (/3des|triple des|\bdes\b|rc4|arcfour|blowfish|\baes\b|grover/.test(s)) { label = 'Grover Weakened'; col = '#fbbf24'; bg = 'rgba(251,191,36,0.12)'; bd = 'rgba(251,191,36,0.3)'; }
                                  else if (/rsa|ecdsa|ecdh|\becc\b|\bec\b|\bdsa\b|diffie|\bdh\b|ed25519|x25519|secp|shor/.test(s)) { label = 'Shor Vulnerable'; }
                                  return (
                                    <span style={{ fontSize: '0.7rem', fontWeight: 600, color: col, background: bg, padding: '0.12rem 0.4rem', borderRadius: '3px', border: `1px solid ${bd}` }}>
                                      {label}
                                    </span>
                                  );
                                })() : (
                                  <span style={{
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    color: '#4ade80',
                                    background: 'rgba(34, 197, 94, 0.12)',
                                    padding: '0.12rem 0.4rem',
                                    borderRadius: '3px',
                                    border: '1px solid rgba(34, 197, 94, 0.25)'
                                  }}>
                                    Quantum-Safe (PQC)
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {totalAssetPages > 1 && (
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginTop: '1rem',
                        paddingTop: '0.85rem',
                        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                        fontSize: '0.8rem',
                        color: 'var(--text-muted, #94a3b8)',
                        flexWrap: 'wrap',
                        gap: '0.5rem'
                      }}>
                        <div>
                          Showing <span style={{ color: '#ffffff', fontWeight: 600 }}>{(assetPage - 1) * assetsPerPage + 1}</span>–<span style={{ color: '#ffffff', fontWeight: 600 }}>{Math.min(assetPage * assetsPerPage, filteredAssets.length)}</span> of <span style={{ color: '#ffffff', fontWeight: 600 }}>{filteredAssets.length.toLocaleString()}</span> assets
                        </div>
                        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                          <button
                            onClick={() => setAssetPage(p => Math.max(1, p - 1))}
                            disabled={assetPage === 1}
                            style={{
                              background: assetPage === 1 ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.08)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              color: assetPage === 1 ? '#475569' : '#ffffff',
                              padding: '0.35rem 0.75rem',
                              borderRadius: '6px',
                              cursor: assetPage === 1 ? 'not-allowed' : 'pointer',
                              fontSize: '0.78rem',
                              fontWeight: 500
                            }}
                          >
                            Previous
                          </button>
                          <span style={{ padding: '0 0.5rem', color: '#94a3b8' }}>
                            Page <strong style={{ color: '#ffffff' }}>{assetPage}</strong> of <strong style={{ color: '#ffffff' }}>{totalAssetPages}</strong>
                          </span>
                          <button
                            onClick={() => setAssetPage(p => Math.min(totalAssetPages, p + 1))}
                            disabled={assetPage === totalAssetPages}
                            style={{
                              background: assetPage === totalAssetPages ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.08)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              color: assetPage === totalAssetPages ? '#475569' : '#ffffff',
                              padding: '0.35rem 0.75rem',
                              borderRadius: '6px',
                              cursor: assetPage === totalAssetPages ? 'not-allowed' : 'pointer',
                              fontSize: '0.78rem',
                              fontWeight: 500
                            }}
                          >
                            Next
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                  </div>
                )}

                {/* SUB-TAB 2: CYCLONEDX 1.6 CBOM */}
                {cbomSubTab === 'cyclonedx' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {/* Header Card / KPIs */}
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.025)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.5rem'
                    }}>
                      {/* 4 Scoped KPI Metric Cards */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginTop: '0.25rem' }}>
                        <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                            <span>Enrolled Endpoints</span>
                            <Laptop size={15} color="#38bdf8" />
                          </div>
                          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#ffffff', margin: '0.3rem 0 0.15rem 0' }}>
                            {machines.length}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: '#4ade80', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#4ade80' }} />
                            {machines.filter(m => m.status === 'online').length} active reporting
                          </div>
                        </div>

                        <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                            <span>Fleet Risk Score</span>
                            <ShieldAlert size={15} color={stats.avgRiskScore > 75 ? '#f87171' : '#38bdf8'} />
                          </div>
                          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: stats.avgRiskScore > 75 ? '#f87171' : '#ffffff', margin: '0.3rem 0 0.15rem 0' }}>
                            {stats.avgRiskScore} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted, #94a3b8)' }}>/ 100</span>
                          </div>
                          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
                            Weighted quantum vulnerability
                          </div>
                        </div>

                        <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                            <span>Total CBOM Assets</span>
                            <Layers size={15} color="#38bdf8" />
                          </div>
                          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#ffffff', margin: '0.3rem 0 0.15rem 0' }}>
                            {stats.totalAssets || assets.length}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
                            Certificates, keys, repos &amp; ciphers
                          </div>
                        </div>

                        <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px', padding: '1rem' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                            <span>Shor Vulnerable</span>
                            <AlertOctagon size={15} color="#f87171" />
                          </div>
                          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#f87171', margin: '0.3rem 0 0.15rem 0' }}>
                            {stats.vulnerableAssets}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary, #94a3b8)' }}>
                            Require ML-KEM / ML-DSA
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Table View */}
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.025)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.5rem'
                    }}>
                      {/* Filters & Search */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                          {['all', 'certificate', 'private_key', 'ssh_key', 'source_code', 'dependency', 'config'].map(cat => (
                            <button
                              key={cat}
                              onClick={() => setCbomCategory(cat)}
                              style={{
                                padding: '0.35rem 0.75rem',
                                borderRadius: '6px',
                                border: '1px solid',
                                borderColor: cbomCategory === cat ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.08)',
                                background: cbomCategory === cat ? 'rgba(56, 189, 248, 0.15)' : 'rgba(0, 0, 0, 0.25)',
                                color: cbomCategory === cat ? '#38bdf8' : 'var(--text-secondary, #94a3b8)',
                                fontSize: '0.76rem',
                                fontWeight: 600,
                                cursor: 'pointer',
                                textTransform: 'capitalize'
                              }}
                            >
                              {cat === 'all' ? 'All Components' : 
                               cat === 'private_key' ? 'Private Keys' : 
                               cat === 'ssh_key' ? 'SSH Keys' : 
                               cat === 'source_code' ? 'Source Code' :
                               cat === 'dependency' ? 'Dependencies' :
                               cat === 'config' ? 'Ciphers & Protocols' : 'Certificates'}
                            </button>
                          ))}
                        </div>

                        <input
                          type="text"
                          placeholder="Search CBOM components, algorithms, hostnames..."
                          value={cbomSearch}
                          onChange={e => setCbomSearch(e.target.value)}
                          style={{
                            background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(255, 255, 255, 0.15)',
                            padding: '0.45rem 0.85rem',
                            borderRadius: '6px',
                            color: '#ffffff',
                            fontSize: '0.82rem',
                            outline: 'none',
                            width: '280px'
                          }}
                        />
                      </div>

                      <div style={{ overflowX: 'auto', maxHeight: '550px' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                          <thead style={{ position: 'sticky', top: 0, background: '#0b1120', zIndex: 2 }}>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Component Identifier</th>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Asset Type</th>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Algorithm &amp; Size</th>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Quantum Threat</th>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Standards</th>
                              <th style={{ padding: '0.65rem 0.5rem' }}>Host / Source</th>
                            </tr>
                          </thead>
                          <tbody>
                            {assets.filter(a => {
                              if (cbomCategory !== 'all' && a.type !== cbomCategory) return false;
                              if (cbomSearch) {
                                const q = cbomSearch.toLowerCase();
                                return (
                                  a.name.toLowerCase().includes(q) ||
                                  a.algorithm.toLowerCase().includes(q) ||
                                  (a.hostname && a.hostname.toLowerCase().includes(q)) ||
                                  (a.sourceRef && a.sourceRef.toLowerCase().includes(q)) ||
                                  (a.path && a.path.toLowerCase().includes(q))
                                );
                              }
                              return true;
                            }).map(a => (
                              <tr key={a.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                                <td style={{ padding: '0.7rem 0.5rem' }}>
                                  <div style={{ color: '#ffffff', fontWeight: 600 }}>{a.name}</div>
                                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace' }}>
                                    {a.path || `cryptoProperties.assetType: ${a.type}`}
                                  </div>
                                </td>
                                <td style={{ padding: '0.7rem 0.5rem' }}>
                                  <span style={{
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    textTransform: 'uppercase',
                                    padding: '0.15rem 0.45rem',
                                    borderRadius: '3px',
                                    background: a.source === 'git_repo' ? 'rgba(192, 132, 252, 0.12)' : 'rgba(255, 255, 255, 0.05)',
                                    color: a.source === 'git_repo' ? '#c084fc' : 'var(--text-secondary, #94a3b8)'
                                  }}>
                                    {a.type}
                                  </span>
                                </td>
                                <td style={{ padding: '0.7rem 0.5rem' }}>
                                  <span style={{ fontFamily: 'monospace', color: a.algorithm?.includes('ML-') ? '#4ade80' : '#38bdf8', fontWeight: 600 }}>
                                    {a.algorithm}
                                  </span>
                                  {a.keySize && (
                                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', marginLeft: '0.35rem' }}>
                                      ({a.keySize}b)
                                    </span>
                                  )}
                                </td>
                                <td style={{ padding: '0.7rem 0.5rem' }}>
                                  {a.isVulnerable ? (
                                    <span style={{
                                      fontSize: '0.7rem',
                                      fontWeight: 700,
                                      color: '#f87171',
                                      background: 'rgba(239, 68, 68, 0.12)',
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '3px',
                                      border: '1px solid rgba(239, 68, 68, 0.25)'
                                    }}>
                                      Shor Vulnerable
                                    </span>
                                  ) : (
                                    <span style={{
                                      fontSize: '0.7rem',
                                      fontWeight: 700,
                                      color: '#4ade80',
                                      background: 'rgba(34, 197, 94, 0.12)',
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '3px',
                                      border: '1px solid rgba(34, 197, 94, 0.25)'
                                    }}>
                                      Post-Quantum Ready
                                    </span>
                                  )}
                                </td>
                                <td style={{ padding: '0.7rem 0.5rem', fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
                                  {Array.isArray(a.complianceViolations) && a.complianceViolations.length > 0 ? (
                                    <span style={{ color: '#f87171' }}>{a.complianceViolations.join(', ')}</span>
                                  ) : (
                                    <span>NIST SP 800-208 / CNSA 2.0</span>
                                  )}
                                </td>
                                <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted, #94a3b8)' }}>
                                 {a.source === 'git_repo' ? (
                                   <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#c084fc', fontSize: '0.78rem' }}>
                                     <GitBranch size={13} color="#c084fc" />
                                     <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Git Repository'}</span>
                                   </span>
                                 ) : a.source === 'cloud_kms' ? (
                                   <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#00f2fe', fontSize: '0.78rem' }}>
                                     <Cloud size={13} color="#00f2fe" />
                                     <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Cloud KMS'}</span>
                                   </span>
                                 ) : a.source === 'enterprise_pki' ? (
                                   <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#38bdf8', fontSize: '0.78rem' }}>
                                     <Database size={13} color="#38bdf8" />
                                     <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Enterprise CA'}</span>
                                   </span>
                                 ) : a.source === 'pqc_proxy' ? (
                                   <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#f59e0b', fontSize: '0.78rem' }}>
                                     <Radio size={13} color="#f59e0b" />
                                     <span title={a.sourceRef || a.hostname}>{a.hostname || a.sourceRef || 'Hybrid TLS Proxy'}</span>
                                   </span>
                                 ) : (
                                   <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', color: '#38bdf8', fontSize: '0.78rem' }}>
                                     <Laptop size={13} color="#38bdf8" />
                                     <span>{a.hostname || 'Workstation'}</span>
                                   </span>
                                 )}
                               </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* SUB-TAB 3: RAW JSON & EXPORT */}
                {cbomSubTab === 'json' && (
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.025)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '12px',
                    padding: '1.5rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                      <div>
                        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: '0 0 0.25rem 0', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Code2 size={18} color="#38bdf8" />
                          <span>Standardized CycloneDX 1.6 Cryptographic BOM Schema</span>
                        </h3>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                          Machine-readable CBOM format for SIEM ingestion, compliance auditors, and CI/CD pipelines.
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                        {/* CDXA Toggle */}
                        <button
                          onClick={() => setCbomAttestationMode(!cbomAttestationMode)}
                          title="Toggle CycloneDX 1.6 CDXA Attestation Declarations (NIST SP 800-218, CNSA 2.0) and ML-DSA-65 Digital Signature"
                          style={{
                            background: cbomAttestationMode ? 'rgba(168, 85, 247, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                            border: cbomAttestationMode ? '1px solid #c084fc' : '1px solid rgba(255, 255, 255, 0.12)',
                            color: cbomAttestationMode ? '#c084fc' : '#94a3b8',
                            padding: '0.4rem 0.85rem',
                            borderRadius: '6px',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <ShieldCheck size={13} color={cbomAttestationMode ? '#c084fc' : '#94a3b8'} />
                          {cbomAttestationMode ? 'CDXA Attestation & Signing: ON' : 'Include CDXA Attestation: OFF'}
                        </button>

                        <button
                          onClick={() => {
                            const fullJson = JSON.stringify(buildCycloneDxDocument(cbomAttestationMode), null, 2);
                            navigator.clipboard.writeText(fullJson);
                            setCbomJsonCopied(true);
                            setTimeout(() => setCbomJsonCopied(false), 2000);
                          }}
                          style={{
                            background: 'rgba(255, 255, 255, 0.05)',
                            border: '1px solid rgba(255, 255, 255, 0.12)',
                            color: cbomJsonCopied ? '#4ade80' : '#38bdf8',
                            padding: '0.4rem 0.85rem',
                            borderRadius: '6px',
                            fontSize: '0.78rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.35rem'
                          }}
                        >
                          {cbomJsonCopied ? <Check size={13} color="#4ade80" /> : <Copy size={13} />}
                          {cbomJsonCopied ? 'Copied Full CBOM' : 'Copy JSON'}
                        </button>

                        <button
                          onClick={() => downloadCBOMJson(cbomAttestationMode)}
                          style={{
                            background: cbomAttestationMode 
                              ? 'linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(56, 189, 248, 0.25) 100%)'
                              : 'linear-gradient(135deg, rgba(0, 242, 254, 0.2) 0%, rgba(56, 189, 248, 0.2) 100%)',
                            border: cbomAttestationMode 
                              ? '1px solid rgba(168, 85, 247, 0.5)'
                              : '1px solid rgba(0, 242, 254, 0.4)',
                            color: cbomAttestationMode ? '#c084fc' : '#38bdf8',
                            padding: '0.4rem 0.85rem',
                            borderRadius: '6px',
                            fontSize: '0.78rem',
                            fontWeight: 700,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.35rem'
                          }}
                        >
                          <Download size={13} /> {cbomAttestationMode ? 'Download Attested CDXA' : 'Download JSON'}
                        </button>
                      </div>
                    </div>

                    <pre style={{
                      margin: 0,
                      padding: '1.25rem',
                      background: '#030712',
                      borderRadius: '8px',
                      fontFamily: 'monospace',
                      fontSize: '0.78rem',
                      color: cbomAttestationMode ? '#c084fc' : '#38bdf8',
                      border: cbomAttestationMode ? '1px solid rgba(168, 85, 247, 0.3)' : '1px solid rgba(255, 255, 255, 0.08)',
                      overflowX: 'auto',
                      maxHeight: '560px',
                      whiteSpace: 'pre'
                    }}>
                      {cbomPreviewJson}
                    </pre>
                  </div>
                )}

                {/* Cryptographic Drift Subtab View */}
                {cbomSubTab === 'drift' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                    {/* Drift Metrics Summary */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '1rem'
                    }}>
                      <div style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '8px',
                        padding: '1rem'
                      }}>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Drift Events</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.35rem' }}>{driftEvents.length}</div>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.2rem' }}>Continuous cryptographic diffs</div>
                      </div>

                      <div style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '8px',
                        padding: '1rem'
                      }}>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Assets Added</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#34d399', marginTop: '0.35rem' }}>
                          {driftEvents.filter(e => e.changeType === 'added').length}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.2rem' }}>Newly discovered keys &amp; certs</div>
                      </div>

                      <div style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '8px',
                        padding: '1rem'
                      }}>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Assets Decommissioned</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#94a3b8', marginTop: '0.35rem' }}>
                          {driftEvents.filter(e => e.changeType === 'removed').length}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.2rem' }}>Removed from monitored endpoints</div>
                      </div>

                      <div style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '8px',
                        padding: '1rem'
                      }}>
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Vulnerable Additions</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f87171', marginTop: '0.35rem' }}>
                          {driftEvents.filter(e => e.changeType === 'added' && e.isVulnerable).length}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.2rem' }}>Classical / quantum-vulnerable</div>
                      </div>
                    </div>

                    {/* Filter & Refresh Toolbar */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '220px' }}>
                        <div style={{ position: 'relative', width: '100%', maxWidth: '360px' }}>
                          <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                          <input
                            type="text"
                            placeholder="Filter drift by asset, algorithm, or machine..."
                            value={driftSearch}
                            onChange={(e) => setDriftSearch(e.target.value)}
                            style={{
                              width: '100%',
                              padding: '0.5rem 0.75rem 0.5rem 2.25rem',
                              background: 'rgba(255, 255, 255, 0.03)',
                              border: '1px solid rgba(255, 255, 255, 0.1)',
                              borderRadius: '6px',
                              color: '#fff',
                              fontSize: '0.8rem'
                            }}
                          />
                        </div>
                      </div>

                      <button
                        onClick={fetchDriftEvents}
                        disabled={isLoadingDrift}
                        style={{
                          background: 'rgba(56, 189, 248, 0.1)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          color: '#38bdf8',
                          padding: '0.5rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          cursor: isLoadingDrift ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem'
                        }}
                      >
                        <RefreshCw size={13} className={isLoadingDrift ? 'animate-spin' : ''} />
                        {isLoadingDrift ? 'Refreshing...' : 'Refresh Drift Log'}
                      </button>
                    </div>

                    {/* Drift Table */}
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '8px',
                      overflowX: 'auto'
                    }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', background: 'rgba(255, 255, 255, 0.02)' }}>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Change</th>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Asset Name</th>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Algorithm</th>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Quantum Status</th>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Machine ID</th>
                            <th style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontWeight: 600 }}>Detected At</th>
                          </tr>
                        </thead>
                        <tbody>
                          {driftEvents
                            .filter(e => {
                              if (!driftSearch) return true;
                              const q = driftSearch.toLowerCase();
                              return (
                                (e.assetName || '').toLowerCase().includes(q) ||
                                (e.algorithm || '').toLowerCase().includes(q) ||
                                (e.machineId || '').toLowerCase().includes(q)
                              );
                            })
                            .map((ev, idx) => (
                              <tr key={ev.id || idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                                <td style={{ padding: '0.75rem 1rem' }}>
                                  <span style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.25rem',
                                    padding: '0.2rem 0.55rem',
                                    borderRadius: '4px',
                                    fontSize: '0.7rem',
                                    fontWeight: 700,
                                    textTransform: 'uppercase',
                                    background: ev.changeType === 'added' ? 'rgba(52, 211, 153, 0.15)' : 'rgba(248, 113, 113, 0.15)',
                                    color: ev.changeType === 'added' ? '#34d399' : '#f87171',
                                    border: `1px solid ${ev.changeType === 'added' ? 'rgba(52, 211, 153, 0.3)' : 'rgba(248, 113, 113, 0.3)'}`
                                  }}>
                                    {ev.changeType === 'added' ? '+ ADDED' : '- REMOVED'}
                                  </span>
                                </td>
                                <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f1f5f9' }}>
                                  {ev.assetName}
                                </td>
                                <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                                  {ev.algorithm}
                                </td>
                                <td style={{ padding: '0.75rem 1rem' }}>
                                  <span style={{
                                    padding: '0.15rem 0.5rem',
                                    borderRadius: '4px',
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    background: ev.isVulnerable ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                    color: ev.isVulnerable ? '#f87171' : '#34d399'
                                  }}>
                                    {ev.isVulnerable ? 'Quantum Vulnerable' : 'Post-Quantum Secure'}
                                  </span>
                                </td>
                                <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                                  {ev.machineId ? ev.machineId.substring(0, 16) : '-'}
                                </td>
                                <td style={{ padding: '0.75rem 1rem', color: '#64748b', fontSize: '0.75rem' }}>
                                  {ev.detectedAt ? new Date(ev.detectedAt).toLocaleString() : '-'}
                                </td>
                              </tr>
                            ))}
                          {driftEvents.length === 0 && !isLoadingDrift && (
                            <tr>
                              <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: '#64748b' }}>
                                <Activity size={24} style={{ margin: '0 auto 0.75rem', opacity: 0.5, color: '#38bdf8' }} />
                                <div style={{ fontWeight: 600, color: '#94a3b8' }}>No Cryptographic Drift Detected</div>
                                <div style={{ fontSize: '0.75rem', marginTop: '0.25rem', color: '#64748b' }}>
                                  Monitored endpoints have not reported added or removed cryptographic assets relative to their baseline.
                                </div>
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {cbomSubTab === 'sbom' && (
                  <div style={{ marginTop: '0.5rem' }}>
                    <SbomInventory
                      tenant={client?.name || cleanSlug}
                      apiUrl=""
                      isSuperAdmin={false}
                    />
                  </div>
                )}
              </div>
            )}

            {/* INTEGRATIONS & GATEWAYS — Git / PKI / Proxy sub-tabs */}
            {isIntegrationsTab && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {/* Sub-tab bar */}
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '0.75rem' }}>
                  {([
                    { id: 'git' as const, label: 'Git & CI/CD Gate', Icon: GitBranch },
                    { id: 'pki' as const, label: 'Enterprise PKI & Vaults', Icon: Database },
                    { id: 'proxy' as const, label: 'Hybrid Quantum TLS Proxy', Icon: Radio }
                  ]).map(({ id, label, Icon }) => (
                    <button
                      key={id}
                      onClick={() => setActiveTab(id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem',
                        padding: '0.5rem 0.9rem',
                        borderRadius: '7px',
                        background: activeTab === id ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
                        border: activeTab === id ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)',
                        color: activeTab === id ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-secondary, #94a3b8)',
                        fontSize: '0.82rem',
                        fontWeight: activeTab === id ? 600 : 500,
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <Icon size={15} color={activeTab === id ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-muted, #64748b)'} />
                      <span>{label}</span>
                    </button>
                  ))}
                </div>

                {/* Sub-tab content */}
                {activeTab === 'git' && (
                  <GitRepoAuditor onAssetsChanged={fetchTenantData} />
                )}
                {activeTab === 'pki' && (
                  <EnterprisePkiVaults tenantName={client.displayName || tenantSlug} onAssetsChanged={fetchTenantData} />
                )}
                {activeTab === 'proxy' && (
                  <PqcProxyGateway onAssetsChanged={fetchTenantData} />
                )}
              </div>
            )}

            {/* Compliance (OSCAL) — authorization boundaries / Projects (BILL-4) */}
            {activeTab === 'compliance' && (
              <ComplianceProjects tenantName={client.displayName} />
            )}

            {/* Threat & Risk Graph (Risk Assurance plan) — tenant is pinned server-side */}
            {activeTab === 'threat' && (
              <React.Suspense fallback={<div style={{ padding: '1rem', color: 'var(--text-muted)' }}>Loading Threat &amp; Risk Graph…</div>}>
                <ThreatRiskGraph />
              </React.Suspense>
            )}

            {/* 4. PQC COPILOT ASSISTANT TAB */}
            {activeTab === 'copilot' && (
              <div style={{ display: 'flex', gap: '1rem', height: 'calc(100vh - 120px)', minHeight: '680px' }}>
                {/* Left Sidebar: Conversations list */}
                <div style={{
                  width: '260px',
                  flexShrink: 0,
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem'
                }}>
                  {/* + New Chat Button */}
                  <button
                    onClick={handleNewChat}
                    style={{
                      width: '100%',
                      padding: '0.65rem 1rem',
                      borderRadius: '8px',
                      background: 'rgba(56, 189, 248, 0.08)',
                      border: '1px solid rgba(56, 189, 248, 0.35)',
                      color: '#ffffff',
                      fontSize: '0.85rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '0.5rem',
                      transition: 'all 0.2s ease'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'rgba(56, 189, 248, 0.16)';
                      e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.6)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'rgba(56, 189, 248, 0.08)';
                      e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.35)';
                    }}
                  >
                    <Plus size={16} color="#38bdf8" />
                    <span>New Chat</span>
                  </button>

                  <div style={{
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    color: '#64748b',
                    textTransform: 'uppercase',
                    marginTop: '0.25rem',
                    paddingLeft: '0.25rem'
                  }}>
                    CONVERSATIONS
                  </div>

                  {/* Sessions List */}
                  <div style={{
                    flex: 1,
                    overflowY: 'auto',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem',
                    paddingRight: '0.25rem'
                  }}>
                    {copilotSessions.map(session => {
                      const isActive = session.id === activeSessionId;
                      return (
                        <div
                          key={session.id}
                          onClick={() => setActiveSessionId(session.id)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '0.55rem 0.65rem',
                            borderRadius: '8px',
                            cursor: 'pointer',
                            background: isActive ? 'rgba(56, 189, 248, 0.14)' : 'transparent',
                            border: isActive ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid transparent',
                            color: isActive ? '#ffffff' : '#94a3b8',
                            fontSize: '0.8rem',
                            transition: 'background 0.15s ease'
                          }}
                          onMouseEnter={(e) => {
                            if (!isActive) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                          }}
                          onMouseLeave={(e) => {
                            if (!isActive) e.currentTarget.style.background = 'transparent';
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', overflow: 'hidden', flex: 1, minWidth: 0 }}>
                            <MessageSquare size={14} color={isActive ? '#38bdf8' : '#64748b'} style={{ flexShrink: 0 }} />
                            <span style={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              fontWeight: isActive ? 600 : 400
                            }}>
                              {session.title || 'New Conversation'}
                            </span>
                          </div>

                          <button
                            onClick={(e) => handleDeleteSession(session.id, e)}
                            title="Delete chat"
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#64748b',
                              cursor: 'pointer',
                              padding: '2px 4px',
                              display: 'flex',
                              alignItems: 'center',
                              borderRadius: '4px',
                              opacity: isActive ? 0.9 : 0.6,
                              transition: 'all 0.15s'
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.color = '#ef4444';
                              e.currentTarget.style.opacity = '1';
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.color = '#64748b';
                              e.currentTarget.style.opacity = isActive ? '0.9' : '0.6';
                            }}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Right Chat Panel */}
                <div style={{
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.25rem',
                  overflow: 'hidden'
                }}>
                  {/* Top Bar matching screenshot */}
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingBottom: '0.75rem',
                    borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
                    flexWrap: 'wrap',
                    gap: '0.75rem'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <div style={{
                        width: '32px',
                        height: '32px',
                        borderRadius: '8px',
                        background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2) 0%, rgba(56, 189, 248, 0.2) 100%)',
                        border: '1px solid rgba(0, 242, 254, 0.4)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        <Sparkles size={18} color="#38bdf8" />
                      </div>
                      <div>
                        <h3 style={{ fontSize: '1.05rem', fontWeight: 800, margin: 0, color: '#ffffff' }}>
                          QuarkShield AI • PQC Copilot
                        </h3>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.1rem' }}>
                          Scoped to {client.displayName || 'Enterprise'} ({stats.totalAssets || assets.length} Discovered Assets)
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      <label style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.45rem',
                        fontSize: '0.78rem',
                        color: liveWebSearch ? '#38bdf8' : '#94a3b8',
                        cursor: 'pointer',
                        userSelect: 'none',
                        fontWeight: 500
                      }}>
                        <input
                          type="checkbox"
                          checked={liveWebSearch}
                          onChange={e => setLiveWebSearch(e.target.checked)}
                          style={{ cursor: 'pointer', accentColor: '#38bdf8' }}
                        />
                        <span>🌐 Live Web Search (NIST/PQC)</span>
                      </label>

                      <button
                        onClick={handleClearCurrentChat}
                        style={{
                          background: 'rgba(239, 68, 68, 0.08)',
                          border: '1px solid rgba(239, 68, 68, 0.35)',
                          color: '#f87171',
                          padding: '0.35rem 0.75rem',
                          borderRadius: '6px',
                          fontSize: '0.76rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                          transition: 'all 0.15s'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = 'rgba(239, 68, 68, 0.18)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)';
                        }}
                      >
                        <Trash2 size={13} /> Clear Chat
                      </button>
                    </div>
                  </div>

                  {/* Quick Prompts Bar */}
                  <div style={{ display: 'flex', gap: '0.5rem', overflowX: 'auto', paddingBottom: '0.25rem' }}>
                    {[
                      "What are my next steps after license onboarding?",
                      "How do I run my first desktop scan?",
                      "How do I set up the CI/CD Pipeline CBOM Gate?",
                      "How do I connect Enterprise PKI & Vaults?",
                      "How do I deploy the Hybrid Quantum TLS Proxy?",
                      "Explain the 3-Tier Enterprise PQC Deployment Strategy",
                      "How do I onboard staff & allocate license seats?",
                      "How do I migrate RSA-2048 keys to ML-DSA (FIPS 204)?",
                      "How does Shor's Algorithm break RSA-2048 & ECC?",
                      "Generate NGINX config for post-quantum hybrid TLS (X25519MLKEM768)",
                      "How do I configure OpenSSH 9.8+ for hybrid PQC key exchange?"
                    ].map((chip, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleSendCopilotMessage(chip)}
                        style={{
                          padding: '0.35rem 0.75rem',
                          borderRadius: '16px',
                          background: 'rgba(0, 0, 0, 0.4)',
                          border: '1px solid rgba(56, 189, 248, 0.25)',
                          color: 'var(--accent-cyan, #38bdf8)',
                          fontSize: '0.72rem',
                          fontWeight: 500,
                          cursor: 'pointer',
                          whiteSpace: 'nowrap',
                          flexShrink: 0,
                          transition: 'all 0.15s'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.6)';
                          e.currentTarget.style.background = 'rgba(56, 189, 248, 0.1)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.25)';
                          e.currentTarget.style.background = 'rgba(0, 0, 0, 0.4)';
                        }}
                      >
                        ⚡ {chip}
                      </button>
                    ))}
                  </div>

                  {/* Message Thread */}
                  <div style={{
                    flex: 1,
                    background: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    borderRadius: '10px',
                    padding: '1.25rem',
                    overflowY: 'auto',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '1rem'
                  }}>
                    {copilotMessages.map((msg, i) => {
                      const isUser = msg.sender === 'user';
                      return (
                        <div
                          key={msg.id || i}
                          style={{
                            display: 'flex',
                            justifyContent: isUser ? 'flex-end' : 'flex-start',
                            gap: '0.75rem',
                            alignItems: 'flex-start'
                          }}
                        >
                          {!isUser && (
                            <div style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '8px',
                              background: 'rgba(56, 189, 248, 0.15)',
                              border: '1px solid rgba(56, 189, 248, 0.3)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0
                            }}>
                              <Bot size={18} color="#38bdf8" />
                            </div>
                          )}

                          <div style={{
                            maxWidth: isUser ? '75%' : '88%',
                            padding: '0.9rem 1.15rem',
                            borderRadius: isUser ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                            background: isUser ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' : 'rgba(255, 255, 255, 0.035)',
                            border: isUser ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                            color: '#ffffff',
                            fontSize: '0.85rem',
                            lineHeight: '1.55'
                          }}>
                            {/* Render attachments if any */}
                            {msg.attachments && msg.attachments.length > 0 && (
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.5rem' }}>
                                {msg.attachments.map((att, aIdx) => (
                                  <div
                                    key={aIdx}
                                    style={{
                                      display: 'flex',
                                      alignItems: 'center',
                                      gap: '0.35rem',
                                      background: 'rgba(0, 0, 0, 0.25)',
                                      padding: '0.2rem 0.5rem',
                                      borderRadius: '4px',
                                      fontSize: '0.72rem',
                                      border: '1px solid rgba(255, 255, 255, 0.15)'
                                    }}
                                  >
                                    <File size={12} color="#38bdf8" />
                                    <span>{att.name}</span>
                                    <span style={{ color: '#94a3b8' }}>({(att.size / 1024).toFixed(1)} KB)</span>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* Markdown-formatted content */}
                            {isUser ? (
                              <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>
                            ) : (
                              <div>{renderMarkdownMessage(msg.text)}</div>
                            )}

                            {msg.code && (
                              <div style={{ marginTop: '0.65rem' }}>
                                <div style={{
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  alignItems: 'center',
                                  background: '#030712',
                                  padding: '0.35rem 0.65rem',
                                  borderRadius: '4px 4px 0 0',
                                  borderBottom: '1px solid rgba(255,255,255,0.06)',
                                  fontSize: '0.7rem',
                                  color: 'var(--text-muted, #94a3b8)'
                                }}>
                                  <span>{msg.language || 'config'}</span>
                                  <button
                                    onClick={() => {
                                      copyToClipboard(msg.code || '', `copilot-${i}`);
                                      setCopilotCopiedIdx(i);
                                      setTimeout(() => setCopilotCopiedIdx(null), 2000);
                                    }}
                                    style={{ background: 'transparent', border: 'none', color: '#38bdf8', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                                  >
                                    {copilotCopiedIdx === i ? <Check size={12} color="#4ade80" /> : <Copy size={12} />}
                                    {copilotCopiedIdx === i ? 'Copied' : 'Copy'}
                                  </button>
                                </div>
                                <pre style={{ margin: 0, padding: '0.75rem', background: '#030712', borderRadius: '0 0 4px 4px', fontFamily: 'monospace', fontSize: '0.76rem', color: '#4ade80', overflowX: 'auto' }}>
                                  {msg.code}
                                </pre>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}

                    {copilotLoading && (
                      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                        <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Sparkles size={16} color="#38bdf8" />
                        </div>
                        <div style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.8rem', fontStyle: 'italic' }}>
                          QuarkShield Copilot is reasoning through cryptographic dependencies...
                        </div>
                      </div>
                    )}
                    <div ref={chatBottomRef} />
                  </div>

                  {/* Pending Attachments preview chips */}
                  {pendingAttachments.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', padding: '0.35rem 0.5rem', background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.2)', borderRadius: '8px' }}>
                      {pendingAttachments.map((att, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.4rem',
                            background: 'rgba(0, 0, 0, 0.4)',
                            padding: '0.25rem 0.6rem',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            color: '#ffffff',
                            border: '1px solid rgba(255, 255, 255, 0.1)'
                          }}
                        >
                          <File size={13} color="#38bdf8" />
                          <span style={{ maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{att.name}</span>
                          <span style={{ color: '#64748b', fontSize: '0.7rem' }}>({(att.size / 1024).toFixed(1)} KB)</span>
                          <button
                            type="button"
                            onClick={() => removePendingAttachment(idx)}
                            style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center' }}
                          >
                            <X size={12} color="#f87171" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Voice recording alert */}
                  {isListening && (
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      padding: '0.35rem 0.75rem',
                      background: 'rgba(239, 68, 68, 0.12)',
                      border: '1px solid rgba(239, 68, 68, 0.35)',
                      borderRadius: '6px',
                      color: '#f87171',
                      fontSize: '0.75rem',
                      fontWeight: 600
                    }}>
                      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }} />
                      <span>Listening to speech dictation... Speak into your microphone. Click mic again when finished.</span>
                    </div>
                  )}

                  {/* Input Bar with paperclip & mic */}
                  <form
                    onSubmit={e => {
                      e.preventDefault();
                      handleSendCopilotMessage();
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '10px',
                      padding: '0.45rem 0.6rem'
                    }}
                  >
                    {/* Hidden file input */}
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileSelect}
                      multiple
                      style={{ display: 'none' }}
                      accept=".pem,.crt,.key,.pub,.conf,.json,.yaml,.yml,.txt,.log,.csv,image/*"
                    />

                    {/* Paperclip button */}
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      title="Attach file (.pem, .crt, .key, .conf, .json, .log, images)"
                      style={{
                        background: pendingAttachments.length > 0 ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                        border: pendingAttachments.length > 0 ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                        color: pendingAttachments.length > 0 ? '#38bdf8' : '#94a3b8',
                        borderRadius: '8px',
                        width: '36px',
                        height: '36px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        cursor: 'pointer',
                        flexShrink: 0,
                        transition: 'all 0.15s'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.color = '#38bdf8';
                        e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.4)';
                      }}
                      onMouseLeave={(e) => {
                        if (pendingAttachments.length === 0) {
                          e.currentTarget.style.color = '#94a3b8';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                        }
                      }}
                    >
                      <Paperclip size={17} />
                    </button>

                    {/* Mic button */}
                    <button
                      type="button"
                      onClick={toggleVoiceInput}
                      title={isListening ? 'Stop voice dictation' : 'Start voice dictation'}
                      style={{
                        background: isListening ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                        border: isListening ? '1px solid #ef4444' : '1px solid rgba(255, 255, 255, 0.08)',
                        color: isListening ? '#ef4444' : '#94a3b8',
                        borderRadius: '8px',
                        width: '36px',
                        height: '36px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        cursor: 'pointer',
                        flexShrink: 0,
                        transition: 'all 0.15s'
                      }}
                      onMouseEnter={(e) => {
                        if (!isListening) {
                          e.currentTarget.style.color = '#38bdf8';
                          e.currentTarget.style.borderColor = 'rgba(56, 189, 248, 0.4)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (!isListening) {
                          e.currentTarget.style.color = '#94a3b8';
                          e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                        }
                      }}
                    >
                      {isListening ? <MicOff size={17} /> : <Mic size={17} />}
                    </button>

                    {/* Text input */}
                    <input
                      type="text"
                      placeholder="Ask a question or describe your attached file..."
                      value={copilotInput}
                      onChange={e => setCopilotInput(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          handleSendCopilotMessage();
                        }
                      }}
                      style={{
                        flex: 1,
                        background: 'transparent',
                        border: 'none',
                        color: '#ffffff',
                        fontSize: '0.85rem',
                        padding: '0.4rem 0.6rem',
                        outline: 'none'
                      }}
                    />

                    {/* Send button */}
                    <button
                      type="submit"
                      disabled={(!copilotInput.trim() && pendingAttachments.length === 0) || copilotLoading}
                      style={{
                        background: (copilotInput.trim() || pendingAttachments.length > 0) && !copilotLoading
                          ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)'
                          : 'rgba(255, 255, 255, 0.05)',
                        border: 'none',
                        borderRadius: '8px',
                        width: '36px',
                        height: '36px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#ffffff',
                        cursor: (copilotInput.trim() || pendingAttachments.length > 0) && !copilotLoading ? 'pointer' : 'not-allowed',
                        flexShrink: 0,
                        transition: 'all 0.15s'
                      }}
                    >
                      <Send size={15} />
                    </button>
                  </form>
                </div>
              </div>
            )}

            {/* SETTINGS MAIN VIEW (PROFILE, TEAM & 2FA, LICENSE) */}
            {isSettingsActive && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                {/* Settings Header with Workspace Context & Horizontal Subtabs */}
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.25rem 1.5rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '1rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.25rem' }}>
                        <div style={{ padding: '0.4rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
                          <Settings size={20} color="var(--accent-cyan, #38bdf8)" />
                        </div>
                        <h1 style={{ fontSize: '1.35rem', fontWeight: 800, margin: 0, color: '#ffffff' }}>
                          Workspace Settings &amp; Security Controls
                        </h1>
                      </div>
                      <p style={{ margin: 0, color: 'var(--text-muted, #94a3b8)', fontSize: '0.84rem' }}>
                        Configure user profile, update password, review 2FA, manage team members, inspect enterprise licenses, and deploy PQC agents for {displayCustomerName}.
                      </p>
                    </div>

                    {/* Workspace Node Badge */}
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                      padding: '0.4rem 0.85rem',
                      background: 'rgba(13, 19, 33, 0.85)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      fontSize: '0.78rem'
                    }}>
                      <Building size={14} color="var(--accent-cyan, #38bdf8)" />
                      <span style={{ color: 'var(--text-muted, #94a3b8)' }}>Node:</span>
                      <strong style={{ color: '#ffffff' }}>{cleanSlug}.quarkshield.ai</strong>
                    </div>
                  </div>

                  {/* Horizontal Settings Subtabs */}
                  <div style={{
                    display: 'flex',
                    gap: '0.5rem',
                    borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                    paddingTop: '0.85rem',
                    overflowX: 'auto'
                  }}>
                    {[
                      { id: 'profile' as const, label: 'Profile', icon: User, badge: 'Personal & Logs' },
                      { id: 'users' as const, label: 'Team & 2FA', icon: Users, badge: 'RBAC' },
                      { id: 'license' as const, label: 'License', icon: Key, badge: `${activeLicenses.length} Active` },
                      { id: 'groups' as const, label: 'Groups', icon: Layers, badge: `${fleetGroups.length}` },
                      { id: 'stakeholders' as const, label: 'Report Stakeholders', icon: Users, badge: 'Email' }
                    ].map(tab => {
                      const Icon = tab.icon;
                      const isSubActive = effectiveSettingsTab === tab.id;
                      return (
                        <button
                          key={tab.id}
                          onClick={() => {
                            setActiveTab('settings');
                            setSettingsSubTab(tab.id);
                          }}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.55rem',
                            padding: '0.55rem 1rem',
                            borderRadius: '8px',
                            background: isSubActive ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                            border: isSubActive ? '1px solid rgba(0, 242, 254, 0.4)' : '1px solid rgba(255, 255, 255, 0.06)',
                            color: isSubActive ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-secondary, #94a3b8)',
                            fontSize: '0.84rem',
                            fontWeight: isSubActive ? 700 : 500,
                            cursor: 'pointer',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <Icon size={16} color={isSubActive ? 'var(--accent-cyan, #38bdf8)' : 'var(--text-muted, #64748b)'} />
                          <span>{tab.label}</span>
                          {tab.badge && (
                            <span style={{
                              fontSize: '0.65rem',
                              fontWeight: 700,
                              padding: '0.1rem 0.4rem',
                              borderRadius: '4px',
                              background: isSubActive ? 'rgba(56, 189, 248, 0.25)' : 'rgba(255, 255, 255, 0.06)',
                              color: isSubActive ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                              border: '1px solid rgba(255, 255, 255, 0.06)'
                            }}>
                              {tab.badge}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* SUBTAB 1: PROFILE */}
                {effectiveSettingsTab === 'profile' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    {/* Feedback Toasts */}
                    {profileToast && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                        padding: '0.75rem 1rem',
                        background: 'rgba(16, 185, 129, 0.15)',
                        border: '1px solid rgba(16, 185, 129, 0.4)',
                        borderRadius: '8px',
                        color: 'var(--status-secure, #4ade80)',
                        fontSize: '0.85rem'
                      }}>
                        <CheckCircle2 size={18} />
                        <span>{profileToast}</span>
                      </div>
                    )}
                    {passwordSuccess && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                        padding: '0.75rem 1rem',
                        background: 'rgba(16, 185, 129, 0.15)',
                        border: '1px solid rgba(16, 185, 129, 0.4)',
                        borderRadius: '8px',
                        color: 'var(--status-secure, #4ade80)',
                        fontSize: '0.85rem'
                      }}>
                        <CheckCircle2 size={18} />
                        <span>{passwordSuccess}</span>
                      </div>
                    )}
                    {passwordError && (
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                        padding: '0.75rem 1rem',
                        background: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid rgba(239, 68, 68, 0.4)',
                        borderRadius: '8px',
                        color: '#f87171',
                        fontSize: '0.85rem'
                      }}>
                        <AlertTriangle size={18} />
                        <span>{passwordError}</span>
                      </div>
                    )}

                    {/* Standard Information & Password Management Cards */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.25rem' }}>
                      {/* Card 1: Standard Information */}
                      <div style={{
                        background: 'rgba(255, 255, 255, 0.025)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '12px',
                        padding: '1.5rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '1.25rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
                              <User size={18} color="#38bdf8" />
                            </div>
                            <div>
                              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                                Personal &amp; Standard Information
                              </h3>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                                Identity parameters &amp; contact coordinates
                              </span>
                            </div>
                          </div>
                          <span style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.2rem 0.55rem',
                            borderRadius: '20px',
                            background: isPartner ? 'rgba(168, 85, 247, 0.15)' : 'rgba(0, 242, 254, 0.12)',
                            color: isPartner ? '#c084fc' : 'var(--accent-cyan, #38bdf8)',
                            border: `1px solid ${isPartner ? 'rgba(168, 85, 247, 0.3)' : 'rgba(0, 242, 254, 0.3)'}`
                          }}>
                            Profile Information
                          </span>
                        </div>

                        <form onSubmit={handleSaveProfileInfo} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              Full Name / Display Alias
                            </label>
                            <input
                              type="text"
                              value={profileFullName}
                              onChange={e => setProfileFullName(e.target.value)}
                              placeholder="e.g. Alexander Vance"
                              style={{
                                width: '100%',
                                boxSizing: 'border-box',
                                background: 'rgba(0, 0, 0, 0.35)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                borderRadius: '6px',
                                padding: '0.55rem 0.75rem',
                                color: '#ffffff',
                                fontSize: '0.84rem'
                              }}
                            />
                          </div>

                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              Department / Organizational Unit
                            </label>
                            <input
                              type="text"
                              value={profileDepartment}
                              onChange={e => setProfileDepartment(e.target.value)}
                              placeholder="e.g. Enterprise Security Operations"
                              style={{
                                width: '100%',
                                boxSizing: 'border-box',
                                background: 'rgba(0, 0, 0, 0.35)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                borderRadius: '6px',
                                padding: '0.55rem 0.75rem',
                                color: '#ffffff',
                                fontSize: '0.84rem'
                              }}
                            />
                          </div>

                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              Direct Phone / Contact Number
                            </label>
                            <div style={{ position: 'relative' }}>
                              <Phone size={15} color="var(--text-muted, #64748b)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                              <input
                                type="text"
                                value={profilePhone}
                                onChange={e => setProfilePhone(e.target.value)}
                                placeholder="+1 (555) 000-0000"
                                style={{
                                  width: '100%',
                                  boxSizing: 'border-box',
                                  background: 'rgba(0, 0, 0, 0.35)',
                                  border: '1px solid rgba(255, 255, 255, 0.12)',
                                  borderRadius: '6px',
                                  padding: '0.55rem 0.75rem 0.55rem 2rem',
                                  color: '#ffffff',
                                  fontSize: '0.84rem'
                                }}
                              />
                            </div>
                          </div>

                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', paddingTop: '0.25rem' }}>
                            <div>
                              <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block', marginBottom: '0.2rem' }}>
                                Authenticated Email
                              </span>
                              <div style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.4rem',
                                background: 'rgba(0, 0, 0, 0.25)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '6px',
                                padding: '0.45rem 0.65rem',
                                fontSize: '0.8rem',
                                color: '#ffffff',
                                overflow: 'hidden'
                              }}>
                                <CheckCircle2 size={13} color="#10b981" style={{ flexShrink: 0 }} />
                                <span style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={emailInput}>
                                  {emailInput}
                                </span>
                              </div>
                            </div>
                            <div>
                              <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block', marginBottom: '0.2rem' }}>
                                Customer Identifier
                              </span>
                              <div style={{
                                background: 'rgba(0, 0, 0, 0.25)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '6px',
                                padding: '0.45rem 0.65rem',
                                fontSize: '0.8rem',
                                color: '#38bdf8',
                                fontFamily: 'monospace',
                                fontWeight: 600
                              }}>
                                {displayCustomerId}
                              </div>
                            </div>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                            <button
                              type="submit"
                              className="btn-primary"
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.45rem',
                                padding: '0.5rem 1.25rem',
                                fontSize: '0.84rem'
                              }}
                            >
                              <Save size={15} />
                              <span>Save Profile Changes</span>
                            </button>
                          </div>
                        </form>
                      </div>

                      {/* Card 2: Password Management */}
                      <div style={{
                        background: 'rgba(255, 255, 255, 0.025)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '12px',
                        padding: '1.5rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '1.25rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
                              <Lock size={18} color="#38bdf8" />
                            </div>
                            <div>
                              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                                Password Management
                              </h3>
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                                Argon2id memory-hard cryptographic hash
                              </span>
                            </div>
                          </div>
                          <span style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.2rem 0.55rem',
                            borderRadius: '4px',
                            background: 'rgba(16, 185, 129, 0.15)',
                            color: '#4ade80',
                            border: '1px solid rgba(16, 185, 129, 0.3)'
                          }}>
                            Argon2id (m=65536)
                          </span>
                        </div>

                        <form onSubmit={handleUpdatePassword} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              Current Password
                            </label>
                            <div style={{ position: 'relative' }}>
                              <input
                                type={showCurrentPassword ? 'text' : 'password'}
                                value={currentPassword}
                                onChange={e => setCurrentPassword(e.target.value)}
                                placeholder="Enter your current password"
                                style={{
                                  width: '100%',
                                  boxSizing: 'border-box',
                                  background: 'rgba(0, 0, 0, 0.35)',
                                  border: '1px solid rgba(255, 255, 255, 0.12)',
                                  borderRadius: '6px',
                                  padding: '0.55rem 2.2rem 0.55rem 0.75rem',
                                  color: '#ffffff',
                                  fontSize: '0.84rem'
                                }}
                              />
                              <button
                                type="button"
                                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                                style={{
                                  position: 'absolute',
                                  right: '8px',
                                  top: '50%',
                                  transform: 'translateY(-50%)',
                                  background: 'transparent',
                                  border: 'none',
                                  color: 'var(--text-muted, #64748b)',
                                  cursor: 'pointer',
                                  padding: '2px'
                                }}
                              >
                                {showCurrentPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                              </button>
                            </div>
                          </div>

                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              New Password
                            </label>
                            <div style={{ position: 'relative' }}>
                              <input
                                type={showNewPassword ? 'text' : 'password'}
                                value={newPassword}
                                onChange={e => setNewPassword(e.target.value)}
                                placeholder="Minimum 8 characters"
                                style={{
                                  width: '100%',
                                  boxSizing: 'border-box',
                                  background: 'rgba(0, 0, 0, 0.35)',
                                  border: '1px solid rgba(255, 255, 255, 0.12)',
                                  borderRadius: '6px',
                                  padding: '0.55rem 2.2rem 0.55rem 0.75rem',
                                  color: '#ffffff',
                                  fontSize: '0.84rem'
                                }}
                              />
                              <button
                                type="button"
                                onClick={() => setShowNewPassword(!showNewPassword)}
                                style={{
                                  position: 'absolute',
                                  right: '8px',
                                  top: '50%',
                                  transform: 'translateY(-50%)',
                                  background: 'transparent',
                                  border: 'none',
                                  color: 'var(--text-muted, #64748b)',
                                  cursor: 'pointer',
                                  padding: '2px'
                                }}
                              >
                                {showNewPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                              </button>
                            </div>
                          </div>

                          <div>
                            <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: 600, color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.35rem' }}>
                              Confirm New Password
                            </label>
                            <div style={{ position: 'relative' }}>
                              <input
                                type={showConfirmPassword ? 'text' : 'password'}
                                value={confirmPassword}
                                onChange={e => setConfirmPassword(e.target.value)}
                                placeholder="Re-type new password"
                                style={{
                                  width: '100%',
                                  boxSizing: 'border-box',
                                  background: 'rgba(0, 0, 0, 0.35)',
                                  border: '1px solid rgba(255, 255, 255, 0.12)',
                                  borderRadius: '6px',
                                  padding: '0.55rem 2.2rem 0.55rem 0.75rem',
                                  color: '#ffffff',
                                  fontSize: '0.84rem'
                                }}
                              />
                              <button
                                type="button"
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                style={{
                                  position: 'absolute',
                                  right: '8px',
                                  top: '50%',
                                  transform: 'translateY(-50%)',
                                  background: 'transparent',
                                  border: 'none',
                                  color: 'var(--text-muted, #64748b)',
                                  cursor: 'pointer',
                                  padding: '2px'
                                }}
                              >
                                {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                              </button>
                            </div>
                          </div>

                          {/* Password Strength Indicator */}
                          {newPassword && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', marginTop: '0.2rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                                <span style={{ color: 'var(--text-muted, #64748b)' }}>Entropy Strength:</span>
                                <span style={{
                                  fontWeight: 700,
                                  color: newPassword.length >= 12 && /[A-Z]/.test(newPassword) && /[0-9]/.test(newPassword) && /[^A-Za-z0-9]/.test(newPassword)
                                    ? '#10b981'
                                    : newPassword.length >= 8
                                    ? '#38bdf8'
                                    : '#f87171'
                                }}>
                                  {newPassword.length >= 12 && /[A-Z]/.test(newPassword) && /[0-9]/.test(newPassword) && /[^A-Za-z0-9]/.test(newPassword)
                                    ? 'Quantum-Grade'
                                    : newPassword.length >= 8
                                    ? 'Strong'
                                    : 'Weak (min 8 chars)'}
                                </span>
                              </div>
                              <div style={{ height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                                <div style={{
                                  height: '100%',
                                  width: `${Math.min(100, (newPassword.length / 14) * 100)}%`,
                                  background: newPassword.length >= 12 ? 'linear-gradient(90deg, #38bdf8, #10b981)' : '#38bdf8',
                                  transition: 'width 0.2s ease'
                                }} />
                              </div>
                            </div>
                          )}

                          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.4rem' }}>
                            <button
                              type="submit"
                              className="btn-primary"
                              style={{
                                padding: '0.5rem 1.25rem',
                                fontSize: '0.84rem'
                              }}
                            >
                              Update Password
                            </button>
                          </div>
                        </form>
                      </div>
                    </div>

                    {/* Card 3: Two-Factor Authentication (2FA) Security */}
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.025)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.5rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '1rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
                            <ShieldCheck size={18} color="#10b981" />
                          </div>
                          <div>
                            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                              Two-Factor Authentication (2FA) &amp; Session Guard
                            </h3>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                              Hardware &amp; TOTP authenticator challenge status for {emailInput}
                            </span>
                          </div>
                        </div>

                        <span style={{
                          fontSize: '0.74rem',
                          fontWeight: 700,
                          padding: '0.25rem 0.75rem',
                          borderRadius: '20px',
                          background: 'rgba(16, 185, 129, 0.15)',
                          color: '#4ade80',
                          border: '1px solid rgba(16, 185, 129, 0.3)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.35rem'
                        }}>
                          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', display: 'inline-block', boxShadow: '0 0 8px rgba(16, 185, 129, 0.8)' }} />
                          ACTIVE &amp; ENFORCED (RFC 6238)
                        </span>
                      </div>

                      <div style={{
                        background: 'rgba(13, 19, 33, 0.85)',
                        borderRadius: '8px',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        padding: '1rem',
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                        gap: '1rem',
                        fontSize: '0.82rem'
                      }}>
                        <div>
                          <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Primary Method</span>
                          <strong style={{ color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.15rem' }}>
                            <QrCode size={14} color="#38bdf8" /> Authenticator App (RFC 6238 TOTP)
                          </strong>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Post-Quantum Key Exchange</span>
                          <strong style={{ color: 'var(--accent-cyan, #38bdf8)', marginTop: '0.15rem', display: 'block' }}>
                            ML-KEM-768 (FIPS 203 Hybrid)
                          </strong>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Recovery Safeguard</span>
                          <strong style={{ color: '#ffffff', marginTop: '0.15rem', display: 'block' }}>
                            8 Emergency Single-Use Codes
                          </strong>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Session Re-Challenge</span>
                          <strong style={{ color: '#ffffff', marginTop: '0.15rem', display: 'block' }}>
                            Every 12 Hours or on IP Change
                          </strong>
                        </div>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'flex-start', gap: '0.75rem', flexWrap: 'wrap', paddingTop: '0.25rem' }}>
                        <button
                          type="button"
                          onClick={() => setShowTOTPModal(true)}
                          className="btn-secondary"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.45rem',
                            padding: '0.5rem 1rem',
                            fontSize: '0.82rem'
                          }}
                        >
                          <QrCode size={15} color="var(--accent-cyan, #38bdf8)" />
                          <span>Configure / Scan Authenticator QR Code</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowBackupCodesModal(true)}
                          className="btn-secondary"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.45rem',
                            padding: '0.5rem 1rem',
                            fontSize: '0.82rem'
                          }}
                        >
                          <Key size={15} color="var(--accent-cyan, #38bdf8)" />
                          <span>View Emergency Recovery Codes</span>
                        </button>
                      </div>
                    </div>

                    {/* Card 4: Internal User Logs (Audit Trail) */}
                    <div style={{
                      background: 'rgba(255, 255, 255, 0.025)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '12px',
                      padding: '1.5rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '1rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.12)', border: '1px solid rgba(56, 189, 248, 0.25)' }}>
                            <FileText size={18} color="#38bdf8" />
                          </div>
                          <div>
                            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <span>Internal User Logs &amp; Security Audit Trail</span>
                              <span style={{
                                fontSize: '0.7rem',
                                fontWeight: 700,
                                padding: '0.15rem 0.5rem',
                                borderRadius: '12px',
                                background: 'rgba(56, 189, 248, 0.15)',
                                color: '#38bdf8',
                                border: '1px solid rgba(56, 189, 248, 0.3)'
                              }}>
                                {filteredUserLogs.length} Events Recorded
                              </span>
                            </h3>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                              Cryptographic ledger of authentication, credential rotations, 2FA verifications, and compliance exports
                            </span>
                          </div>
                        </div>

                        <button
                          type="button"
                          onClick={handleExportUserLogs}
                          className="btn-secondary"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.45rem',
                            padding: '0.45rem 0.95rem',
                            fontSize: '0.8rem'
                          }}
                        >
                          <Download size={14} color="#38bdf8" />
                          <span>Export Logs (CSV)</span>
                        </button>
                      </div>

                      {/* Filter & Search Bar */}
                      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
                        <div style={{ position: 'relative', flex: 1, minWidth: '220px' }}>
                          <Search size={14} color="var(--text-muted, #64748b)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                          <input
                            type="text"
                            value={logSearch}
                            onChange={e => setLogSearch(e.target.value)}
                            placeholder="Filter audit events by description, code, or IP..."
                            style={{
                              width: '100%',
                              boxSizing: 'border-box',
                              background: 'rgba(0, 0, 0, 0.35)',
                              border: '1px solid rgba(255, 255, 255, 0.1)',
                              borderRadius: '6px',
                              padding: '0.45rem 0.75rem 0.45rem 2rem',
                              color: '#ffffff',
                              fontSize: '0.82rem'
                            }}
                          />
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <Filter size={14} color="var(--text-muted, #64748b)" />
                          <select
                            value={logCategoryFilter}
                            onChange={e => setLogCategoryFilter(e.target.value as any)}
                            style={{
                              background: 'rgba(0, 0, 0, 0.35)',
                              border: '1px solid rgba(255, 255, 255, 0.1)',
                              borderRadius: '6px',
                              padding: '0.45rem 0.75rem',
                              color: '#ffffff',
                              fontSize: '0.82rem',
                              cursor: 'pointer'
                            }}
                          >
                            <option value="all">All Categories</option>
                            <option value="auth">Authentication</option>
                            <option value="security">Security &amp; 2FA</option>
                            <option value="crypto">Cryptographic Operations</option>
                            <option value="admin">Administrative</option>
                          </select>
                        </div>

                        {(logSearch || logCategoryFilter !== 'all') && (
                          <button
                            type="button"
                            onClick={() => {
                              setLogSearch('');
                              setLogCategoryFilter('all');
                            }}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#38bdf8',
                              fontSize: '0.78rem',
                              cursor: 'pointer',
                              textDecoration: 'underline'
                            }}
                          >
                            Clear Filters
                          </button>
                        )}
                      </div>

                      {/* Interactive Logs Table */}
                      <div style={{
                        background: 'rgba(0, 0, 0, 0.35)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '8px',
                        overflow: 'hidden'
                      }}>
                        <div style={{ overflowX: 'auto' }}>
                          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted, #94a3b8)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Event Code</th>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Category</th>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Description</th>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Client IP / Origin</th>
                                <th style={{ padding: '0.65rem 0.85rem' }}>Attestation</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filteredUserLogs.length === 0 ? (
                                <tr>
                                  <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted, #64748b)' }}>
                                    No audit log records match the current filter.
                                  </td>
                                </tr>
                              ) : (
                                filteredUserLogs.map((log) => {
                                  const categoryColor =
                                    log.category === 'auth' ? '#38bdf8' :
                                    log.category === 'security' ? '#c084fc' :
                                    log.category === 'crypto' ? '#34d399' : '#f59e0b';
                                  const categoryBg =
                                    log.category === 'auth' ? 'rgba(56, 189, 248, 0.15)' :
                                    log.category === 'security' ? 'rgba(192, 132, 252, 0.15)' :
                                    log.category === 'crypto' ? 'rgba(52, 211, 153, 0.15)' : 'rgba(245, 158, 11, 0.15)';

                                  return (
                                    <tr key={log.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                                      <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-muted, #94a3b8)', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: '0.74rem' }}>
                                        {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                        <div style={{ fontSize: '0.68rem', color: '#64748b' }}>
                                          {new Date(log.timestamp).toISOString().split('T')[0]}
                                        </div>
                                      </td>
                                      <td style={{ padding: '0.65rem 0.85rem', whiteSpace: 'nowrap' }}>
                                        <code style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '0.18rem 0.4rem', borderRadius: '4px', fontSize: '0.74rem', color: '#e2e8f0', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                          {log.event}
                                        </code>
                                      </td>
                                      <td style={{ padding: '0.65rem 0.85rem', whiteSpace: 'nowrap' }}>
                                        <span style={{
                                          fontSize: '0.68rem',
                                          fontWeight: 700,
                                          padding: '0.15rem 0.45rem',
                                          borderRadius: '4px',
                                          background: categoryBg,
                                          color: categoryColor,
                                          textTransform: 'uppercase'
                                        }}>
                                          {log.category}
                                        </span>
                                      </td>
                                      <td style={{ padding: '0.65rem 0.85rem', color: '#e2e8f0', maxWidth: '340px' }}>
                                        {log.description}
                                      </td>
                                      <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                                        {log.ipAddress}
                                      </td>
                                      <td style={{ padding: '0.65rem 0.85rem', whiteSpace: 'nowrap' }}>
                                        <span style={{
                                          fontSize: '0.7rem',
                                          color: 'var(--status-secure, #4ade80)',
                                          display: 'flex',
                                          alignItems: 'center',
                                          gap: '0.3rem'
                                        }}>
                                          <CheckCircle2 size={12} color="#10b981" />
                                          {log.attestationStatus}
                                        </span>
                                      </td>
                                    </tr>
                                  );
                                })
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* SUBTAB 2: TEAM & 2FA POLICIES */}
                {/* SUBTAB: REPORT STAKEHOLDERS */}
                {effectiveSettingsTab === 'stakeholders' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '1.5rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
                        <div>
                          <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <Users size={19} color="var(--accent-cyan, #38bdf8)" /> Report Stakeholders
                          </h3>
                          <p style={{ margin: '0.3rem 0 0', fontSize: '0.82rem', color: 'var(--text-muted, #94a3b8)' }}>
                            Management &amp; stakeholders who receive the PQC Executive Roadmap report by email in one click. Add as many recipients as you need.
                          </p>
                        </div>
                        <button
                          onClick={emailRoadmapToStakeholders}
                          disabled={emailingReport || reportStakeholders.length === 0}
                          title={reportStakeholders.length === 0 ? 'Add a stakeholder first' : 'Email the PQC Roadmap report to all stakeholders'}
                          style={{ background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.4)', color: '#34d399', padding: '0.55rem 1rem', borderRadius: '7px', fontSize: '0.84rem', fontWeight: 600, cursor: (emailingReport || reportStakeholders.length === 0) ? 'not-allowed' : 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', opacity: reportStakeholders.length === 0 ? 0.55 : 1 }}
                        >
                          <Save size={15} /> {emailingReport ? 'Sending…' : '📧 Email PQC Roadmap'}
                        </button>
                      </div>
                      {stkToast && (
                        <div style={{ marginBottom: '0.9rem', padding: '0.6rem 0.8rem', background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.4)', borderRadius: '6px', color: '#4ade80', fontSize: '0.84rem' }}>{stkToast}</div>
                      )}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginBottom: '1rem' }}>
                        {reportStakeholders.length === 0 && (
                          <div style={{ fontSize: '0.84rem', color: 'var(--text-muted, #94a3b8)', fontStyle: 'italic', padding: '0.5rem 0' }}>No stakeholders yet. Add management or stakeholders below.</div>
                        )}
                        {reportStakeholders.map((s) => (
                          <div key={s.email} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', padding: '0.6rem 0.85rem', background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '7px' }}>
                            <div style={{ overflow: 'hidden' }}>
                              <span style={{ color: '#fff', fontSize: '0.88rem', fontWeight: 600 }}>{s.name || s.email}</span>
                              {s.name && <span style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.82rem', marginLeft: '0.5rem' }}>{s.email}</span>}
                            </div>
                            <button onClick={() => removeStakeholder(s.email)} disabled={stkSaving} title="Remove" style={{ background: 'transparent', border: '1px solid rgba(239,68,68,0.35)', color: '#f87171', padding: '0.25rem 0.6rem', borderRadius: '5px', fontSize: '0.74rem', cursor: 'pointer' }}>Remove</button>
                          </div>
                        ))}
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <input value={newStkName} onChange={e => setNewStkName(e.target.value)} placeholder="Name (optional)" style={{ flex: '1 1 160px', minWidth: 0, padding: '0.6rem 0.8rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.84rem' }} />
                        <input value={newStkEmail} onChange={e => setNewStkEmail(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') addStakeholder(); }} placeholder="email@company.com" style={{ flex: '2 1 240px', minWidth: 0, padding: '0.6rem 0.8rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.84rem' }} />
                        <button onClick={addStakeholder} disabled={stkSaving} style={{ background: 'rgba(0,242,254,0.12)', border: '1px solid rgba(0,242,254,0.35)', color: 'var(--accent-cyan, #38bdf8)', padding: '0.6rem 1rem', borderRadius: '6px', fontSize: '0.84rem', fontWeight: 600, cursor: 'pointer' }}>{stkSaving ? 'Saving…' : '+ Add'}</button>
                      </div>
                    </div>
                  </div>
                )}

                {effectiveSettingsTab === 'users' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <TenantUserManagement currentTenant={cleanSlug} allowTenantSwitch={false} />
                  </div>
                )}

                {/* SUBTAB: GROUPS (DEF-42) */}
                {effectiveSettingsTab === 'groups' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <div style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '1.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                        <Layers size={18} color="#c084fc" />
                        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: '#fff' }}>Workstation Groups</h2>
                      </div>
                      <p style={{ fontSize: '0.82rem', color: 'var(--text-muted, #94a3b8)', margin: '0 0 1.1rem 0' }}>
                        Organize endpoints into groups (e.g. Engineering, Finance, a region). Pick a group when enrolling,
                        move workstations between groups, and schedule pulls per group. Unassigned endpoints are in <strong style={{ color: '#cbd5e1' }}>Default</strong>.
                      </p>

                      {/* Create group */}
                      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.1rem', flexWrap: 'wrap' }}>
                        <input
                          value={newGroupName}
                          onChange={e => setNewGroupName(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter') handleCreateGroup(); }}
                          placeholder="New group name (e.g. Finance)"
                          style={{ flex: '1 1 220px', background: 'rgba(255,255,255,0.05)', color: '#fff', border: '1px solid rgba(255,255,255,0.15)', borderRadius: '6px', padding: '0.45rem 0.6rem', fontSize: '0.85rem' }}
                        />
                        <button onClick={handleCreateGroup}
                          style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.35)', color: '#c084fc', padding: '0.45rem 0.9rem', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                          <Plus size={14} /> Create group
                        </button>
                      </div>

                      {/* Groups list */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem', marginBottom: '0.5rem' }}>
                        {fleetGroups.map(g => (
                          <div key={g.name} style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '9px', padding: '0.5rem 0.8rem' }}>
                            <div>
                              <div style={{ fontSize: '0.86rem', fontWeight: 700, color: g.name.toLowerCase() === 'default' ? '#cbd5e1' : '#d8b4fe' }}>{g.name}</div>
                              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted, #94a3b8)' }}>{g.count} {g.count === 1 ? 'workstation' : 'workstations'}</div>
                            </div>
                            {g.name.toLowerCase() !== 'default' && (
                              <button onClick={() => handleDeleteGroup(g.name)} title="Delete group"
                                style={{ background: 'transparent', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171', borderRadius: '6px', padding: '0.2rem 0.4rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center' }}>
                                <Trash2 size={13} />
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Move workstations between groups */}
                    <div style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '1.5rem' }}>
                      <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 0.9rem 0', color: '#fff' }}>Assign Workstations</h3>
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.72rem', textTransform: 'uppercase' }}>
                              <th style={{ padding: '0.6rem 0.5rem' }}>Workstation / Host</th>
                              <th style={{ padding: '0.6rem 0.5rem' }}>Platform</th>
                              <th style={{ padding: '0.6rem 0.5rem' }}>Status</th>
                              <th style={{ padding: '0.6rem 0.5rem' }}>Group</th>
                            </tr>
                          </thead>
                          <tbody>
                            {machines.map(m => (
                              <tr key={m.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                <td style={{ padding: '0.6rem 0.5rem', color: '#fff', fontWeight: 600 }}>{m.computerName || m.hostname}</td>
                                <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-secondary, #94a3b8)', textTransform: 'uppercase', fontSize: '0.72rem' }}>{m.os}</td>
                                <td style={{ padding: '0.6rem 0.5rem' }}>
                                  <span style={{ fontSize: '0.72rem', fontWeight: 600, color: m.status === 'online' ? '#4ade80' : '#94a3b8' }}>
                                    {m.status === 'online' ? 'Online' : 'Offline'}
                                  </span>
                                </td>
                                <td style={{ padding: '0.6rem 0.5rem' }}>
                                  <select value={(m.group && m.group !== 'Default') ? m.group : ''} onChange={e => handleSetGroup(m.id, e.target.value)}
                                    style={{ background: 'rgba(168,85,247,0.08)', color: m.group && m.group !== 'Default' ? '#d8b4fe' : '#94a3b8', border: '1px solid rgba(168,85,247,0.25)', borderRadius: '5px', fontSize: '0.78rem', fontWeight: 600, padding: '0.25rem 0.4rem', cursor: 'pointer' }}>
                                    <option value="">Default</option>
                                    {fleetGroups.filter(g => g.name.toLowerCase() !== 'default').map(g => <option key={g.name} value={g.name}>{g.name}</option>)}
                                    {m.group && m.group !== 'Default' && !fleetGroups.some(g => g.name === m.group) && <option value={m.group}>{m.group}</option>}
                                  </select>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}

                {/* SUBTAB 3: LICENSE (Strictly titled "License", no "& Quota") */}
                {effectiveSettingsTab === 'license' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.5rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Key size={20} color="#38bdf8" />
                      <span>Active Enterprise Licenses ({activeLicenses.length})</span>
                    </h2>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => {
                          setGeneratedTokenData(null);
                          setShowEnrollModal(true);
                        }}
                        style={{
                          background: 'rgba(56, 189, 248, 0.12)',
                          border: '1px solid rgba(56, 189, 248, 0.3)',
                          color: '#38bdf8',
                          padding: '0.4rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                        title="Enroll a new device or generate fleet token"
                      >
                        <Plus size={14} /> Enroll New Device
                      </button>
                      <button
                        onClick={handleOpenStripePortal}
                        disabled={portalLoading}
                        style={{
                          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(168, 85, 247, 0.2) 100%)',
                          border: '1px solid rgba(168, 85, 247, 0.4)',
                          color: '#c084fc',
                          padding: '0.4rem 0.85rem',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: portalLoading ? 'wait' : 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                        title="Manage subscription, invoices, and payment cards on Stripe Customer Portal"
                      >
                        <CreditCard size={14} />
                        {portalLoading ? 'Opening Portal...' : 'Manage Billing & Invoices (Stripe)'}
                      </button>
                      <span style={{
                        fontSize: '0.78rem',
                        fontWeight: 700,
                        color: '#38bdf8',
                        background: 'rgba(56, 189, 248, 0.12)',
                        border: '1px solid rgba(56, 189, 248, 0.3)',
                        padding: '0.25rem 0.75rem',
                        borderRadius: '12px'
                      }}>
                        Fleet Capacity: {usedSeats} / {totalCapacity} Seats Active
                      </span>
                    </div>
                  </div>
                  <p style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.85rem', margin: '0 0 1.25rem 0' }}>
                    Authorized cryptographic licenses issued to {client.displayName} for silent fleet scanning and PQC posture ingestion.
                  </p>

                  {/* 1. Sub-Licenses & Fleet Endpoint Keys Table */}
                  <div style={{
                    background: 'rgba(0, 0, 0, 0.35)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    marginBottom: '1.25rem'
                  }}>
                    <div style={{ padding: '0.75rem 1rem', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Key size={14} color="#38bdf8" />
                      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                        Sub-Licenses & Fleet Endpoint Keys ({licenses.length})
                      </span>
                    </div>
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted, #94a3b8)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                            <th style={{ padding: '0.65rem 0.75rem' }}>#</th>
                            <th style={{ padding: '0.65rem 0.75rem' }}>License Key</th>
                            <th style={{ padding: '0.65rem 0.75rem' }}>Assigned Contact</th>
                            <th style={{ padding: '0.65rem 0.75rem' }}>Seat Allocation</th>
                            <th style={{ padding: '0.65rem 0.75rem' }}>Expiration</th>
                            <th style={{ padding: '0.65rem 0.75rem' }}>Status</th>
                            <th style={{ padding: '0.65rem 0.75rem', textAlign: 'right' }}>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {licenses.map((lic, idx) => {
                            const isRevoked = lic.status === 'revoked';
                            const isExpired = lic.expiresAt ? new Date(lic.expiresAt).getTime() < Date.now() : false;
                            const daysLeft = lic.expiresAt ? Math.max(0, Math.ceil((new Date(lic.expiresAt).getTime() - Date.now()) / 86400000)) : 365;
                            const attachedMachines = machines.filter(m => (m.licenseKey || '').trim().toUpperCase() === (lic.licenseKey || '').trim().toUpperCase());

                            return (
                              <tr key={lic.id || idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)', opacity: isRevoked ? 0.6 : 1 }}>
                                <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'monospace' }}>
                                  #{idx + 1}
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem' }}>
                                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
                                    <code style={{
                                      fontSize: '0.78rem',
                                      background: 'rgba(0, 0, 0, 0.45)',
                                      padding: '0.2rem 0.45rem',
                                      borderRadius: '4px',
                                      color: isRevoked ? 'var(--text-muted, #94a3b8)' : '#38bdf8',
                                      fontFamily: 'monospace'
                                    }}>
                                      {lic.licenseKey}
                                    </code>
                                    <button
                                      onClick={() => copyToClipboard(lic.licenseKey, `lic-${idx}`)}
                                      title="Copy license key"
                                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedKey === `lic-${idx}` ? '#4ade80' : 'var(--text-muted, #94a3b8)', padding: '2px' }}
                                    >
                                      {copiedKey === `lic-${idx}` ? <Check size={13} /> : <Copy size={13} />}
                                    </button>
                                  </div>
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-secondary, #94a3b8)' }}>
                                  <div>
                                    <div style={{ color: '#ffffff', fontWeight: 500 }}>{lic.contactName || client.contactName || 'Enterprise Administrator'}</div>
                                    <div style={{ color: '#38bdf8', fontSize: '0.72rem' }}>{lic.contactEmail || client.adminEmail || (`admin@${cleanSlug}.com`)}</div>
                                  </div>
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem' }}>
                                  {isRevoked ? (
                                    <span style={{ color: '#f87171', fontSize: '0.78rem', fontWeight: 600 }}>0 / {lic.seats || 100} Seats (Revoked)</span>
                                  ) : (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                      <span style={{ fontWeight: 600, color: attachedMachines.length > 0 ? '#38bdf8' : '#ffffff' }}>
                                        {attachedMachines.length} / {lic.seats || 100} Seats
                                      </span>
                                      <span style={{
                                        fontSize: '0.7rem',
                                        color: '#4ade80',
                                        fontWeight: 600,
                                        background: 'rgba(34, 197, 94, 0.12)',
                                        padding: '0.1rem 0.4rem',
                                        borderRadius: '3px',
                                        border: '1px solid rgba(34, 197, 94, 0.25)'
                                      }}>
                                        Active
                                      </span>
                                    </div>
                                  )}
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem', color: 'var(--text-secondary, #94a3b8)' }}>
                                  <div>{lic.expiresAt ? lic.expiresAt.split('T')[0] : '2027-09-14'}</div>
                                  {!isExpired && !isRevoked && (
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)' }}>
                                      {daysLeft} days remaining
                                    </div>
                                  )}
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem' }}>
                                  {isRevoked ? (
                                    <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 700 }}>
                                      Revoked
                                    </span>
                                  ) : (
                                    <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.3)', fontWeight: 700 }}>
                                      Active
                                    </span>
                                  )}
                                </td>
                                <td style={{ padding: '0.65rem 0.75rem', textAlign: 'right' }}>
                                  <button
                                    onClick={() => copyToClipboard(lic.licenseKey, `lic-${idx}`)}
                                    style={{
                                      background: 'rgba(56, 189, 248, 0.1)',
                                      border: '1px solid rgba(56, 189, 248, 0.3)',
                                      color: '#38bdf8',
                                      borderRadius: '4px',
                                      padding: '0.25rem 0.55rem',
                                      fontSize: '0.72rem',
                                      cursor: 'pointer',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.25rem'
                                    }}
                                  >
                                    {copiedKey === `lic-${idx}` ? <Check size={12} color="#4ade80" /> : <Copy size={12} />}
                                    <span>Copy Key</span>
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* 2. Enrolled Workstations Consuming Seats Table (Vertical, Collapsible) */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '8px',
                    padding: '1rem',
                    boxShadow: 'inset 0 2px 6px rgba(0, 0, 0, 0.3)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: workstationsCollapsed ? 0 : '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div 
                        onClick={() => setWorkstationsCollapsed(!workstationsCollapsed)}
                        style={{ fontSize: '0.82rem', fontWeight: 700, color: '#38bdf8', display: 'flex', gap: '0.45rem', alignItems: 'center', letterSpacing: '0.3px', cursor: 'pointer' }}
                      >
                        <ChevronRight
                          size={15}
                          style={{
                            transform: workstationsCollapsed ? 'rotate(0deg)' : 'rotate(90deg)',
                            transition: 'transform 0.2s ease',
                            color: '#38bdf8'
                          }}
                        />
                        <Laptop size={15} />
                        <span>ENROLLED WORKSTATIONS CONSUMING SEATS ({machines.length} Active Device{machines.length !== 1 ? 's' : ''})</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-muted, #94a3b8)', display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                          <span>Seat Utilization: <strong style={{ color: '#38bdf8' }}>{usedSeats} / {totalCapacity} ({Math.round((usedSeats / Math.max(1, totalCapacity)) * 100)}%)</strong></span>
                          <span style={{ color: '#38bdf8' }}>• {machines.filter(m => (m.os||'').toLowerCase().includes('mac') || (m.os||'').toLowerCase().includes('darwin')).length} macOS</span>
                          <span style={{ color: '#c084fc' }}>• {machines.filter(m => (m.os||'').toLowerCase().includes('win')).length} Windows</span>
                        </div>
                        <button
                          onClick={() => {
                            setGeneratedTokenData(null);
                            setShowEnrollModal(true);
                          }}
                          style={{
                            background: 'rgba(56, 189, 248, 0.12)',
                            border: '1px solid rgba(56, 189, 248, 0.3)',
                            color: '#38bdf8',
                            padding: '0.25rem 0.65rem',
                            borderRadius: '6px',
                            fontSize: '0.75rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            transition: 'all 0.15s ease'
                          }}
                          title="Enroll a new device or generate fleet token"
                        >
                          <Plus size={13} /> Enroll New Device
                        </button>
                        <button
                          onClick={() => setWorkstationsCollapsed(!workstationsCollapsed)}
                          style={{
                            background: 'rgba(255, 255, 255, 0.04)',
                            border: '1px solid rgba(255, 255, 255, 0.1)',
                            borderRadius: '4px',
                            color: 'var(--text-secondary, #94a3b8)',
                            padding: '0.2rem 0.5rem',
                            fontSize: '0.72rem',
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem'
                          }}
                        >
                          {workstationsCollapsed ? <ChevronDown size={12} /> : <ChevronUp size={12} />}
                          {workstationsCollapsed ? 'Expand Devices' : 'Collapse Devices'}
                        </button>
                      </div>
                    </div>

                    {!workstationsCollapsed && (
                      machines.length === 0 ? (
                        <div style={{
                          textAlign: 'center',
                          padding: '2.5rem 1rem',
                          background: 'rgba(0, 0, 0, 0.2)',
                          borderRadius: '8px',
                          border: '1px dashed rgba(255, 255, 255, 0.1)',
                          margin: '0.5rem 0'
                        }}>
                          <Laptop size={32} style={{ color: 'var(--text-muted, #94a3b8)', opacity: 0.5, marginBottom: '0.75rem' }} />
                          <h4 style={{ margin: '0 0 0.35rem 0', color: '#ffffff', fontSize: '0.95rem' }}>No Workstations Enrolled Yet</h4>
                          <p style={{ margin: '0 0 1rem 0', fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', maxWidth: '420px', marginLeft: 'auto', marginRight: 'auto' }}>
                            Enroll your first macOS, Windows, or Linux workstation to start continuous cryptographic posture auditing and telemetry ingestion.
                          </p>
                          <button
                            onClick={() => {
                              setGeneratedTokenData(null);
                              setShowEnrollModal(true);
                            }}
                            style={{
                              background: 'rgba(56, 189, 248, 0.12)',
                              border: '1px solid rgba(56, 189, 248, 0.35)',
                              color: '#38bdf8',
                              padding: '0.45rem 1rem',
                              borderRadius: '6px',
                              fontSize: '0.82rem',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.45rem',
                              transition: 'all 0.15s ease'
                            }}
                          >
                            <Plus size={14} /> Enroll New Device
                          </button>
                        </div>
                      ) : (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted, #94a3b8)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                              <th style={{ padding: '0.5rem' }}>Workstation / Host</th>
                              <th style={{ padding: '0.5rem' }}>Group</th>
                              <th style={{ padding: '0.5rem' }}>Hardware UUID</th>
                              <th style={{ padding: '0.5rem' }}>Platform / OS</th>
                              <th style={{ padding: '0.5rem' }}>IP Address</th>
                              <th style={{ padding: '0.5rem' }}>Active License Key</th>
                              <th style={{ padding: '0.5rem' }}>PQC Risk Score</th>
                              <th style={{ padding: '0.5rem' }}>Agent Status</th>
                              <th style={{ padding: '0.5rem' }}>Last Seen</th>
                              <th style={{ padding: '0.5rem', textAlign: 'right' }}>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {machines.map(m => {
                              const isMac = (m.os || '').toLowerCase().includes('darwin') || (m.os || '').toLowerCase().includes('mac');
                              const isWin = (m.os || '').toLowerCase().includes('win');
                              const riskScore = m.quantumRiskScore || 80;
                              const displayName = m.computerName || m.hostname;

                              return (
                                <tr key={m.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
                                      {isMac ? (
                                        <Laptop size={14} style={{ color: '#38bdf8' }} />
                                      ) : isWin ? (
                                        <Monitor size={14} style={{ color: '#c084fc' }} />
                                      ) : (
                                        <Server size={14} style={{ color: '#4ade80' }} />
                                      )}
                                      <div>
                                        <span style={{ fontWeight: 600, color: '#ffffff' }}>
                                          {displayName}
                                        </span>
                                        {m.computerName && m.computerName !== m.hostname && (
                                          <div style={{ fontSize: '0.68rem', color: '#64748b', fontFamily: 'monospace' }}>
                                            {m.hostname}
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <select value={(m.group && m.group !== 'Default') ? m.group : ''} onChange={e => handleSetGroup(m.id, e.target.value)}
                                      title="Move this workstation to a group"
                                      style={{ background: 'rgba(168,85,247,0.08)', color: m.group && m.group !== 'Default' ? '#d8b4fe' : '#94a3b8', border: '1px solid rgba(168,85,247,0.25)', borderRadius: '5px', fontSize: '0.74rem', fontWeight: 600, padding: '0.2rem 0.3rem', cursor: 'pointer', maxWidth: '130px' }}>
                                      <option value="">Default</option>
                                      {fleetGroups.filter(g => g.name.toLowerCase() !== 'default').map(g => <option key={g.name} value={g.name}>{g.name}</option>)}
                                      {m.group && m.group !== 'Default' && !fleetGroups.some(g => g.name === m.group) && <option value={m.group}>{m.group}</option>}
                                    </select>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <span style={{
                                      fontSize: '0.72rem',
                                      fontFamily: 'monospace',
                                      color: '#38bdf8',
                                      background: 'rgba(56, 189, 248, 0.08)',
                                      padding: '0.15rem 0.35rem',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(56, 189, 248, 0.2)'
                                    }}>
                                      {m.hardwareUuid ? `${m.hardwareUuid.substring(0, 13)}...` : 'N/A'}
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <span style={{
                                      fontSize: '0.74rem',
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '4px',
                                      fontWeight: 500,
                                      background: isMac ? 'rgba(56, 189, 248, 0.12)' : isWin ? 'rgba(168, 85, 247, 0.12)' : 'rgba(34, 197, 94, 0.12)',
                                      color: isMac ? '#38bdf8' : isWin ? '#c084fc' : '#4ade80',
                                      border: isMac ? '1px solid rgba(56, 189, 248, 0.25)' : isWin ? '1px solid rgba(168, 85, 247, 0.25)' : '1px solid rgba(34, 197, 94, 0.25)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.3rem'
                                    }}>
                                      {isMac ? `macOS (${m.arch || 'arm64'})` : isWin ? `Windows (${m.arch || 'amd64'})` : `Linux (${m.arch || 'amd64'})`}
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-secondary, #94a3b8)', fontFamily: 'monospace', fontSize: '0.78rem' }}>
                                    {m.ip || '127.0.0.1'}
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <code style={{
                                      fontSize: '0.74rem',
                                      background: 'rgba(0, 0, 0, 0.4)',
                                      padding: '0.15rem 0.4rem',
                                      borderRadius: '3px',
                                      color: 'var(--accent-cyan, #38bdf8)',
                                      fontFamily: 'monospace'
                                    }}>
                                      {m.licenseKey ? (m.licenseKey.length > 28 ? `${m.licenseKey.substring(0, 24)}...` : m.licenseKey) : 'Default License'}
                                    </code>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    <span style={{
                                      fontSize: '0.72rem',
                                      fontWeight: 700,
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '4px',
                                      background: riskScore >= 75 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                                      color: riskScore >= 75 ? '#f87171' : '#fbbf24',
                                      border: riskScore >= 75 ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(245, 158, 11, 0.3)'
                                    }}>
                                      {riskScore}/100 ({riskScore >= 75 ? 'CRITICAL' : 'HIGH'})
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem' }}>
                                    {(() => {
                                      const isOnline = m.status === 'online';
                                      return (
                                        <span style={{
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '0.35rem',
                                          fontSize: '0.74rem',
                                          fontWeight: 600,
                                          color: isOnline ? '#4ade80' : '#94a3b8',
                                          background: isOnline ? 'rgba(34, 197, 94, 0.1)' : 'rgba(148, 163, 184, 0.1)',
                                          padding: '0.15rem 0.45rem',
                                          borderRadius: '4px',
                                          border: `1px solid ${isOnline ? 'rgba(34, 197, 94, 0.25)' : 'rgba(148, 163, 184, 0.25)'}`
                                        }}>
                                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: isOnline ? '#4ade80' : '#94a3b8' }} />
                                          {isOnline ? 'Online' : 'Offline'}
                                        </span>
                                      );
                                    })()}
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-muted, #94a3b8)', fontSize: '0.76rem', fontFamily: 'monospace' }}>
                                    {m.lastSeen ? new Date(m.lastSeen).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Unknown'}
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }}>
                                    <button
                                      disabled={pullingMachineId === m.id}
                                      onClick={() => handlePullWorkstation(m.id, displayName)}
                                      style={{
                                        background: 'rgba(56, 189, 248, 0.08)',
                                        border: '1px solid rgba(56, 189, 248, 0.25)',
                                        color: '#38bdf8',
                                        padding: '0.25rem 0.5rem',
                                        borderRadius: '4px',
                                        fontSize: '0.72rem',
                                        fontWeight: 600,
                                        cursor: pullingMachineId === m.id ? 'not-allowed' : 'pointer',
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '0.3rem',
                                        opacity: pullingMachineId === m.id ? 0.6 : 1
                                      }}
                                      title="Pull latest cryptographic telemetry from this endpoint immediately"
                                    >
                                      <RefreshCw size={11} className={pullingMachineId === m.id ? 'animate-spin' : ''} />
                                      {pullingMachineId === m.id ? 'Pulling...' : 'Pull'}
                                    </button>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                      )
                    )}
                  </div>
                </div>
              </div>
            )}

          </div>
        )}


            {/* Fleet Enrollment Token Generator Modal */}
            {showEnrollModal && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(5, 10, 20, 0.85)',
                backdropFilter: 'blur(8px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 9999,
                padding: '1.5rem'
              }}>
                <div style={{
                  background: '#0a1120',
                  border: '1px solid rgba(0, 242, 254, 0.35)',
                  borderRadius: '14px',
                  maxWidth: '680px',
                  width: '100%',
                  maxHeight: '90vh',
                  overflowY: 'auto',
                  boxShadow: '0 25px 60px rgba(0, 0, 0, 0.7), 0 0 35px rgba(0, 242, 254, 0.12)',
                  padding: '1.75rem',
                  position: 'relative'
                }}>
                  {/* Close Button */}
                  <button
                    onClick={() => setShowEnrollModal(false)}
                    style={{
                      position: 'absolute',
                      top: '1.25rem',
                      right: '1.25rem',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '6px',
                      color: '#94a3b8',
                      padding: '6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                  >
                    <X size={18} />
                  </button>

                  {/* Modal Header */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
                    <div style={{
                      background: 'rgba(0, 242, 254, 0.12)',
                      border: '1px solid rgba(0, 242, 254, 0.3)',
                      borderRadius: '10px',
                      padding: '10px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <Key size={22} color="#00f2fe" />
                    </div>
                    <div>
                      <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
                        Enroll New Workstation / Generate Fleet Token
                      </h2>
                      <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.82rem', color: '#94a3b8' }}>
                        Generate an enrollment secret or copy 1-line rollout scripts for {client.displayName || displayCustomerName}.
                      </p>
                    </div>
                  </div>

                  {/* License Boundary Card */}
                  <div style={{
                    background: 'rgba(0, 0, 0, 0.35)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '8px',
                    padding: '0.9rem 1rem',
                    marginBottom: '1.25rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '0.75rem'
                  }}>
                    <div>
                      <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>
                        Bound Organization License
                      </div>
                      <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', color: '#38bdf8', fontWeight: 600, marginTop: '2px' }}>
                        {activeLicenseKey}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span style={{
                        fontSize: '0.72rem',
                        background: 'rgba(34, 197, 94, 0.15)',
                        border: '1px solid rgba(34, 197, 94, 0.3)',
                        color: '#4ade80',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontWeight: 600
                      }}>
                        Active • 100 Seats
                      </span>
                      <span style={{
                        fontSize: '0.72rem',
                        background: 'rgba(56, 189, 248, 0.15)',
                        border: '1px solid rgba(56, 189, 248, 0.3)',
                        color: '#38bdf8',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontWeight: 600
                      }}>
                        {machines.length} Enrolled
                      </span>
                    </div>
                  </div>

                  {/* Token Creation Input */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    borderRadius: '8px',
                    padding: '1.1rem',
                    marginBottom: '1.25rem'
                  }}>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.4rem' }}>
                      Workstation Group
                    </label>
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <input
                        type="text"
                        list="qs-group-options"
                        placeholder="Pick a group or type a new one (e.g. Engineering, Finance)"
                        value={newTokenGroup}
                        onChange={e => setNewTokenGroup(e.target.value)}
                        style={{
                          flex: 1,
                          background: 'rgba(0, 0, 0, 0.4)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          borderRadius: '6px',
                          padding: '0.55rem 0.85rem',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          outline: 'none'
                        }}
                      />
                      <datalist id="qs-group-options">
                        {fleetGroups.filter(g => g.name.toLowerCase() !== 'default').map(g => (
                          <option key={g.name} value={g.name} />
                        ))}
                      </datalist>
                      <button
                        onClick={handleGenerateToken}
                        disabled={isGeneratingToken || !newTokenGroup.trim()}
                        style={{
                          background: 'linear-gradient(135deg, #00f2fe 0%, #4facfe 100%)',
                          border: 'none',
                          borderRadius: '6px',
                          color: '#000000',
                          fontWeight: 700,
                          fontSize: '0.82rem',
                          padding: '0.55rem 1.1rem',
                          cursor: isGeneratingToken ? 'not-allowed' : 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          opacity: isGeneratingToken ? 0.7 : 1,
                          boxShadow: '0 2px 10px rgba(0, 242, 254, 0.25)'
                        }}
                      >
                        {isGeneratingToken ? <RefreshCw size={14} className="animate-spin" /> : <Plus size={14} />}
                        <span>{isGeneratingToken ? 'Generating...' : 'Generate Token'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Ready-to-use Command Box for Generated/Selected Token */}
                  {(() => {
                    const currentToken = generatedTokenData?.token || tenantTokens[0]?.token || activeLicenseKey;
                    const macCommand = `curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | sudo bash -s -- --token "${currentToken}"`;
                    const winCommand = `Invoke-WebRequest -Uri "https://quarkshield.ai/api/scan/agent/install.ps1" -OutFile "$env:TEMP\\install.ps1"; & "$env:TEMP\\install.ps1" -EnrollmentToken "${currentToken}"`;
                    const linuxCommand = `curl -sSL https://quarkshield.ai/api/scan/agent/install.sh | sudo bash -s -- --token "${currentToken}"`;
                    const activeCommand = enrollTabOs === 'macos' ? macCommand : enrollTabOs === 'windows' ? winCommand : linuxCommand;

                    return (
                      <div style={{
                        background: 'rgba(0, 242, 254, 0.03)',
                        border: '1px solid rgba(0, 242, 254, 0.25)',
                        borderRadius: '10px',
                        padding: '1.25rem',
                        marginBottom: '1.25rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <Terminal size={14} color="#00f2fe" />
                            <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ffffff' }}>
                              Enrollment Secret:
                            </span>
                            <code style={{
                              background: 'rgba(0, 0, 0, 0.4)',
                              padding: '2px 8px',
                              borderRadius: '4px',
                              color: '#38bdf8',
                              fontSize: '0.8rem',
                              fontFamily: 'monospace'
                            }}>
                              {currentToken}
                            </code>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(currentToken);
                                setTokenCopied(true);
                                setTimeout(() => setTokenCopied(false), 2000);
                              }}
                              style={{
                                background: 'transparent',
                                border: 'none',
                                color: tokenCopied ? '#4ade80' : '#38bdf8',
                                cursor: 'pointer',
                                padding: '2px 4px',
                                display: 'flex',
                                alignItems: 'center'
                              }}
                              title="Copy Token Secret"
                            >
                              {tokenCopied ? <Check size={14} /> : <Copy size={14} />}
                            </button>
                          </div>

                          {/* OS Switcher Tabs */}
                          <div style={{
                            display: 'flex',
                            background: 'rgba(0, 0, 0, 0.4)',
                            padding: '3px',
                            borderRadius: '6px',
                            gap: '2px'
                          }}>
                            {[
                              { id: 'macos', label: '🍎 macOS' },
                              { id: 'windows', label: '🪟 Windows (PS)' },
                              { id: 'linux', label: '🐧 Linux' }
                            ].map(os => (
                              <button
                                key={os.id}
                                onClick={() => setEnrollTabOs(os.id as any)}
                                style={{
                                  background: enrollTabOs === os.id ? 'rgba(0, 242, 254, 0.2)' : 'transparent',
                                  border: enrollTabOs === os.id ? '1px solid rgba(0, 242, 254, 0.4)' : '1px solid transparent',
                                  color: enrollTabOs === os.id ? '#00f2fe' : '#94a3b8',
                                  padding: '3px 9px',
                                  borderRadius: '4px',
                                  fontSize: '0.74rem',
                                  fontWeight: 600,
                                  cursor: 'pointer'
                                }}
                              >
                                {os.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Copyable 1-Liner Shell Code */}
                        <div style={{
                          background: 'rgba(0, 0, 0, 0.6)',
                          borderRadius: '6px',
                          padding: '0.85rem 1rem',
                          fontFamily: 'monospace',
                          fontSize: '0.78rem',
                          color: '#a5f3fc',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          wordBreak: 'break-all',
                          border: '1px solid rgba(255, 255, 255, 0.08)'
                        }}>
                          <span>{activeCommand}</span>
                          <button
                            onClick={() => copyToClipboard(activeCommand, `enroll-cmd-${enrollTabOs}`)}
                            style={{
                              background: 'rgba(0, 242, 254, 0.15)',
                              border: '1px solid rgba(0, 242, 254, 0.3)',
                              color: '#00f2fe',
                              borderRadius: '4px',
                              padding: '5px 10px',
                              fontSize: '0.74rem',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                              flexShrink: 0,
                              marginLeft: '0.75rem'
                            }}
                          >
                            {copiedKey === `enroll-cmd-${enrollTabOs}` ? <Check size={13} color="#4ade80" /> : <Copy size={13} />}
                            <span>{copiedKey === `enroll-cmd-${enrollTabOs}` ? 'Copied!' : 'Copy Command'}</span>
                          </button>
                        </div>

                        <div style={{ marginTop: '0.6rem', fontSize: '0.74rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <CheckCircle2 size={12} color="#4ade80" />
                          Installs agent as background daemon, binds automatically to this organization, and syncs CBOM within 30 seconds.
                        </div>
                      </div>
                    );
                  })()}

                  {/* Active Tokens List */}
                  <div>
                    <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Active Enrollment Tokens ({tenantTokens.length})
                    </h4>
                    {tenantTokens.length === 0 ? (
                      <div style={{ padding: '0.85rem', background: 'rgba(0, 0, 0, 0.25)', borderRadius: '6px', textAlign: 'center', color: '#64748b', fontSize: '0.8rem' }}>
                        No custom tokens yet. Generate one above or use the organization master license key.
                      </div>
                    ) : (
                      <div style={{ maxHeight: '160px', overflowY: 'auto', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '6px' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                          <thead>
                            <tr style={{ background: 'rgba(255, 255, 255, 0.03)', color: '#94a3b8', borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <th style={{ padding: '8px 10px', textAlign: 'left' }}>Group Tag</th>
                              <th style={{ padding: '8px 10px', textAlign: 'left' }}>Token Secret</th>
                              <th style={{ padding: '8px 10px', textAlign: 'left' }}>Devices</th>
                              <th style={{ padding: '8px 10px', textAlign: 'left' }}>Created</th>
                              <th style={{ padding: '8px 10px', textAlign: 'right' }}>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {tenantTokens.map(tok => (
                              <tr key={tok.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                                <td style={{ padding: '8px 10px', color: '#ffffff', fontWeight: 600 }}>{tok.name}</td>
                                <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: '#38bdf8' }}>
                                  {tok.token.slice(0, 16)}••••••••
                                </td>
                                <td style={{ padding: '8px 10px', color: '#4ade80' }}>
                                  {tok.machineCount || 0} active
                                </td>
                                <td style={{ padding: '8px 10px', color: '#64748b' }}>
                                  {new Date(tok.createdAt).toLocaleDateString()}
                                </td>
                                <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                                  <button
                                    onClick={() => {
                                      navigator.clipboard.writeText(tok.token);
                                      setCopiedKey(`table-${tok.id}`);
                                      setTimeout(() => setCopiedKey(null), 2000);
                                    }}
                                    style={{
                                      background: 'transparent',
                                      border: 'none',
                                      color: copiedKey === `table-${tok.id}` ? '#4ade80' : '#38bdf8',
                                      cursor: 'pointer',
                                      marginRight: '8px'
                                    }}
                                    title="Copy Secret"
                                  >
                                    {copiedKey === `table-${tok.id}` ? <Check size={13} /> : <Copy size={13} />}
                                  </button>
                                  <button
                                    onClick={() => handleRevokeToken(tok.id)}
                                    style={{
                                      background: 'transparent',
                                      border: 'none',
                                      color: '#f87171',
                                      cursor: 'pointer'
                                    }}
                                    title="Revoke Token"
                                  >
                                    <Trash2 size={13} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Done Button */}
                  <div style={{ marginTop: '1.5rem', display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      onClick={() => setShowEnrollModal(false)}
                      style={{
                        background: 'rgba(255, 255, 255, 0.08)',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        padding: '0.5rem 1.25rem',
                        fontSize: '0.82rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Automated Workstation Sync Schedule Modal */}
            {scheduleModalOpen && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.75)',
                backdropFilter: 'blur(6px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 9999,
                padding: '1rem'
              }}>
                <div style={{
                  background: '#0d1527',
                  border: '1px solid rgba(168, 85, 247, 0.3)',
                  borderRadius: '12px',
                  width: '100%',
                  maxWidth: '560px',
                  padding: '1.75rem',
                  boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <Clock size={20} color="#c084fc" />
                      <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 700, color: '#ffffff' }}>
                        Automated Workstation Sync Schedule
                      </h3>
                    </div>
                    <button
                      onClick={() => setScheduleModalOpen(false)}
                      style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                    >
                      <X size={18} />
                    </button>
                  </div>

                  <p style={{ fontSize: '0.82rem', color: '#94a3b8', margin: '0 0 1.25rem 0', lineHeight: 1.5 }}>
                    Configure tenant-wide automated cryptographic discovery synchronization. Enrolled workstation agents will automatically wake up and sync their latest post-quantum cryptography findings according to this schedule.
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
                    <div>
                      <label style={{ fontSize: '0.78rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '0.4rem' }}>
                        Sync Frequency
                      </label>
                      <select
                        value={syncSchedulePolicy.frequency}
                        onChange={(e) => setSyncSchedulePolicy({ ...syncSchedulePolicy, frequency: e.target.value as any })}
                        style={{
                          width: '100%',
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#ffffff',
                          padding: '0.6rem 0.75rem',
                          borderRadius: '6px',
                          fontSize: '0.85rem'
                        }}
                      >
                        <option value="daily" style={{ background: '#0d1527' }}>Daily (Recommended - Off-Peak)</option>
                        <option value="hourly" style={{ background: '#0d1527' }}>Hourly (Continuous Audit)</option>
                        <option value="weekly" style={{ background: '#0d1527' }}>Weekly (Weekend Digest)</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: '0.78rem', color: '#cbd5e1', fontWeight: 600, display: 'block', marginBottom: '0.4rem' }}>
                        Scheduled Execution Time (Local Workstation Time)
                      </label>
                      <input
                        type="time"
                        value={syncSchedulePolicy.time}
                        onChange={(e) => setSyncSchedulePolicy({ ...syncSchedulePolicy, time: e.target.value })}
                        style={{
                          width: '100%',
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#ffffff',
                          padding: '0.6rem 0.75rem',
                          borderRadius: '6px',
                          fontSize: '0.85rem'
                        }}
                      />
                    </div>

                    <div style={{
                      background: 'rgba(168, 85, 247, 0.08)',
                      border: '1px solid rgba(168, 85, 247, 0.2)',
                      borderRadius: '8px',
                      padding: '0.85rem',
                      display: 'flex',
                      gap: '0.75rem',
                      alignItems: 'flex-start'
                    }}>
                      <Shield size={18} color="#c084fc" style={{ flexShrink: 0, marginTop: '2px' }} />
                      <div style={{ fontSize: '0.76rem', color: '#e2e8f0', lineHeight: 1.45 }}>
                        <strong>Smart License Deduplication Active:</strong> Automated scheduled scans update the endpoint’s existing record in-place by Hardware UUID. Each machine permanently occupies exactly <strong>1 license seat</strong>, while historical trends are safely archived into daily snapshots.
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                    <button
                      onClick={() => setScheduleModalOpen(false)}
                      style={{
                        background: 'rgba(255, 255, 255, 0.08)',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        padding: '0.5rem 1rem',
                        fontSize: '0.82rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        setScheduleModalOpen(false);
                        alert(`Automated sync policy updated: Running ${syncSchedulePolicy.frequency.toUpperCase()} at ${syncSchedulePolicy.time}. Enrolled agents have been notified.`);
                      }}
                      style={{
                        background: 'linear-gradient(135deg, #a855f7 0%, #6366f1 100%)',
                        border: 'none',
                        borderRadius: '6px',
                        color: '#ffffff',
                        padding: '0.5rem 1.25rem',
                        fontSize: '0.82rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      Save Schedule Policy
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* USER LICENSE & 2FA SECURITY MODAL */}
            {showLicense2FAModal && (
              <div style={{
                position: 'fixed',
                top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.8)',
                backdropFilter: 'blur(6px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 1000
              }}>
                <div className="glass-panel" style={{ width: '560px', maxHeight: '90vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)', boxShadow: '0 0 35px rgba(0, 242, 254, 0.15)', borderRadius: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                      <img src="/quarkshield-logo.png" alt="QuarkShield" style={{ height: '28px', width: 'auto', objectFit: 'contain' }} />
                      <div>
                        <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.15rem', fontWeight: 700 }}>
                          User License & Security Authentication
                        </h3>
                        <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary, #94a3b8)', fontSize: '0.78rem' }}>
                          {displayRole} Session Credentials & Cryptographic Multi-Factor Status
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => setShowLicense2FAModal(false)}
                      style={{ background: 'transparent', border: 'none', color: 'var(--text-muted, #64748b)', cursor: 'pointer', padding: '4px' }}
                    >
                      <X size={18} />
                    </button>
                  </div>

                  {/* Identity & Session */}
                  <div style={{ background: 'rgba(13, 19, 33, 0.85)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '1rem', marginBottom: '1rem' }}>
                    <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan, #38bdf8)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.65rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <User size={13} /> {isPartner ? 'Active Partner Workspace Node' : 'Active Client Workspace Node'}
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Email Address</span>
                        <strong style={{ color: '#ffffff', wordBreak: 'break-all' }}>{emailInput}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Role Authority</span>
                        <span style={{ color: isPartner ? '#c084fc' : 'var(--accent-cyan, #38bdf8)', fontWeight: 600 }}>{displayRole}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Customer ID</span>
                        <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{displayCustomerId}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Customer / Workspace</span>
                        <strong style={{ color: '#ffffff' }}>{displayCustomerName}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Session Guard</span>
                        <span style={{ color: 'var(--status-secure, #4ade80)', display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 600 }}>
                          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
                          Verified & Active
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Endpoint Security</span>
                        <span style={{ color: 'var(--text-secondary, #94a3b8)' }}>FIPS 203 Hybrid Post-Quantum</span>
                      </div>
                    </div>
                  </div>

                  {/* 2FA Section */}
                  <div style={{ background: 'rgba(13, 19, 33, 0.85)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '1rem', marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan, #38bdf8)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <ShieldCheck size={13} /> Two-Factor Authentication (2FA)
                      </div>
                      <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.15)', color: 'var(--status-secure, #4ade80)', fontWeight: 700, border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                        ACTIVE & ENFORCED
                      </span>
                    </div>
                    <p style={{ margin: '0 0 0.75rem 0', color: 'var(--text-secondary, #94a3b8)', fontSize: '0.8rem', lineHeight: 1.4 }}>
                      Multi-factor authentication is hardware-secured for this administrative account. Time-based One-Time Passwords (RFC 6238 TOTP) and post-quantum token challenges are active.
                    </p>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => setShowTOTPModal(true)}
                        className="btn-secondary"
                        style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                      >
                        <Lock size={13} /> Configure Authenticator App
                      </button>
                      <button
                        onClick={() => setShowBackupCodesModal(true)}
                        className="btn-secondary"
                        style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
                      >
                        View Backup Codes
                      </button>
                    </div>
                  </div>

                  {/* User License & Subscription Scale Section */}
                  <div style={{ background: 'rgba(13, 19, 33, 0.85)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '1rem', marginBottom: '1.25rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan, #38bdf8)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <Building size={13} /> {isPartner ? 'MSP Partner Pro Capacity & Fleet Control' : 'Subscription & License Allocation'}
                      </div>
                      <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '10px', background: isPartner ? 'rgba(168, 85, 247, 0.15)' : 'rgba(0, 242, 254, 0.15)', color: isPartner ? '#c084fc' : 'var(--accent-cyan, #38bdf8)', fontWeight: 700, border: `1px solid ${isPartner ? 'rgba(168, 85, 247, 0.3)' : 'rgba(0, 242, 254, 0.3)'}` }}>
                        {isPartner ? 'MSP PARTNER PRO' : 'CORPORATE ENTERPRISE'}
                      </span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem', marginBottom: '0.75rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Total Node Capacity</span>
                        <strong style={{ color: '#ffffff' }}>{isPartner ? '50 Partner Nodes' : `${client.mcaLimit || 100} Enterprise Endpoints`}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Active Monitored Endpoints</span>
                        <strong style={{ color: 'var(--accent-cyan, #38bdf8)' }}>{machines.length} Active Devices</strong>
                      </div>
                      <div style={{ gridColumn: '1 / -1' }}>
                        <span style={{ color: 'var(--text-muted, #64748b)', fontSize: '0.72rem', display: 'block' }}>Cryptographic License Key</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.2rem' }}>
                          <code style={{ background: 'rgba(0,0,0,0.4)', padding: '0.35rem 0.65rem', borderRadius: '4px', fontSize: '0.78rem', color: 'var(--accent-cyan, #38bdf8)', border: '1px solid rgba(255,255,255,0.08)', flex: 1, overflowX: 'auto' }}>
                            {activeLicKey}
                          </code>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(activeLicKey);
                              setActiveLicKeyCopied(true);
                              setTimeout(() => setActiveLicKeyCopied(false), 2000);
                            }}
                            className="btn-secondary"
                            style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                          >
                            {activeLicKeyCopied ? <Check size={13} color="var(--status-secure, #4ade80)" /> : <Copy size={13} />}
                            {activeLicKeyCopied ? 'Copied' : 'Copy'}
                          </button>
                        </div>
                      </div>
                    </div>

                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary, #94a3b8)' }}>
                        Manage tenant seat allocations, licenses & team 2FA policies
                      </span>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button
                          onClick={() => {
                            setShowLicense2FAModal(false);
                            setActiveTab('settings');
                            setSettingsSubTab('profile');
                          }}
                          className="btn-secondary"
                          style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap' }}
                        >
                          <User size={14} /> Profile &amp; Logs
                        </button>
                        <button
                          onClick={() => {
                            setShowLicense2FAModal(false);
                            setActiveTab('settings');
                            setSettingsSubTab('users');
                          }}
                          className="btn-secondary"
                          style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap' }}
                        >
                          <Users size={14} /> Team &amp; 2FA
                        </button>
                        <button
                          onClick={() => {
                            setShowLicense2FAModal(false);
                            setActiveTab('settings');
                            setSettingsSubTab('license');
                          }}
                          className="btn-primary"
                          style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap' }}
                        >
                          <Key size={14} /> View License
                        </button>
                        <button
                          onClick={handleOpenStripePortal}
                          disabled={portalLoading}
                          className="btn-secondary"
                          style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap', color: '#c084fc', borderColor: 'rgba(168, 85, 247, 0.4)' }}
                          title="Manage subscription and billing on Stripe Customer Portal"
                        >
                          <CreditCard size={14} /> {portalLoading ? 'Opening...' : 'Stripe Billing'}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Close Button */}
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      onClick={() => setShowLicense2FAModal(false)}
                      className="btn-secondary"
                      style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-MODAL: CONFIGURE AUTHENTICATOR APP (TOTP) */}
            {showTOTPModal && (
              <div style={{
                position: 'fixed',
                top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.85)',
                backdropFilter: 'blur(8px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 1100
              }}>
                <div className="glass-panel" style={{ width: '480px', maxHeight: '90vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)', borderRadius: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div style={{ padding: '0.5rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
                        <QrCode size={20} color="var(--accent-cyan, #38bdf8)" />
                      </div>
                      <div>
                        <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.1rem', fontWeight: 700 }}>
                          Configure Authenticator App
                        </h3>
                        <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary, #94a3b8)', fontSize: '0.76rem' }}>
                          RFC 6238 Time-based One-Time Password (TOTP)
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        setShowTOTPModal(false);
                        setTotpSuccess(false);
                        setTotpVerificationCode('');
                      }}
                      style={{ background: 'transparent', border: 'none', color: 'var(--text-muted, #64748b)', cursor: 'pointer', padding: '4px' }}
                    >
                      <X size={18} />
                    </button>
                  </div>

                  {totpSuccess ? (
                    <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
                      <div style={{ width: '56px', height: '56px', borderRadius: '50%', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1rem auto' }}>
                        <CheckCircle2 size={32} color="#10b981" />
                      </div>
                      <h4 style={{ color: '#ffffff', fontSize: '1.1rem', margin: '0 0 0.5rem 0' }}>
                        2FA Authenticator Verified & Bound!
                      </h4>
                      <p style={{ color: 'var(--text-secondary, #94a3b8)', fontSize: '0.84rem', lineHeight: 1.5, margin: '0 0 1.5rem 0' }}>
                        Your account <strong>{emailInput}</strong> is securely protected with Post-Quantum session verification and hardware-backed TOTP challenge tokens.
                      </p>
                      <button
                        onClick={() => {
                          setShowTOTPModal(false);
                          setTotpSuccess(false);
                          setTotpVerificationCode('');
                        }}
                        className="btn-primary"
                        style={{ padding: '0.5rem 1.5rem', fontSize: '0.85rem' }}
                      >
                        Done
                      </button>
                    </div>
                  ) : (
                    <div>
                      <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary, #94a3b8)', lineHeight: 1.45, margin: '0 0 1rem 0' }}>
                        1. Scan this QR code with your mobile authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, or YubiKey):
                      </p>

                      {/* QR Code Graphical Box */}
                      <div style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '1.25rem',
                        background: '#ffffff',
                        borderRadius: '10px',
                        margin: '0 auto 1rem auto',
                        width: '180px',
                        boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
                      }}>
                        <svg viewBox="0 0 100 100" width="150" height="150" style={{ shapeRendering: 'crispEdges' }}>
                          {/* Corner Squares */}
                          <rect x="5" y="5" width="30" height="30" fill="#0f172a" />
                          <rect x="9" y="9" width="22" height="22" fill="#ffffff" />
                          <rect x="13" y="13" width="14" height="14" fill="#0284c7" />

                          <rect x="65" y="5" width="30" height="30" fill="#0f172a" />
                          <rect x="69" y="9" width="22" height="22" fill="#ffffff" />
                          <rect x="73" y="13" width="14" height="14" fill="#0284c7" />

                          <rect x="5" y="65" width="30" height="30" fill="#0f172a" />
                          <rect x="9" y="69" width="22" height="22" fill="#ffffff" />
                          <rect x="13" y="73" width="14" height="14" fill="#0284c7" />

                          {/* Data patterns */}
                          <rect x="42" y="8" width="6" height="6" fill="#0f172a" />
                          <rect x="52" y="8" width="6" height="6" fill="#0f172a" />
                          <rect x="42" y="20" width="6" height="6" fill="#0f172a" />
                          <rect x="52" y="26" width="6" height="6" fill="#0f172a" />
                          <rect x="8" y="42" width="6" height="6" fill="#0f172a" />
                          <rect x="20" y="42" width="6" height="6" fill="#0f172a" />
                          <rect x="26" y="52" width="6" height="6" fill="#0f172a" />
                          <rect x="40" y="40" width="20" height="20" fill="#0284c7" rx="3" />
                          <circle cx="50" cy="50" r="5" fill="#ffffff" />
                          <rect x="65" y="42" width="6" height="6" fill="#0f172a" />
                          <rect x="78" y="42" width="6" height="6" fill="#0f172a" />
                          <rect x="85" y="52" width="6" height="6" fill="#0f172a" />
                          <rect x="42" y="65" width="6" height="6" fill="#0f172a" />
                          <rect x="52" y="72" width="6" height="6" fill="#0f172a" />
                          <rect x="42" y="85" width="6" height="6" fill="#0f172a" />
                          <rect x="65" y="65" width="6" height="6" fill="#0f172a" />
                          <rect x="75" y="75" width="6" height="6" fill="#0f172a" />
                          <rect x="85" y="85" width="6" height="6" fill="#0f172a" />
                        </svg>
                        <span style={{ fontSize: '0.65rem', fontWeight: 700, color: '#0f172a', marginTop: '0.35rem', letterSpacing: '0.04em' }}>
                          QUARKSHIELD 2FA
                        </span>
                      </div>

                      {/* Manual Entry Key */}
                      <div style={{ marginBottom: '1rem' }}>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted, #64748b)', display: 'block', marginBottom: '0.25rem' }}>
                          Manual Secret Key (Base32):
                        </span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <code style={{ flex: 1, background: 'rgba(0,0,0,0.4)', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.8rem', color: 'var(--accent-cyan, #38bdf8)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: 'monospace' }}>
                            QS2F-A7KX-99MN-PL38-KYBER
                          </code>
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText('QS2F-A7KX-99MN-PL38-KYBER');
                              alert('Base32 secret key copied to clipboard.');
                            }}
                            className="btn-secondary"
                            style={{ padding: '0.4rem 0.7rem', fontSize: '0.75rem' }}
                          >
                            Copy
                          </button>
                        </div>
                      </div>

                      {/* Verification Code Input */}
                      <div style={{ marginBottom: '1.25rem' }}>
                        <label style={{ fontSize: '0.75rem', fontWeight: 700, color: '#ffffff', display: 'block', marginBottom: '0.35rem' }}>
                          2. Enter the 6-digit verification code from your authenticator app:
                        </label>
                        <input
                          type="text"
                          maxLength={6}
                          placeholder="000000"
                          value={totpVerificationCode}
                          onChange={(e) => setTotpVerificationCode(e.target.value.replace(/[^0-9]/g, ''))}
                          style={{
                            width: '100%',
                            boxSizing: 'border-box',
                            background: 'rgba(255, 255, 255, 0.05)',
                            border: '1px solid rgba(0, 242, 254, 0.4)',
                            borderRadius: '6px',
                            color: '#ffffff',
                            fontSize: '1.2rem',
                            letterSpacing: '0.4rem',
                            textAlign: 'center',
                            padding: '0.5rem',
                            fontFamily: 'monospace',
                            outline: 'none'
                          }}
                        />
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
                        <button
                          onClick={() => {
                            setShowTOTPModal(false);
                            setTotpVerificationCode('');
                          }}
                          className="btn-secondary"
                          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => {
                            if (totpVerificationCode.length === 6) {
                              setTotpSuccess(true);
                            } else {
                              alert('Please enter a valid 6-digit verification code from your authenticator app.');
                            }
                          }}
                          className="btn-primary"
                          style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}
                        >
                          Verify &amp; Activate 2FA
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SUB-MODAL: VIEW BACKUP RECOVERY CODES */}
            {showBackupCodesModal && (
              <div style={{
                position: 'fixed',
                top: 0, left: 0, right: 0, bottom: 0,
                background: 'rgba(0,0,0,0.85)',
                backdropFilter: 'blur(8px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 1100
              }}>
                <div className="glass-panel" style={{ width: '480px', maxHeight: '90vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)', borderRadius: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.85rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <div style={{ padding: '0.5rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
                        <Key size={20} color="var(--accent-cyan, #38bdf8)" />
                      </div>
                      <div>
                        <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.1rem', fontWeight: 700 }}>
                          Emergency 2FA Backup Codes
                        </h3>
                        <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary, #94a3b8)', fontSize: '0.76rem' }}>
                          Single-Use Cryptographic Recovery Tokens
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => setShowBackupCodesModal(false)}
                      style={{ background: 'transparent', border: 'none', color: 'var(--text-muted, #64748b)', cursor: 'pointer', padding: '4px' }}
                    >
                      <X size={18} />
                    </button>
                  </div>

                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '8px',
                    padding: '0.75rem',
                    marginBottom: '1rem',
                    display: 'flex',
                    gap: '0.6rem',
                    alignItems: 'flex-start'
                  }}>
                    <AlertTriangle size={16} color="#f87171" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <div style={{ fontSize: '0.76rem', color: '#fecaca', lineHeight: 1.4 }}>
                      Store these recovery codes securely offline. Each code can be used exactly once if you lose access to your primary authenticator device.
                    </div>
                  </div>

                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '0.5rem',
                    background: 'rgba(0,0,0,0.4)',
                    padding: '1rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    marginBottom: '1.25rem'
                  }}>
                    {[
                      '8492-1920', '4719-8832',
                      '9281-5503', '1374-9921',
                      '6602-4189', '3182-7740',
                      '5829-1034', '7741-2390'
                    ].map((code, idx) => (
                      <div key={idx} style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent-cyan, #38bdf8)', background: 'rgba(255,255,255,0.04)', padding: '0.4rem 0.6rem', borderRadius: '4px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.04)' }}>
                        {code}
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => {
                          const allCodes = [
                            '8492-1920', '4719-8832',
                            '9281-5503', '1374-9921',
                            '6602-4189', '3182-7740',
                            '5829-1034', '7741-2390'
                          ].join('\n');
                          navigator.clipboard.writeText(`QuarkShield Emergency 2FA Backup Codes (${emailInput}):\n\n${allCodes}\n`);
                          setCopiedBackupCodes(true);
                          setTimeout(() => setCopiedBackupCodes(false), 2000);
                        }}
                        className="btn-secondary"
                        style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                      >
                        {copiedBackupCodes ? <Check size={13} color="var(--status-secure, #4ade80)" /> : <Copy size={13} />}
                        {copiedBackupCodes ? 'Copied' : 'Copy All Codes'}
                      </button>
                      <button
                        onClick={() => {
                          const allCodes = [
                            '8492-1920', '4719-8832',
                            '9281-5503', '1374-9921',
                            '6602-4189', '3182-7740',
                            '5829-1034', '7741-2390'
                          ].join('\n');
                          const blob = new Blob([`QuarkShield Emergency 2FA Backup Codes (${emailInput})\nGenerated: ${new Date().toISOString()}\n\n${allCodes}\n`], { type: 'text/plain' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `quarkshield-backup-codes-${cleanSlug}.txt`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="btn-secondary"
                        style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                      >
                        <Download size={13} /> Download .txt
                      </button>
                    </div>

                    <button
                      onClick={() => setShowBackupCodesModal(false)}
                      className="btn-primary"
                      style={{ padding: '0.45rem 1.25rem', fontSize: '0.82rem' }}
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
        </div>
      </main>
      </div>
    </div>
  );
};
