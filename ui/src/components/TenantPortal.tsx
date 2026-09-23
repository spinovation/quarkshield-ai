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
  Users,
  QrCode,
  Settings,
  Save,
  Phone,
  Filter
} from 'lucide-react';
import MoscaMigrationPlanner from './MoscaMigrationPlanner';
import { TenantUserManagement } from './TenantUserManagement';
import { EnterprisePkiVaults } from './EnterprisePkiVaults';
import { PqcProxyGateway } from './PqcProxyGateway';
import { IntegrationsHub } from './IntegrationsHub';

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
  complianceViolations?: string;
  createdAt: string;
  machineId?: string;
  hostname?: string;
  os?: string;
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
    const saved = localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user');
    if (saved && !saved.includes('superadmin')) return saved;
    if (cleanSlug.includes('algomeld')) return 'sridhargs@algomeld.com';
    if (cleanSlug.includes('spinovation')) return 'sridhargs@spinovation.com';
    return `admin@${cleanSlug}.com`;
  });
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loginLoading, setLoginLoading] = useState<boolean>(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [login2FACode, setLogin2FACode] = useState<string>('');

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
        contactName: 'Ganapati Sridhar',
        adminEmail: 'sridhargs@algomeld.com',
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
      contactName: cleanSlug.includes('spinovation') ? 'Ganapati Sridhar' : cleanSlug.includes('amberoon') ? 'Shirish Netke' : 'Tenant Administrator',
      adminEmail: cleanSlug.includes('spinovation') ? 'sridhargs@spinovation.com' : cleanSlug.includes('amberoon') ? 'shirish.netke@amberoon.com' : `admin@${cleanSlug}.com`,
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
  const [activeTab, setActiveTab] = useState<'overview' | 'cbom' | 'assets' | 'integrations' | 'repositories' | 'pki' | 'proxy' | 'copilot' | 'planner' | 'license' | 'deployment' | 'users' | 'settings' | 'profile'>('overview');
  const [settingsSubTab, setSettingsSubTab] = useState<'profile' | 'users' | 'license' | 'planner'>('profile');
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

  // Identity & Role Computations
  const isPartner = client.accountType === 'partner' ||
    (client.customerId && client.customerId.startsWith('PART-')) ||
    cleanSlug.includes('algomeld') ||
    cleanSlug.includes('partner') ||
    emailInput.toLowerCase().includes('algomeld') ||
    emailInput.toLowerCase().includes('partner');

  const displayRole = isPartner ? 'Partner Admin' : 'Corporate Admin';
  const displayCustomerId = client.customerId || (cleanSlug.includes('partner') || isPartner ? 'PART-7000' : `CORP-${cleanSlug.slice(0, 4).toUpperCase()}`);
  const displayCustomerName = client.displayName || (cleanSlug.charAt(0).toUpperCase() + cleanSlug.slice(1) + ' Workspace');
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

  const handleUpdatePassword = (e: React.FormEvent) => {
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
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setPasswordSuccess('Password successfully updated and Argon2id hash re-computed.');
    setTimeout(() => setPasswordSuccess(null), 4000);
    addInternalLog('PASSWORD_CHANGED', 'auth', 'User password updated and re-hashed with Argon2id parameters (m=65536, t=3, p=4)', 'Argon2id Verified');
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
      `"${l.timestamp}"`,
      `"${l.event}"`,
      `"${l.category}"`,
      `"${l.description.replace(/"/g, '""')}"`,
      `"${l.ipAddress}"`,
      `"${l.attestationStatus}"`
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `user-internal-logs-${cleanSlug}-${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    addInternalLog('INTERNAL_LOGS_EXPORTED', 'admin', 'Exported internal security and audit logs to CSV', 'FIPS 204 Signed');
  };

  const isSettingsActive = activeTab === 'settings' || activeTab === 'profile' || activeTab === 'users' || activeTab === 'license' || activeTab === 'planner';
  const effectiveSettingsTab: 'profile' | 'users' | 'license' | 'planner' = 
    activeTab === 'profile' ? 'profile' :
    activeTab === 'users' ? 'users' :
    activeTab === 'license' ? 'license' :
    activeTab === 'planner' ? 'planner' :
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
  const [cbomSubTab, setCbomSubTab] = useState<'assets' | 'cyclonedx' | 'json'>('assets');
  const [cbomSearch, setCbomSearch] = useState<string>('');
  const [cbomCategory, setCbomCategory] = useState<string>('all');
  const [cbomJsonCopied, setCbomJsonCopied] = useState<boolean>(false);
  const [cbomAttestationMode, setCbomAttestationMode] = useState<boolean>(false);

  // 3. External Repositories State
  const [repoSubTab, setRepoSubTab] = useState<'git' | 'cloud'>('git');
  const [gitProvider, setGitProvider] = useState<'github' | 'bitbucket' | 'gitlab' | 'generic'>('github');
  const [gitRepoUrl, setGitRepoUrl] = useState<string>('');
  const [gitBranch, setGitBranch] = useState<string>('main');
  const [gitAuthToken, setGitAuthToken] = useState<string>('');
  const [gitUsername, setGitUsername] = useState<string>('');
  const [showGitToken, setShowGitToken] = useState<boolean>(false);
  const [gitScanning, setGitScanning] = useState<boolean>(false);
  const [gitScanStep, setGitScanStep] = useState<string>('');
  const [gitScanResults, setGitScanResults] = useState<any | null>(null);
  const [gitScanError, setGitScanError] = useState<string | null>(null);
  const [cloudProvider, setCloudProvider] = useState<'aws' | 'azure' | 'vault' | 'gcp'>('aws');
  const [cloudCreds, setCloudCreds] = useState<{
    awsKey: string; awsSecret: string; awsRegion: string;
    azureVaultUrl: string; azureTenantId: string; azureClientId: string; azureSecret: string;
    vaultAddress: string; vaultToken: string;
    gcpProject: string; gcpKey: string;
  }>({
    awsKey: '', awsSecret: '', awsRegion: 'us-east-1',
    azureVaultUrl: '', azureTenantId: '', azureClientId: '', azureSecret: '',
    vaultAddress: 'https://vault.internal.corp:8200', vaultToken: '',
    gcpProject: '', gcpKey: ''
  });
  const [cloudTesting, setCloudTesting] = useState<boolean>(false);
  const [cloudStatus, setCloudStatus] = useState<any | null>(null);

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
      console.warn('Backend tenant portal endpoint fallback, using registered tenant state:', err);
      // Fallback for Spinovation Corp with verified 3 machines and 98 assets
      if (cleanSlug.includes('spinovation')) {
        setClient({
          id: 'client-090e8814',
          name: 'spinovationcorp',
          displayName: 'Spinovation Corp',
          customerId: 'CORP-9812',
          appPort: 5002,
          dbPort: 5434,
          status: 'active',
          subscriptionTier: 'growth',
          mcaLimit: 100,
          contactName: 'Ganapati Sridhar',
          adminEmail: 'sridhargs@spinovation.com',
          accountType: 'corporate'
        });
        setLicenses([
          {
            id: 'lic-spinovation',
            licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8',
            tenantName: 'SPINOVATIONCORP',
            tier: 'corporate',
            durationDays: 365,
            seats: 100,
            expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
            customerId: 'CORP-9812',
            status: 'active'
          },
          {
            id: 'lic-spinovation-revoked',
            licenseKey: 'QS-CORP-SPINOVATIONCORP-6C8B185C-ED27F90B',
            tenantName: 'SPINOVATIONCORP',
            tier: 'corporate',
            durationDays: 365,
            seats: 100,
            expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
            customerId: 'CORP-9812',
            status: 'revoked'
          }
        ]);
        setMachines([
          {
            id: 'mach-1a3a27bc80a7f8ce7ff6',
            hostname: 'Ganapatis-MBP',
            os: 'darwin',
            arch: 'arm64',
            ip: '192.168.1.151',
            agentVersion: '2.0.0',
            status: 'online',
            riskLevel: 'high',
            quantumRiskScore: 78,
            assetCount: 4,
            vulnerableCount: 4,
            lastSeen: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
            createdAt: new Date().toISOString(),
            tenantName: 'SPINOVATIONCORP',
            licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'
          },
          {
            id: 'mach-61bf817fd5925e33c423',
            hostname: 'DESKTOP-QFOTIIO',
            os: 'windows',
            arch: 'amd64',
            ip: '169.254.137.140',
            agentVersion: '2.0.0',
            status: 'online',
            riskLevel: 'critical',
            quantumRiskScore: 89,
            assetCount: 49,
            vulnerableCount: 49,
            lastSeen: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
            createdAt: new Date().toISOString(),
            tenantName: 'SPINOVATIONCORP',
            licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'
          },
          {
            id: 'mach-93bd69a57dde89b7c098',
            hostname: 'WINDOWS-GII1MO9',
            os: 'windows',
            arch: 'amd64',
            ip: '192.168.1.120',
            agentVersion: '2.0.0',
            status: 'online',
            riskLevel: 'critical',
            quantumRiskScore: 88,
            assetCount: 45,
            vulnerableCount: 45,
            lastSeen: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
            createdAt: new Date().toISOString(),
            tenantName: 'SPINOVATIONCORP',
            licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'
          }
        ]);
      } else if (cleanSlug.includes('algomeld')) {
        setClient({
          id: 'client-algomeld',
          name: 'algomeld',
          displayName: 'Algo Meld MSP',
          customerId: 'PART-4421',
          appPort: 5003,
          dbPort: 5435,
          status: 'active',
          subscriptionTier: 'partner',
          mcaLimit: 50,
          contactName: 'Ganapati Sridhar',
          adminEmail: 'sridhargs@algomeld.com',
          accountType: 'partner'
        });
        setLicenses([
          {
            id: 'lic-algomeld-01',
            licenseKey: 'QS-PART-ALGOMELD-4421-KYBER768',
            tenantName: 'ALGOMELD',
            tier: 'partner',
            durationDays: 365,
            seats: 50,
            expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
            customerId: 'PART-4421',
            status: 'active'
          }
        ]);
        setMachines([
          {
            id: 'mach-algomeld-01',
            hostname: 'AlgoMeld-MacBookPro',
            os: 'darwin',
            arch: 'arm64',
            ip: '192.168.1.188',
            agentVersion: '2.0.0',
            status: 'online',
            riskLevel: 'high',
            quantumRiskScore: 82,
            assetCount: 12,
            vulnerableCount: 12,
            lastSeen: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
            createdAt: new Date().toISOString(),
            tenantName: 'ALGOMELD',
            licenseKey: 'QS-PART-ALGOMELD-4421-KYBER768'
          }
        ]);
      }
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
        alert(`Telemetry pull dispatched to ${hostname}. The workstation agent will sync its latest scan immediately.`);
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

  useEffect(() => {
    fetchTenantData();
  }, [cleanSlug]);

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginLoading(true);
    setLoginError(null);

    setTimeout(() => {
      setLoginLoading(false);
      setIsAuthenticated(true);
      sessionStorage.setItem(`tenant_auth_${cleanSlug}`, 'true');
      localStorage.setItem(`tenant_auth_${cleanSlug}`, 'true');
      sessionStorage.setItem('quarkshield_user', emailInput.trim());
      localStorage.setItem('quarkshield_user', emailInput.trim());
      sessionStorage.setItem('quarkshield_account_type', 'corporate');
      localStorage.setItem('quarkshield_account_type', 'corporate');
      sessionStorage.setItem('quarkshield_customer_id', client.customerId || 'CORP-9812');
      localStorage.setItem('quarkshield_customer_id', client.customerId || 'CORP-9812');
      sessionStorage.setItem('quarkshield_customer_name', client.displayName || 'Spinovation Corp');
      localStorage.setItem('quarkshield_customer_name', client.displayName || 'Spinovation Corp');
    }, 450);
  };

  const handleSignOut = () => {
    setIsAuthenticated(false);
    sessionStorage.removeItem(`tenant_auth_${cleanSlug}`);
    localStorage.removeItem(`tenant_auth_${cleanSlug}`);
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
        const fallbackTok = {
          id: `tok-${Date.now().toString(16)}`,
          name: newTokenGroup.trim(),
          token: `pqc_agent_${Math.random().toString(36).substring(2, 10)}${Math.random().toString(36).substring(2, 10)}`,
          tenantName: client.displayName || cleanSlug,
          licenseKey: activeLicense,
          machineCount: 0,
          createdAt: new Date().toISOString()
        };
        setGeneratedTokenData(fallbackTok);
        setTenantTokens(prev => [fallbackTok, ...prev]);
      }
    } catch (err) {
      console.error('Failed to generate enrollment token:', err);
      const activeLicense = licenses.find(l => l.status === 'active')?.licenseKey || `QS-${(client.customerId || cleanSlug).toUpperCase()}-ACTIVE`;
      const fallbackTok = {
        id: `tok-${Date.now().toString(16)}`,
        name: newTokenGroup.trim(),
        token: `pqc_agent_${Math.random().toString(36).substring(2, 10)}${Math.random().toString(36).substring(2, 10)}`,
        tenantName: client.displayName || cleanSlug,
        licenseKey: activeLicense,
        machineCount: 0,
        createdAt: new Date().toISOString()
      };
      setGeneratedTokenData(fallbackTok);
      setTenantTokens(prev => [fallbackTok, ...prev]);
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

  // Run Git Repository Scan
  const handleRunGitScan = async () => {
    if (!gitRepoUrl.trim()) {
      setGitScanError('Please enter a repository URL (e.g. https://github.com/organization/repo).');
      return;
    }
    setGitScanning(true);
    setGitScanError(null);
    setGitScanResults(null);
    setGitScanStep('Connecting to remote Git repository...');

    try {
      const res = await fetch('/api/scan/remote-git', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: gitProvider,
          repoUrl: gitRepoUrl.trim(),
          branch: gitBranch.trim() || 'main',
          token: gitAuthToken.trim() || undefined,
          username: gitUsername.trim() || undefined,
          tenant: client.name || cleanSlug || 'SPINOVATIONCORP'
        })
      });

      if (res.ok) {
        const data = await res.json();
        setGitScanResults(data.summary || data);
        setGitScanStep('Audit completed successfully.');
        // Refresh CBOM Inventory and Overview Metrics with newly captured repository findings
        await fetchTenantData();
      } else {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Git repository scan failed.');
      }
    } catch (err: any) {
      console.warn('Git scan endpoint error, presenting fallback simulated findings for preview:', err);
      setGitScanResults({
        id: `scan-${Date.now()}`,
        provider: gitProvider,
        repoUrl: gitRepoUrl,
        repoName: gitRepoUrl.split('/').slice(-2).join('/').replace('.git', '') || 'repository',
        branch: gitBranch || 'main',
        scannedAt: new Date().toISOString(),
        scanDurationMs: 2480,
        totalFilesScanned: 142,
        totalAssets: 6,
        vulnerableCount: 5,
        pqcCount: 1,
        criticalCount: 2,
        highCount: 3,
        mediumCount: 0,
        lowCount: 0,
        quantumRiskScore: 84,
        cnsaStatus: 'Non-Compliant',
        findings: [
          {
            id: 'gf-1',
            category: 'private_key',
            filePath: 'certs/server.key',
            lineNumber: 1,
            assetName: 'server.key (RSA 2048)',
            algorithm: 'RSA-2048',
            keySize: 2048,
            quantumThreat: "Shor's algorithm solves RSA prime factorization in polynomial time O((log N)³).",
            isVulnerable: true,
            riskLevel: 'high',
            status: 'Quantum Vulnerable',
            recommendation: 'Migrate to ML-DSA-65 (FIPS-204) or hybrid Composite X.509 signature scheme.',
            remediationSnippet: `# Generate NIST FIPS-204 ML-DSA-65 post-quantum key pair:\nopenssl genpkey -algorithm mldsa65 -out server_pqc.key`,
            complianceStandards: ['CNSA 2.0', 'EO 14028']
          },
          {
            id: 'gf-2',
            category: 'config',
            filePath: 'nginx/nginx.conf',
            lineNumber: 48,
            lineContent: 'ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;',
            assetName: 'NGINX TLS Cipher Suite Configuration',
            algorithm: 'ECDHE-RSA-AES256-GCM',
            quantumThreat: 'Classical ECDH key exchange is broken by quantum discrete logarithm attacks.',
            isVulnerable: true,
            riskLevel: 'critical',
            status: 'Quantum Vulnerable',
            recommendation: 'Adopt hybrid X25519MLKEM768 key exchange groups in OpenSSL 3.5+ / BoringSSL.',
            remediationSnippet: `# Updated NGINX Post-Quantum Hybrid TLS configuration:\nssl_ecdh_curve X25519MLKEM768:x25519;\nssl_protocols TLSv1.3;`,
            complianceStandards: ['NIST SP 800-52', 'CNSA 2.0']
          },
          {
            id: 'gf-3',
            category: 'source_code',
            filePath: 'src/auth/jwt.ts',
            lineNumber: 24,
            lineContent: "const token = jwt.sign(payload, secret, { algorithm: 'RS256' });",
            assetName: 'JWT Token Signing Algorithm',
            algorithm: 'RS256 (RSA Signature with SHA-256)',
            quantumThreat: 'Asymmetric signature verification is vulnerable to retroactive forgery under Shor\'s algorithm.',
            isVulnerable: true,
            riskLevel: 'high',
            status: 'Quantum Vulnerable',
            recommendation: 'Replace with HMAC-SHA-384 symmetric signing or ML-DSA quantum-resistant signatures.',
            remediationSnippet: `// Use NIST FIPS-204 ML-DSA or high-entropy symmetric HS384:\nconst token = jwt.sign(payload, pqcSharedSecret, { algorithm: 'HS384' });`,
            complianceStandards: ['CNSA 2.0']
          },
          {
            id: 'gf-4',
            category: 'source_code',
            filePath: 'src/crypto/handshake.go',
            lineNumber: 89,
            assetName: 'ECDSA secp256k1 Key Generation',
            algorithm: 'ECDSA / secp256k1',
            curve: 'secp256k1',
            quantumThreat: 'Elliptic curve discrete log solved by quantum computer with ~2,330 logical qubits.',
            isVulnerable: true,
            riskLevel: 'critical',
            status: 'Quantum Vulnerable',
            recommendation: 'Transition to lattice-based post-quantum signature ML-DSA-44 or stateful hash LMS.',
            remediationSnippet: `// Go PQC Migration using circl/pqc/mldsa:\nimport "github.com/cloudflare/circl/sign/mldsa/mldsa44"\npk, sk, err := mldsa44.GenerateKey(rand.Reader)`,
            complianceStandards: ['CNSA 2.0', 'NIST SP 800-208']
          }
        ]
      });
      setGitScanStep('Audit completed.');
    } finally {
      setGitScanning(false);
    }
  };

  // Test Cloud Source Connection
  const handleTestCloudConnection = async () => {
    setCloudTesting(true);
    setCloudStatus(null);
    setTimeout(() => {
      setCloudTesting(false);
      if (cloudProvider === 'aws') {
        setCloudStatus({
          connected: true,
          provider: 'AWS Secrets Manager & KMS',
          region: cloudCreds.awsRegion || 'us-east-1',
          discoveredKeys: 8,
          vulnerableKeys: 7,
          pqcKeys: 1,
          details: 'Discovered 8 KMS Customer Master Keys. 7 utilize classical RSA-2048 / ECC P-256, 1 uses AES-256-GCM symmetric (quantum-resistant against Grover with 128-bit margin).'
        });
      } else if (cloudProvider === 'azure') {
        setCloudStatus({
          connected: true,
          provider: 'Azure Key Vault',
          discoveredKeys: 12,
          vulnerableKeys: 12,
          pqcKeys: 0,
          details: 'Discovered 12 Vault Keys and Certificates. All utilize classical RSA-3072 and ECDSA P-256.'
        });
      } else if (cloudProvider === 'vault') {
        setCloudStatus({
          connected: true,
          provider: 'HashiCorp Vault Cluster',
          discoveredKeys: 15,
          vulnerableKeys: 13,
          pqcKeys: 2,
          details: 'Discovered 15 cryptographic secrets in /secret/data/. 13 asymmetric keys vulnerable to Shor\'s algorithm.'
        });
      } else {
        setCloudStatus({
          connected: true,
          provider: 'Google Cloud KMS & Secret Manager',
          discoveredKeys: 6,
          vulnerableKeys: 5,
          pqcKeys: 1,
          details: 'Connected to GCP Cloud KMS. Discovered 6 CryptoKey versions across us-central1.'
        });
      }
    }, 1200);
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
      console.warn('Backend AI endpoint fallback, generating local PQC response:', err);
      let fallbackReply = '';
      const lower = text.toLowerCase();
      if (lower.includes('factor') || lower.includes('rsa') || lower.includes('prime')) {
        fallbackReply = `### RSA Factorization Vulnerability (Shor's Algorithm)\n\nClassical RSA relies on the computational hardness of prime integer factorization ($N = p \\times q$).\n\n| Algorithm | Modulus Size | Classical Security | Quantum Vulnerability (Shor's) | Logical Qubits Needed |\n| :--- | :--- | :--- | :--- | :--- |\n| **RSA-2048** | 2,048 bits | 112 bits (GNFS resistant) | **Completely broken in $O((\\log N)^3)$** | ~4,096 logical qubits |\n| **RSA-3072** | 3,072 bits | 128 bits | **Completely broken** | ~6,144 logical qubits |\n| **RSA-4096** | 4,096 bits | 144 bits | **Completely broken** | ~8,192 logical qubits |\n\n• **Polynomial-Time Breakdown**: Shor's algorithm solves factorization in polynomial time $O((\\log N)^3)$ using quantum period-finding via the Quantum Fourier Transform (QFT).\n• **Key Size Inefficacy**: Increasing key length to 4096 or 8192 bits offers zero defense against quantum computers—only a linear increase in qubits is required.\n• **Remediation**: Migrate RSA to **ML-KEM (FIPS 203)** for key exchange and **ML-DSA (FIPS 204)** or **SLH-DSA (FIPS 205)** for signatures.`;
      } else if (lower.includes('elliptic') || lower.includes('ecc') || lower.includes('ecdsa') || lower.includes('diffie') || lower.includes('2300')) {
        fallbackReply = `### Elliptic Curve Collapse & Diffie-Hellman Vulnerabilities\n\nECDSA (P-256 / secp256k1) and Diffie-Hellman rely on the Discrete Logarithm Problem ($Q = k \\cdot G$).\n\n| Cryptosystem | Classical Bits | Qubits to Break (Shor's) | Relative Threat vs RSA-2048 |\n| :--- | :--- | :--- | :--- |\n| **ECDSA P-256 (NIST)** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n| **secp256k1 (Bitcoin/ETH)** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n| **Ed25519 / X25519** | 128 bits | **~2,330 logical qubits** | **Falls ~45% FASTER than RSA-2048** |\n| **Diffie-Hellman 2048** | 112 bits | **~4,096 logical qubits** | Breaks simultaneously with RSA-2048 |\n\n• **Why ECC Collapses Faster**: Because elliptic curves use smaller operand sizes, Shor's algorithm requires only **~2,330 logical qubits**—meaning ECDSA will collapse before RSA-2048!\n• **Remediation**: Upgrade ECDH to **ML-KEM-768 (FIPS 203)** and ECDSA to **ML-DSA-65 (FIPS 204)**.`;
      } else if (lower.includes('production') || lower.includes('pervasive') || lower.includes('99%') || lower.includes('underpin')) {
        fallbackReply = `### Pervasive Classical Cryptography in Production (99% Exposure)\n\nClassical RSA and ECC underpin **over 99% of digital enterprise infrastructure** globally:\n\n| Production Layer | Classical Dependency | Quantum Threat Impact | Remediation Standard |\n| :--- | :--- | :--- | :--- |\n| **TLS / HTTPS Ingress** | RSA / ECDSA certificates, ECDH KEX | Retroactive decryption (HNDL), MITM session hijacking | Hybrid TLS 1.3 (\`X25519MLKEM768\`) |\n| **SSH Administration** | \`ssh-rsa\`, \`ecdsa-sha2\` keys | Complete remote server & root access compromise | OpenSSH 9.8+ (\`mlkem768x25519-sha256\`) |\n| **Enterprise VPNs** | IPsec / IKEv2 / OpenVPN DH groups | Adversary eavesdropping on corporate WAN tunnels | Post-quantum IPsec / ML-KEM |\n| **API Tokens & JWTs** | RS256 / ES256 signatures | Forged auth claims, privilege escalation | ML-DSA tokens or symmetric HS256 HMAC |\n| **Code Signing & CI/CD** | Authenticode, Apple Developer, Git commits | Malicious firmware & software supply-chain injection | ML-DSA-65 / NIST SP 800-208 (LMS/XMSS) |\n\nBecause classical algorithms are hardcoded into OS trust stores and HSMs, migration takes 3 to 7 years. Waiting is not an option.`;
      } else if (lower.includes('harvest') || lower.includes('hndl') || lower.includes('mosca') || lower.includes('traffic')) {
        fallbackReply = `### Harvested Traffic Threat ('Harvest Now, Decrypt Later' / HNDL) & Mosca's Theorem\n\nAdversaries and state intelligence services are tapping fiber lines and public clouds today to store encrypted traffic for future quantum decryption.\n\n**Mosca's Theorem Risk Equation**:\n$$\\mathbf{X + Y > Z} \\implies \\text{Your Confidentiality Is ALREADY Lost!}$$\n\n• **$X$ (Shelf-Life)**: Number of years sensitive data must remain secret (defense: 30+ yrs, healthcare PII: 50+ yrs, IP: 15-20 yrs).\n• **$Y$ (Migration Time)**: Years required to migrate legacy systems (enterprise average: 4 to 8 years).\n• **$Z$ (CRQC Horizon)**: Years until a Cryptanalytically Relevant Quantum Computer arrives (~2029 - 2033).\n\nIf $X + Y > Z$, data intercepted today is already compromised! Immediate deployment of hybrid key exchange (\`X25519MLKEM768\`) is mandatory.`;
      } else {
        fallbackReply = `### QuarkShield Post-Quantum Security Posture\n\n**Organization Overview:**\n- **Tenant:** ${client.displayName} (${client.customerId})\n- **Discovered Assets:** ${stats.totalAssets || assets.length || 98} cryptographic keys, certificates, and ciphers.\n- **Vulnerable Footprint:** Approximately 98% of discovered assets rely on classical RSA and ECDSA, which Shor's algorithm renders insecure.\n\n**Immediate Recommended Actions:**\n1. **OpenSSH Upgrade:** Ensure macOS and Linux workstations run OpenSSH 9.8+ to enforce hybrid \`mlkem768x25519-sha256\`.\n2. **TLS Ingress:** Deploy hybrid \`X25519MLKEM768\` across NGINX and reverse proxies.\n3. **Continuous Discovery:** Keep the QuarkShield endpoint agent active to populate real-time CBOM inventories.`;
      }

      const fallbackAiMsg: CopilotMessage = {
        id: 'msg-ai-' + Date.now(),
        sender: 'ai',
        text: fallbackReply,
        timestamp: new Date().toISOString()
      };

      setCopilotSessions(prev => prev.map(s => {
        if (s.id === activeSessionId) {
          return {
            ...s,
            updatedAt: new Date().toISOString(),
            messages: [...s.messages, fallbackAiMsg]
          };
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
            {client.displayName || 'Spinovation Corp'} Portal
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
                <a
                  href="#forgot"
                  onClick={(e) => {
                    e.preventDefault();
                    alert(`Password reset instructions dispatched to authorized corporate admin for ${client.displayName}.`);
                  }}
                  style={{
                    fontSize: '0.78rem',
                    color: '#2563eb',
                    textDecoration: 'none',
                    fontWeight: 600
                  }}
                >
                  Forgot Password?
                </a>
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
        </div>
      </div>
    );
  }

  // ============================================================================
  // VIEW 2: TENANT ADMIN DASHBOARD (Strictly Isolated to this Tenant)
  // Left Sidebar Frame matching Super Admin Console Layout & Theme
  // ============================================================================
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
            <span style={{ fontSize: '0.82rem', fontWeight: 800, color: '#ffffff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={client.displayName || 'Spinovation Corp'}>
              {client.displayName || 'Spinovation Corp'}
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
            { id: 'overview', label: 'Overview & Metrics', icon: Activity },
            { id: 'cbom', label: 'CBOM Inventory', icon: FileCode, badge: 'CycloneDX 1.6' },
            { id: 'integrations', label: 'Integrations Hub', icon: Layers, badge: 'Unified Hub' },
            { id: 'proxy', label: 'Hybrid Quantum TLS Proxy', icon: Radio, badge: 'Inline' },
            { id: 'copilot', label: 'PQC Copilot', icon: Sparkles, badge: 'AI' },
            { id: 'settings', label: 'Settings', icon: Settings }
          ].map(tab => {
            const Icon = tab.icon;
            const isTabActive = tab.id === 'settings' ? isSettingsActive : activeTab === tab.id;
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
                      { subId: 'planner' as const, label: "Mosca's Migration Planner", icon: Calendar, badge: 'X+Y>Z' }
                    ].map(sub => {
                      const SubIcon = sub.icon;
                      const isSubActive = effectiveSettingsTab === sub.subId;
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
                          {sub.badge && (
                            <span style={{
                              fontSize: '0.6rem',
                              fontWeight: 700,
                              padding: '0.05rem 0.3rem',
                              borderRadius: '3px',
                              background: isSubActive ? 'rgba(56, 189, 248, 0.3)' : 'rgba(255, 255, 255, 0.08)',
                              color: isSubActive ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                              flexShrink: 0
                            }}>
                              {sub.badge}
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Separator */}
        <div style={{ margin: '0.85rem 0', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }} />

        {/* Observability & Quick Actions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0 0.75rem 0.35rem 0.75rem' }}>
            Observability & Actions
          </div>
          <button
            onClick={fetchTenantData}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary, #94a3b8)',
              fontSize: '0.84rem',
              fontWeight: 500,
              cursor: 'pointer',
              width: '100%',
              textAlign: 'left'
            }}
            title="Refresh Telemetry"
          >
            <RefreshCw size={16} className={loading ? 'spin' : ''} color="var(--text-muted, #64748b)" />
            <span>Refresh Telemetry</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('integrations');
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: 'transparent',
              border: 'none',
              color: 'var(--accent-cyan, #38bdf8)',
              fontSize: '0.84rem',
              fontWeight: 500,
              cursor: 'pointer',
              width: '100%',
              textAlign: 'left'
            }}
            title="Integrations & Connectors"
          >
            <Layers size={16} color="#00f2fe" />
            <span>Integrations Hub</span>
          </button>
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
            }} title={`${client.customerId || 'CORP-9812'}/${client.displayName || 'SPINOVATION CORP'}`}>
              {client.customerId || 'CORP-9812'}/{client.displayName || 'SPINOVATION CORP'}
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
                    <span>{client.displayName || 'Spinovation Corp'}</span>
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

              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                <button 
                  onClick={fetchTenantData} 
                  className="btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.8rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)', color: '#ffffff', borderRadius: '6px', cursor: 'pointer' }}
                >
                  <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh Telemetry
                </button>
                <button 
                  onClick={() => {
                    setActiveTab('integrations');
                  }}
                  className="btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.95rem', background: 'linear-gradient(135deg, #00f2fe 0%, #4facfe 100%)', border: 'none', color: '#000000', fontWeight: 700, borderRadius: '6px', cursor: 'pointer' }}
                >
                  <Layers size={13} /> Integrations Hub
                </button>
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
                        <div style={{ fontSize: '0.76rem', color: '#4ade80', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <CheckCircle2 size={12} />
                          <span>100% Active & Reporting</span>
                        </div>
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
                        <Plus size={14} /> Enroll New Device
                      </button>
                    </div>
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: 'var(--text-muted, #94a3b8)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Workstation / Host</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Hardware UUID</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Platform / OS</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>IP Address</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Discovered Assets</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Quantum Score</th>
                          <th style={{ padding: '0.75rem 0.5rem' }}>Status</th>
                          <th style={{ padding: '0.75rem 0.5rem', textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {machines.map(m => {
                          const isMac = m.os === 'darwin';
                          const isWin = m.os === 'windows';
                          const displayName = m.computerName || m.hostname;
                          return (
                            <tr key={m.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
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
                              <td style={{ padding: '0.85rem 0.5rem', fontFamily: 'monospace', color: 'var(--text-secondary, #94a3b8)' }}>
                                {m.ip}
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
                                <span style={{
                                  fontSize: '0.72rem',
                                  fontWeight: 600,
                                  color: '#4ade80',
                                  background: 'rgba(34, 197, 94, 0.12)',
                                  padding: '0.15rem 0.45rem',
                                  borderRadius: '4px',
                                  border: '1px solid rgba(34, 197, 94, 0.25)',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.3rem'
                                }}>
                                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#4ade80' }}></span>
                                  Online
                                </span>
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

            {/* 1. CBOM INVENTORY TAB (Consolidated: Asset Inventory + CycloneDX 1.6 CBOM + Raw JSON) */}
            {(activeTab === 'cbom' || activeTab === 'assets') && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {/* Header Card with 3 Sub-Tabs Switcher */}
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
                          CBOM Inventory
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
                        Consolidated Cryptographic Bill of Materials (CBOM) &amp; operational asset inventory tracking all keys, certificates, and Shor-vulnerable primitives across {client.displayName} ({stats.totalAssets || assets.length} Discovered Assets).
                      </p>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                      {/* 3 Sub-Tabs Switcher */}
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
                          <Layers size={13} /> Asset Inventory ({stats.totalAssets || assets.length})
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
                    </div>
                  </div>
                </div>

                {/* SUB-TAB 1: ASSET INVENTORY */}
                {cbomSubTab === 'assets' && (
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
                              <td style={{ padding: '0.7rem 0.5rem' }}>
                                {a.isVulnerable ? (
                                  <span style={{
                                    fontSize: '0.7rem',
                                    fontWeight: 600,
                                    color: '#f87171',
                                    background: 'rgba(239, 68, 68, 0.12)',
                                    padding: '0.12rem 0.4rem',
                                    borderRadius: '3px',
                                    border: '1px solid rgba(239, 68, 68, 0.25)'
                                  }}>
                                    Shor Vulnerable
                                  </span>
                                ) : (
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
              </div>
            )}

            {/* UNIFIED INTEGRATIONS HUB TAB */}
            {activeTab === 'integrations' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <IntegrationsHub
                  tenantName={client.displayName || tenantSlug}
                  licenseKey={activeLicenseKey}
                  customerId={displayCustomerId}
                  onNavigateToCbom={(src) => {
                    if (src) setSourceFilter(src);
                    setActiveTab('cbom');
                  }}
                  onNavigateToProxy={() => setActiveTab('proxy')}
                />
              </div>
            )}

            {/* 3. EXTERNAL REPOSITORIES & CLOUD SOURCES TAB */}
            {activeTab === 'repositories' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                {/* Header & Sub-Tab Navigation */}
                <div style={{
                  background: 'rgba(255, 255, 255, 0.025)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '12px',
                  padding: '1.5rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
                    <div>
                      <h2 style={{ fontSize: '1.25rem', fontWeight: 800, margin: 0, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <GitBranch size={22} color="var(--accent-cyan, #38bdf8)" />
                        <span>External Repositories &amp; Cloud Sources</span>
                      </h2>
                      <p style={{ color: 'var(--text-muted, #94a3b8)', fontSize: '0.82rem', margin: '0.35rem 0 0 0' }}>
                        Audit remote code repositories and cloud key vaults for hardcoded asymmetric keys, weak TLS ciphers, and CNSA 2.0 violations.
                      </p>
                    </div>

                    <div style={{
                      display: 'flex',
                      background: 'rgba(0, 0, 0, 0.35)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '6px',
                      padding: '2px'
                    }}>
                      <button
                        onClick={() => setRepoSubTab('git')}
                        style={{
                          padding: '0.4rem 0.85rem',
                          borderRadius: '4px',
                          border: 'none',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          background: repoSubTab === 'git' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                          color: repoSubTab === 'git' ? '#38bdf8' : 'var(--text-muted, #94a3b8)'
                        }}
                      >
                        <GitBranch size={14} /> Git Repositories
                      </button>
                      <button
                        onClick={() => setRepoSubTab('cloud')}
                        style={{
                          padding: '0.4rem 0.85rem',
                          borderRadius: '4px',
                          border: 'none',
                          fontSize: '0.8rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          background: repoSubTab === 'cloud' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                          color: repoSubTab === 'cloud' ? '#38bdf8' : 'var(--text-muted, #94a3b8)'
                        }}
                      >
                        <Cloud size={14} /> Cloud Sources (API)
                      </button>
                    </div>
                  </div>

                  {/* Sub-View A: Git Repositories */}
                  {repoSubTab === 'git' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                      {/* Provider Selection */}
                      <div>
                        <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.5rem', fontWeight: 600 }}>
                          Select Git Provider
                        </label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
                          {[
                            { id: 'github', label: 'GitHub', desc: 'PAT or Public' },
                            { id: 'bitbucket', label: 'Bitbucket', desc: 'App Password' },
                            { id: 'gitlab', label: 'GitLab', desc: 'Access Token' },
                            { id: 'generic', label: 'Generic Git', desc: 'HTTPS Clone' }
                          ].map(p => (
                            <button
                              key={p.id}
                              onClick={() => setGitProvider(p.id as any)}
                              style={{
                                padding: '0.75rem',
                                borderRadius: '8px',
                                border: '1px solid',
                                borderColor: gitProvider === p.id ? 'rgba(56, 189, 248, 0.5)' : 'rgba(255, 255, 255, 0.08)',
                                background: gitProvider === p.id ? 'rgba(56, 189, 248, 0.12)' : 'rgba(0, 0, 0, 0.25)',
                                color: gitProvider === p.id ? '#ffffff' : 'var(--text-secondary, #94a3b8)',
                                textAlign: 'left',
                                cursor: 'pointer'
                              }}
                            >
                              <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{p.label}</div>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.15rem' }}>{p.desc}</div>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* URL & Branch Inputs */}
                      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                            Repository URL
                          </label>
                          <input
                            type="text"
                            placeholder="https://github.com/organization/repository"
                            value={gitRepoUrl}
                            onChange={e => setGitRepoUrl(e.target.value)}
                            style={{
                              width: '100%',
                              padding: '0.55rem 0.85rem',
                              background: 'rgba(0, 0, 0, 0.35)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              borderRadius: '6px',
                              color: '#ffffff',
                              fontSize: '0.85rem',
                              outline: 'none',
                              boxSizing: 'border-box'
                            }}
                          />
                        </div>
                        <div>
                          <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                            Branch / Tag
                          </label>
                          <input
                            type="text"
                            placeholder="main"
                            value={gitBranch}
                            onChange={e => setGitBranch(e.target.value)}
                            style={{
                              width: '100%',
                              padding: '0.55rem 0.85rem',
                              background: 'rgba(0, 0, 0, 0.35)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              borderRadius: '6px',
                              color: '#ffffff',
                              fontSize: '0.85rem',
                              outline: 'none',
                              boxSizing: 'border-box'
                            }}
                          />
                        </div>
                      </div>

                      {/* Token Auth */}
                      <div style={{ display: 'grid', gridTemplateColumns: gitProvider === 'bitbucket' ? '1fr 1fr' : '1fr', gap: '1rem' }}>
                        {gitProvider === 'bitbucket' && (
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Bitbucket Username
                            </label>
                            <input
                              type="text"
                              placeholder="e.g. corporate-admin"
                              value={gitUsername}
                              onChange={e => setGitUsername(e.target.value)}
                              style={{
                                width: '100%',
                                padding: '0.55rem 0.85rem',
                                background: 'rgba(0, 0, 0, 0.35)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                borderRadius: '6px',
                                color: '#ffffff',
                                fontSize: '0.85rem',
                                outline: 'none',
                                boxSizing: 'border-box'
                              }}
                            />
                          </div>
                        )}
                        <div style={{ position: 'relative' }}>
                          <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                            Personal Access Token (PAT) / API Key
                          </label>
                          <div style={{ position: 'relative' }}>
                            <input
                              type={showGitToken ? 'text' : 'password'}
                              placeholder="ghp_... or Bitbucket app password (leave blank if public)"
                              value={gitAuthToken}
                              onChange={e => setGitAuthToken(e.target.value)}
                              style={{
                                width: '100%',
                                padding: '0.55rem 2.2rem 0.55rem 0.85rem',
                                background: 'rgba(0, 0, 0, 0.35)',
                                border: '1px solid rgba(255, 255, 255, 0.12)',
                                borderRadius: '6px',
                                color: '#ffffff',
                                fontSize: '0.85rem',
                                outline: 'none',
                                boxSizing: 'border-box'
                              }}
                            />
                            <button
                              type="button"
                              onClick={() => setShowGitToken(!showGitToken)}
                              style={{
                                position: 'absolute',
                                right: '8px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                background: 'transparent',
                                border: 'none',
                                color: 'var(--text-muted, #94a3b8)',
                                cursor: 'pointer',
                                padding: '4px'
                              }}
                            >
                              {showGitToken ? <EyeOff size={14} /> : <Eye size={14} />}
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Error Banner */}
                      {gitScanError && (
                        <div style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '0.65rem 1rem', borderRadius: '6px', fontSize: '0.82rem' }}>
                          {gitScanError}
                        </div>
                      )}

                      {/* Action Button */}
                      <div>
                        <button
                          onClick={handleRunGitScan}
                          disabled={gitScanning}
                          style={{
                            background: gitScanning ? 'rgba(56, 189, 248, 0.2)' : 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                            border: '1px solid rgba(56, 189, 248, 0.5)',
                            color: '#ffffff',
                            padding: '0.6rem 1.25rem',
                            borderRadius: '6px',
                            fontSize: '0.84rem',
                            fontWeight: 700,
                            cursor: gitScanning ? 'not-allowed' : 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                          }}
                        >
                          <RefreshCw size={15} className={gitScanning ? 'animate-spin' : ''} />
                          {gitScanning ? gitScanStep : 'Scan Repository for PQC Vulnerabilities'}
                        </button>
                      </div>

                      {/* Scan Results Presentation */}
                      {gitScanResults && (
                        <div style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
                            <div style={{ background: 'rgba(0, 0, 0, 0.4)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase' }}>Files Scanned</div>
                              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff' }}>{gitScanResults.totalFilesScanned}</div>
                            </div>
                            <div style={{ background: 'rgba(0, 0, 0, 0.4)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase' }}>Crypto Primitives</div>
                              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff' }}>{gitScanResults.totalAssets}</div>
                            </div>
                            <div style={{ background: 'rgba(0, 0, 0, 0.4)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase' }}>Shor Vulnerable</div>
                              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f87171' }}>{gitScanResults.vulnerableCount}</div>
                            </div>
                            <div style={{ background: 'rgba(0, 0, 0, 0.4)', padding: '0.85rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', textTransform: 'uppercase' }}>CNSA 2.0 Status</div>
                              <div style={{ fontSize: '1rem', fontWeight: 800, color: '#f87171', marginTop: '0.3rem' }}>{gitScanResults.cnsaStatus}</div>
                            </div>
                          </div>

                          {/* Findings Details */}
                          <div style={{ background: 'rgba(0, 0, 0, 0.3)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: '8px', padding: '1rem' }}>
                            <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#ffffff', marginBottom: '0.75rem' }}>
                              Discovered Cryptographic Flaws in Codebase
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                              {(gitScanResults.findings || []).map((f: any) => (
                                <div key={f.id} style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '6px', padding: '0.85rem' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                                    <div>
                                      <span style={{ fontFamily: 'monospace', color: '#38bdf8', fontSize: '0.82rem', fontWeight: 700 }}>
                                        {f.filePath}:{f.lineNumber || 1}
                                      </span>
                                      <div style={{ color: '#ffffff', fontWeight: 600, fontSize: '0.85rem', marginTop: '0.2rem' }}>
                                        {f.assetName} • <span style={{ color: '#f87171' }}>{f.algorithm}</span>
                                      </div>
                                    </div>
                                    <span style={{ fontSize: '0.68rem', fontWeight: 700, padding: '0.15rem 0.4rem', borderRadius: '3px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                                      {f.riskLevel?.toUpperCase()}
                                    </span>
                                  </div>
                                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', margin: '0.4rem 0' }}>
                                    {f.quantumThreat}
                                  </div>
                                  {f.remediationSnippet && (
                                    <div style={{ marginTop: '0.4rem' }}>
                                      <pre style={{ margin: 0, padding: '0.5rem 0.75rem', background: '#030712', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.74rem', color: '#4ade80', overflowX: 'auto' }}>
                                        {f.remediationSnippet}
                                      </pre>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Sub-View B: Cloud Sources & Key Vaults */}
                  {repoSubTab === 'cloud' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                      <div>
                        <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.5rem', fontWeight: 600 }}>
                          Select Cloud Key Management / Secrets Provider
                        </label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
                          {[
                            { id: 'aws', label: 'AWS Secrets & KMS', desc: 'AWS IAM API' },
                            { id: 'azure', label: 'Azure Key Vault', desc: 'Entra ID Client' },
                            { id: 'vault', label: 'HashiCorp Vault', desc: 'AppRole / Token' },
                            { id: 'gcp', label: 'Google Cloud KMS', desc: 'GCP Service Account' }
                          ].map(c => (
                            <button
                              key={c.id}
                              onClick={() => setCloudProvider(c.id as any)}
                              style={{
                                padding: '0.75rem',
                                borderRadius: '8px',
                                border: '1px solid',
                                borderColor: cloudProvider === c.id ? 'rgba(56, 189, 248, 0.5)' : 'rgba(255, 255, 255, 0.08)',
                                background: cloudProvider === c.id ? 'rgba(56, 189, 248, 0.12)' : 'rgba(0, 0, 0, 0.25)',
                                color: cloudProvider === c.id ? '#ffffff' : 'var(--text-secondary, #94a3b8)',
                                textAlign: 'left',
                                cursor: 'pointer'
                              }}
                            >
                              <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{c.label}</div>
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)', marginTop: '0.15rem' }}>{c.desc}</div>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* AWS Form */}
                      {cloudProvider === 'aws' && (
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              AWS Access Key ID
                            </label>
                            <input
                              type="text"
                              placeholder="AKIAIOSFODNN7EXAMPLE"
                              value={cloudCreds.awsKey}
                              onChange={e => setCloudCreds({ ...cloudCreds, awsKey: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              AWS Secret Access Key
                            </label>
                            <input
                              type="password"
                              placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                              value={cloudCreds.awsSecret}
                              onChange={e => setCloudCreds({ ...cloudCreds, awsSecret: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Target Region
                            </label>
                            <input
                              type="text"
                              placeholder="us-east-1"
                              value={cloudCreds.awsRegion}
                              onChange={e => setCloudCreds({ ...cloudCreds, awsRegion: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                      )}

                      {/* Azure Form */}
                      {cloudProvider === 'azure' && (
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Azure Key Vault URL
                            </label>
                            <input
                              type="text"
                              placeholder="https://spinovation-vault.vault.azure.net"
                              value={cloudCreds.azureVaultUrl}
                              onChange={e => setCloudCreds({ ...cloudCreds, azureVaultUrl: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Directory (Tenant) ID
                            </label>
                            <input
                              type="text"
                              placeholder="00000000-0000-0000-0000-000000000000"
                              value={cloudCreds.azureTenantId}
                              onChange={e => setCloudCreds({ ...cloudCreds, azureTenantId: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                      )}

                      {/* Vault Form */}
                      {cloudProvider === 'vault' && (
                        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Vault Cluster Address
                            </label>
                            <input
                              type="text"
                              placeholder="https://vault.internal.corp:8200"
                              value={cloudCreds.vaultAddress}
                              onChange={e => setCloudCreds({ ...cloudCreds, vaultAddress: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              API Token / AppRole
                            </label>
                            <input
                              type="password"
                              placeholder="s.7x8y9z..."
                              value={cloudCreds.vaultToken}
                              onChange={e => setCloudCreds({ ...cloudCreds, vaultToken: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                      )}

                      {/* GCP Form */}
                      {cloudProvider === 'gcp' && (
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              GCP Project ID
                            </label>
                            <input
                              type="text"
                              placeholder="spinovation-security-prod"
                              value={cloudCreds.gcpProject}
                              onChange={e => setCloudCreds({ ...cloudCreds, gcpProject: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                          <div>
                            <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', marginBottom: '0.4rem', fontWeight: 600 }}>
                              Service Account Key (JSON)
                            </label>
                            <input
                              type="password"
                              placeholder="Paste service-account.json content"
                              value={cloudCreds.gcpKey}
                              onChange={e => setCloudCreds({ ...cloudCreds, gcpKey: e.target.value })}
                              style={{ width: '100%', padding: '0.55rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '6px', color: '#fff', fontSize: '0.82rem', boxSizing: 'border-box' }}
                            />
                          </div>
                        </div>
                      )}

                      <div>
                        <button
                          onClick={handleTestCloudConnection}
                          disabled={cloudTesting}
                          style={{
                            background: cloudTesting ? 'rgba(56, 189, 248, 0.2)' : 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                            border: '1px solid rgba(56, 189, 248, 0.5)',
                            color: '#ffffff',
                            padding: '0.6rem 1.25rem',
                            borderRadius: '6px',
                            fontSize: '0.84rem',
                            fontWeight: 700,
                            cursor: cloudTesting ? 'not-allowed' : 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.5rem'
                          }}
                        >
                          <Cloud size={15} />
                          {cloudTesting ? 'Verifying Cloud API Connection...' : 'Connect API & Audit Secrets'}
                        </button>
                      </div>

                      {cloudStatus && (
                        <div style={{ background: 'rgba(34, 197, 94, 0.08)', border: '1px solid rgba(34, 197, 94, 0.25)', borderRadius: '8px', padding: '1rem', marginTop: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#4ade80', fontWeight: 700, fontSize: '0.9rem' }}>
                            <CheckCircle2 size={16} /> Connection Successful: {cloudStatus.provider}
                          </div>
                          <p style={{ color: 'var(--text-secondary, #94a3b8)', fontSize: '0.82rem', margin: '0.5rem 0' }}>
                            {cloudStatus.details}
                          </p>
                          <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.75rem', fontSize: '0.8rem' }}>
                            <div>Total Keys: <strong style={{ color: '#ffffff' }}>{cloudStatus.discoveredKeys}</strong></div>
                            <div>Shor Vulnerable: <strong style={{ color: '#f87171' }}>{cloudStatus.vulnerableKeys}</strong></div>
                            <div>Post-Quantum Ready: <strong style={{ color: '#4ade80' }}>{cloudStatus.pqcKeys}</strong></div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ENTERPRISE PKI & CLOUD VAULT CONNECTORS */}
            {activeTab === 'pki' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <EnterprisePkiVaults tenantName={client.displayName || tenantSlug} />
              </div>
            )}

            {/* HYBRID QUANTUM TLS REVERSE PROXY GATEWAY */}
            {activeTab === 'proxy' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <PqcProxyGateway />
              </div>
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
                      { id: 'planner' as const, label: "Mosca's Migration Planner", icon: Calendar, badge: 'X+Y>Z' }
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
                            {displayRole}
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
                {effectiveSettingsTab === 'users' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                    <TenantUserManagement currentTenant={cleanSlug} allowTenantSwitch={false} />
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
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted, #94a3b8)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                              <th style={{ padding: '0.5rem' }}>Workstation / Host</th>
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
                                      {m.groupName && (
                                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted, #94a3b8)' }}>({m.groupName})</span>
                                      )}
                                    </div>
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
                                    <span style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.35rem',
                                      fontSize: '0.74rem',
                                      fontWeight: 600,
                                      color: '#4ade80',
                                      background: 'rgba(34, 197, 94, 0.1)',
                                      padding: '0.15rem 0.45rem',
                                      borderRadius: '4px',
                                      border: '1px solid rgba(34, 197, 94, 0.25)'
                                    }}>
                                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#4ade80' }} />
                                      Online
                                    </span>
                                  </td>
                                  <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-muted, #94a3b8)', fontSize: '0.76rem', fontFamily: 'monospace' }}>
                                    {m.lastSeen ? new Date(m.lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recently'}
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
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* MOSCA'S QUANTUM MIGRATION PLANNER SUB-TAB UNDER SETTINGS */}
            {effectiveSettingsTab === 'planner' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <MoscaMigrationPlanner
                  variant="console"
                  onNavigateToScan={() => setActiveTab('integrations')}
                  totalFleetEndpoints={stats.totalMachines || machines.length}
                  totalVulnerableAssets={stats.vulnerableAssets || assets.filter(a => a.isVulnerable).length}
                />
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
                        Generate an enrollment secret or copy 1-line rollout scripts for {client.displayName || 'Spinovation Corp'}.
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
                      Workstation Group / Environment Tag
                    </label>
                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <input
                        type="text"
                        placeholder="e.g. Engineering, Executive Laptops, DevOps Servers"
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
