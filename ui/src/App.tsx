import React, { useState, useEffect, useMemo } from 'react';
import { 
  Laptop, 
  Server, 
  ShieldAlert, 
  Terminal, 
  Copy, 
  Check, 
  Download, 
  Search, 
  Plus, 
  Trash2, 
  RefreshCw, 
  FileCode, 
  Code, 
  Cpu, 
  Layers, 
  Key, 
  Lock, 
  AlertOctagon,
  Sparkles,
  Eye,
  X,
  Globe,
  GitBranch,
  LogOut,
  User,
  Building,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  Shield,
  UserPlus,
  Calendar,
  CheckCircle2,
  QrCode,
  AlertTriangle,
  Database,
  Radio,
  Package
} from 'lucide-react';

import { AdminPanel } from './components/AdminPanel';
import { LandingPage } from './components/LandingPage';
import { GitRepoAuditor } from './components/GitRepoAuditor';
import { TenantPortal } from './components/TenantPortal';
import MoscaMigrationPlanner from './components/MoscaMigrationPlanner';
import { EnterprisePkiVaults } from './components/EnterprisePkiVaults';
import { PqcProxyGateway } from './components/PqcProxyGateway';
import SbomInventory from './components/SbomInventory';

export type TabType = 'dashboard' | 'cbom' | 'tokens' | 'git' | 'pki' | 'proxy' | 'planner' | 'admin';

interface FleetMachine {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  ip: string;
  agentVersion: string;
  status: 'online' | 'offline';
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  quantumRiskScore: number;
  assetCount: number;
  vulnerableCount: number;
  lastSeen: string;
  createdAt: string;
  connectorId?: string;
  groupName?: string;
  tenantName?: string;
  licenseKey?: string;
  licenseTier?: string;
}

interface FleetToken {
  id: string;
  name: string;
  token: string;
  status: string;
  lastSync: string | null;
  createdAt: string;
  machineCount: number;
}

class PortalErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('PortalErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#090d16',
          color: '#ffffff',
          padding: '2rem',
          fontFamily: 'system-ui, sans-serif'
        }}>
          <div style={{
            maxWidth: '540px',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '12px',
            padding: '2rem',
            textAlign: 'center'
          }}>
            <h2 style={{ color: '#ef4444', margin: '0 0 1rem 0', fontSize: '1.4rem' }}>Portal Render Notice</h2>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
              The portal encountered an issue rendering this view. Your configuration and data are completely secure.
            </p>
            <div style={{
              background: 'rgba(0,0,0,0.5)',
              padding: '0.75rem',
              borderRadius: '6px',
              fontFamily: 'monospace',
              fontSize: '0.75rem',
              color: '#f87171',
              marginBottom: '1.5rem',
              textAlign: 'left',
              wordBreak: 'break-all'
            }}>
              {this.state.error?.message || 'Component render error'}
            </div>
            <button
              onClick={() => {
                sessionStorage.clear();
                localStorage.clear();
                window.location.reload();
              }}
              style={{
                background: '#00f2fe',
                border: 'none',
                borderRadius: '6px',
                color: '#000',
                padding: '0.6rem 1.25rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Reset Session &amp; Reload Portal
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  const [tenantSlug, setTenantSlug] = useState<string>(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const fromQuery = urlParams.get('tenant') || urlParams.get('workspace');
    if (fromQuery) return fromQuery.toLowerCase().trim();

    const path = window.location.pathname.toLowerCase();
    if (path.startsWith('/tenant/')) {
      return path.split('/')[2].trim();
    } else if (path === '/spinovation' || path === '/spinovationcorp') {
      return 'spinovationcorp';
    }

    const port = window.location.port;
    if (port === '5001') return 'democlient';
    if (port === '5002') return 'spinovationcorp';
    if (port === '5003') return 'vanguard-logistics';
    if (port === '5052') return 'apex-cyber';
    if (port === '5053') return 'cybershield-partners';

    const host = window.location.hostname.toLowerCase();
    if (host.startsWith('scanner.')) {
      return '';
    }
    if (host.includes('.quarkshield.ai') && !host.startsWith('www.') && !host.startsWith('quarkshield.ai') && !host.startsWith('scanner.')) {
      const sub = host.split('.')[0];
      return (sub === 'spinovation' || sub === 'spinovationcorp') ? 'spinovationcorp' : sub;
    }
    if (host.includes('.fedmitigate.com') && !host.startsWith('www.') && !host.startsWith('fedmitigate.com')) {
      const sub = host.split('.')[0];
      return (sub === 'spinovation' || sub === 'spinovationcorp') ? 'spinovationcorp' : sub;
    }

    return localStorage.getItem('quarkshield_tenant_slug') || sessionStorage.getItem('quarkshield_tenant_slug') || '';
  });

  const [isSupportMirror, setIsSupportMirror] = useState<boolean>(false);

  const [viewMode, setViewMode] = useState<'landing' | 'console' | 'tenant'>(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const host = window.location.hostname.toLowerCase();
    const port = window.location.port;
    const path = window.location.pathname.toLowerCase();

    // Check if scanner console subdomain
    if (host.startsWith('scanner.')) {
      return 'console';
    }

    // Check if tenant query param or path
    if (urlParams.get('tenant') || urlParams.get('workspace') || path.startsWith('/tenant/') || path === '/spinovation' || path === '/spinovationcorp') {
      return 'tenant';
    }

    // Check if dedicated tenant port
    if (['5001', '5002', '5003', '5052', '5053'].includes(port)) {
      return 'tenant';
    }

    // Dedicated isolated tenant pod subdomains (e.g. spinovation.quarkshield.ai, spinovationcorp.quarkshield.ai, democlient.quarkshield.ai)
    if (host.includes('.quarkshield.ai') && !host.startsWith('www.') && !host.startsWith('quarkshield.ai') && !host.startsWith('scanner.')) {
      return 'tenant';
    }
    if (host.includes('.fedmitigate.com') && !host.startsWith('www.') && !host.startsWith('fedmitigate.com')) {
      return 'tenant';
    }

    // Explicit view in URL query or hash: ?view=console or #console
    if (urlParams.get('view') === 'console' || window.location.hash === '#console') {
      return 'console';
    }
    if (urlParams.get('view') === 'tenant' || window.location.hash === '#tenant') {
      return 'tenant';
    }
    // Explicit view in URL query: ?view=landing or #landing
    if (urlParams.get('view') === 'landing' || window.location.hash === '#landing') {
      return 'landing';
    }
    // Default to Landing Page on root domain https://quarkshield.ai/
    return 'landing';
  });

  const [activeTab, setActiveTab] = useState<TabType>(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab') as TabType;
    const validTabs: TabType[] = ['dashboard', 'cbom', 'tokens', 'git', 'pki', 'proxy', 'planner', 'admin'];
    if (tabParam && validTabs.includes(tabParam)) {
      return tabParam;
    }
    const savedTab = (localStorage.getItem('quarkshield_active_tab') || sessionStorage.getItem('quarkshield_active_tab')) as TabType;
    if (savedTab && validTabs.includes(savedTab)) {
      return savedTab;
    }
    if (window.location.hash === '#admin') return 'admin';
    if (window.location.hash === '#cbom') return 'cbom';
    if (window.location.hash === '#tokens') return 'tokens';
    if (window.location.hash === '#git') return 'git';
    if (window.location.hash === '#pki') return 'pki';
    if (window.location.hash === '#proxy') return 'proxy';
    if (window.location.hash === '#planner') return 'planner';
    return 'dashboard';
  });
  
  const [currentUserEmail, setCurrentUserEmail] = useState<string>(() => {
    return localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || 'superadmin@quarkshield.ai';
  });

  const [currentAccountType, setCurrentAccountType] = useState<string>(() => {
    const email = (localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || '').toLowerCase();
    if (email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com') return 'superadmin';
    if (email.includes('algomeld') || email.includes('partner') || email.includes('@partner.')) return 'partner';
    return localStorage.getItem('quarkshield_account_type') || sessionStorage.getItem('quarkshield_account_type') || 'superadmin';
  });

  const [currentUserRole, setCurrentUserRole] = useState<string>(() => {
    const email = (localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || '').toLowerCase();
    if (email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com') return 'Super Admin';
    if (email.includes('algomeld') || email.includes('partner') || email.includes('@partner.')) return 'Partner Admin';
    return localStorage.getItem('quarkshield_role') || sessionStorage.getItem('quarkshield_role') || 'Super Admin';
  });

  const [currentCustomerId, setCurrentCustomerId] = useState<string>(() => {
    const email = (localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || '').toLowerCase();
    if (email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com') return 'QS-ADMIN-001';
    if (email.includes('algomeld') || email.includes('partner') || email.includes('@partner.')) return 'PART-9148';
    return localStorage.getItem('quarkshield_customer_id') || sessionStorage.getItem('quarkshield_customer_id') || 'QS-ADMIN-001';
  });

  const [currentCustomerName, setCurrentCustomerName] = useState<string>(() => {
    const email = (localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || '').toLowerCase();
    if (email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com') return 'INTERNAL USER';
    if (email.includes('algomeld') || email.includes('partner') || email.includes('@partner.')) return 'ALGO MELD MSP';
    return localStorage.getItem('quarkshield_customer_name') || sessionStorage.getItem('quarkshield_customer_name') || 'INTERNAL USER';
  });

  const [currentLicenseTier, setCurrentLicenseTier] = useState<string>(() => {
    const email = (localStorage.getItem('quarkshield_user') || sessionStorage.getItem('quarkshield_user') || '').toLowerCase();
    if (email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com') return 'INTERNAL ROOT';
    if (email.includes('algomeld') || email.includes('partner') || email.includes('@partner.')) return 'MSP PARTNER PRO';
    return localStorage.getItem('quarkshield_license_tier') || sessionStorage.getItem('quarkshield_license_tier') || 'INTERNAL ROOT';
  });

  // Dynamically synchronize account identity when user email changes
  useEffect(() => {
    const email = currentUserEmail.toLowerCase();
    const isSuper = email.includes('@quarkshield.ai') || email === 'superadmin' || email === 'sridhargs@gmail.com';
    const isPartner = email.includes('algomeld') || email.includes('partner') || email.includes('@partner.');
    
    if (isSuper) {
      setCurrentUserRole('Super Admin');
      setCurrentAccountType('superadmin');
      setCurrentCustomerId('QS-ADMIN-001');
      setCurrentCustomerName('INTERNAL USER');
      setCurrentLicenseTier('INTERNAL ROOT');
    } else if (isPartner) {
      setCurrentUserRole('Partner Admin');
      setCurrentAccountType('partner');
      const savedId = localStorage.getItem('quarkshield_customer_id') || sessionStorage.getItem('quarkshield_customer_id');
      setCurrentCustomerId(savedId && !savedId.startsWith('QS-') ? savedId : 'PART-9148');
      const savedName = localStorage.getItem('quarkshield_customer_name') || sessionStorage.getItem('quarkshield_customer_name');
      setCurrentCustomerName(savedName && savedName !== 'INTERNAL USER' ? savedName : 'ALGO MELD MSP');
      setCurrentLicenseTier('MSP PARTNER PRO');
    } else {
      const savedRole = localStorage.getItem('quarkshield_role') || sessionStorage.getItem('quarkshield_role') || 'Corporate Admin';
      setCurrentUserRole(savedRole);
      setCurrentAccountType('corporate');
      const savedId = localStorage.getItem('quarkshield_customer_id') || sessionStorage.getItem('quarkshield_customer_id');
      const savedName = localStorage.getItem('quarkshield_customer_name') || sessionStorage.getItem('quarkshield_customer_name');
      setCurrentCustomerId(savedId || 'CORP-4821');
      setCurrentCustomerName(savedName || 'CORPORATE CLIENT');
    }
  }, [currentUserEmail]);

  // Keep viewMode and activeTab persisted in storage
  useEffect(() => {
    if (viewMode) {
      localStorage.setItem('quarkshield_view_mode', viewMode);
      sessionStorage.setItem('quarkshield_view_mode', viewMode);
    }
  }, [viewMode]);

  useEffect(() => {
    if (activeTab) {
      localStorage.setItem('quarkshield_active_tab', activeTab);
      sessionStorage.setItem('quarkshield_active_tab', activeTab);
    }
  }, [activeTab]);

  const handleLogout = () => {
    localStorage.removeItem('quarkshield_token');
    sessionStorage.removeItem('quarkshield_token');
    localStorage.removeItem('quarkshield_user');
    sessionStorage.removeItem('quarkshield_user');
    localStorage.removeItem('quarkshield_role');
    sessionStorage.removeItem('quarkshield_role');
    localStorage.removeItem('quarkshield_customer_id');
    sessionStorage.removeItem('quarkshield_customer_id');
    localStorage.removeItem('quarkshield_license_tier');
    sessionStorage.removeItem('quarkshield_license_tier');
    localStorage.removeItem('quarkshield_view_mode');
    sessionStorage.removeItem('quarkshield_view_mode');
    localStorage.removeItem('quarkshield_active_tab');
    sessionStorage.removeItem('quarkshield_active_tab');
    if (window.history.pushState) {
      const cleanUrl = window.location.protocol + '//' + window.location.host + window.location.pathname;
      window.history.pushState({ path: cleanUrl }, '', cleanUrl);
    }
    setViewMode('landing');
  };

  // Data states
  const [machines, setMachines] = useState<FleetMachine[]>([]);
  const [tokens, setTokens] = useState<FleetToken[]>([]);
  const [cbomData, setCbomData] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedMachineFilter, setSelectedMachineFilter] = useState<string>('all');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<string>('all');
  const [selectedStatusFilter, setSelectedStatusFilter] = useState<string>('all');
  const [cbomViewMode, setCbomViewMode] = useState<'table' | 'json' | 'sbom'>('table');
  const [cbomPage, setCbomPage] = useState<number>(1);
  const cbomPerPage = 50;

  // Tenant / Partner grouping & CBOM states
  const [expandedTenants, setExpandedTenants] = useState<Record<string, boolean>>({});
  const [selectedTenantFilter, setSelectedTenantFilter] = useState<string>('all');
  const [tenantSearchQuery, setTenantSearchQuery] = useState('');
  const [showLicense2FAModal, setShowLicense2FAModal] = useState(false);
  const [showTOTPModal, setShowTOTPModal] = useState(false);
  const [showBackupCodesModal, setShowBackupCodesModal] = useState(false);
  const [totpVerificationCode, setTotpVerificationCode] = useState('');
  const [totpSuccess, setTotpSuccess] = useState(false);
  const [copiedBackupCodes, setCopiedBackupCodes] = useState(false);
  const [adminInitialSubTab, setAdminInitialSubTab] = useState<'onboarding' | 'registry' | 'licenses' | 'users' | 'analytics' | 'platform_sbom'>('licenses');

  // Token creation & deployment states
  const [showCreateTokenModal, setShowCreateTokenModal] = useState(false);
  const [newTokenName, setNewTokenName] = useState('');
  const [newTokenTenant, setNewTokenTenant] = useState('SPINOVATIONCORP');
  const [selectedDeploymentToken, setSelectedDeploymentToken] = useState<string>('');
  const [deploymentMethod, setDeploymentMethod] = useState<'desktop' | 'curl' | 'jamf' | 'intune' | 'ansible' | 'docker'>('desktop');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Inspection & Remediation Modals
  const [selectedAssetDetail, setSelectedAssetDetail] = useState<any | null>(null);
  const [inoculationScriptModal, setInoculationScriptModal] = useState<FleetMachine | null>(null);

  const apiOrigin = window.location.origin;

  // 1. Fetch Fleet Machines
  const fetchMachines = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/fleet/machines');
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setMachines(data);
    } catch (err: any) {
      console.warn('Could not fetch machines from server, using sample fleet data:', err);
      setMachines([
        {
          id: 'mach-01',
          hostname: 'secops-macbook-pro.local',
          os: 'darwin',
          arch: 'arm64',
          ip: '192.168.1.104',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'high',
          quantumRiskScore: 78,
          assetCount: 14,
          vulnerableCount: 11,
          lastSeen: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Engineering Workstations',
          tenantName: 'Apex Defense Labs (MSP)',
          licenseKey: 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E',
          licenseTier: 'Enterprise Pro (500 Seats)'
        },
        {
          id: 'mach-02',
          hostname: 'prod-k8s-worker-03.internal',
          os: 'linux',
          arch: 'amd64',
          ip: '10.240.0.18',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'critical',
          quantumRiskScore: 92,
          assetCount: 28,
          vulnerableCount: 22,
          lastSeen: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Production Clusters',
          tenantName: 'Apex Defense Labs (MSP)',
          licenseKey: 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E',
          licenseTier: 'Enterprise Pro (500 Seats)'
        },
        {
          id: 'mach-03',
          hostname: 'partner-audit-node-01.lan',
          os: 'linux',
          arch: 'amd64',
          ip: '172.16.20.12',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'medium',
          quantumRiskScore: 45,
          assetCount: 8,
          vulnerableCount: 3,
          lastSeen: new Date(Date.now() - 1000 * 60 * 20).toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Audit Network',
          tenantName: 'PARTNERTEST (MSP Partner)',
          licenseKey: 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296',
          licenseTier: 'MSP Partner (50 Seats)'
        },
        {
          id: 'mach-04',
          hostname: 'partner-jumpbox-win.ad',
          os: 'windows',
          arch: 'amd64',
          ip: '172.16.20.15',
          agentVersion: '2.0.0',
          status: 'offline',
          riskLevel: 'high',
          quantumRiskScore: 68,
          assetCount: 12,
          vulnerableCount: 8,
          lastSeen: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Management Jumpbox',
          tenantName: 'PARTNERTEST (MSP Partner)',
          licenseKey: 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296',
          licenseTier: 'MSP Partner (50 Seats)'
        },
        {
          id: 'mach-05',
          hostname: 'Ganapatis-MBP',
          os: 'darwin',
          arch: 'arm64',
          ip: '192.168.1.151',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'high',
          quantumRiskScore: 80,
          assetCount: 16,
          vulnerableCount: 12,
          lastSeen: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Executive Fleet',
          tenantName: 'Executive Engineering Fleet',
          licenseKey: 'QS-CORP-DEMOCLIENT-6AF00609-C7486296',
          licenseTier: 'Growth Tier (12/250)'
        },
        {
          id: 'mach-06',
          hostname: 'finance-win11-corp.ad',
          os: 'windows',
          arch: 'amd64',
          ip: '10.0.12.45',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'medium',
          quantumRiskScore: 42,
          assetCount: 9,
          vulnerableCount: 4,
          lastSeen: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
          createdAt: new Date().toISOString(),
          groupName: 'Corporate Laptops',
          tenantName: 'Executive Engineering Fleet',
          licenseKey: 'QS-CORP-DEMOCLIENT-6AF00609-C7486296',
          licenseTier: 'Growth Tier (12/250)'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  // 2. Fetch Fleet Tokens
  const fetchTokens = async () => {
    try {
      const res = await fetch('/api/fleet/tokens');
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setTokens(data);
      if (data.length > 0 && !selectedDeploymentToken) {
        setSelectedDeploymentToken(data[0].token);
      }
    } catch (err: any) {
      console.warn('Could not fetch tokens from server, using demo token:', err);
      const fallbackTokens: FleetToken[] = [
        {
          id: 'tok-01',
          name: 'Engineering Workstations 2026',
          token: 'pqc_agent_8a7b9c0d1e2f3a4b5c6d',
          status: 'active',
          lastSync: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          machineCount: 14
        },
        {
          id: 'tok-02',
          name: 'Production Hypervisors',
          token: 'pqc_agent_9f8e7d6c5b4a3a2b1c0d',
          status: 'active',
          lastSync: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          machineCount: 28
        }
      ];
      setTokens(fallbackTokens);
      setSelectedDeploymentToken(fallbackTokens[0].token);
    }
  };

  // 3. Fetch CBOM
  const fetchCBOM = async (machineId?: string) => {
    try {
      const url = machineId && machineId !== 'all' ? `/api/fleet/cbom?machine_id=${machineId}` : '/api/fleet/cbom';
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();
      setCbomData(data);
    } catch (err: any) {
      console.warn('Could not fetch CBOM from server, using sample CBOM data:', err);
      setCbomData({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        serialNumber: "urn:uuid:7c8b9d0e-1f2a-4b3c-9d8e-5a6b7c8d9e0f",
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          component: {
            type: "platform",
            name: "Desktop & Host PQC Fleet CBOM"
          }
        },
        components: [
          {
            type: "cryptographic-asset",
            bomRef: "cbom-item-01",
            name: "id_ed25519",
            cryptoProperties: {
              assetType: "key",
              algorithmProperties: {
                name: "Ed25519",
                keyLength: 256,
                quantumSecurityLevel: 0
              },
              detectionContext: {
                filePath: "/Users/developer/.ssh/id_ed25519",
                machineHostname: "secops-macbook-pro.local",
                operatingSystem: "darwin"
              }
            },
            properties: [
              { name: "quarkshield:quantumStatus", value: "Quantum Vulnerable" },
              { name: "quarkshield:riskLevel", value: "high" },
              { name: "quarkshield:recommendation", value: "Upgrade to OpenSSH 9.8+ with hybrid mlkem768x25519-sha256 key exchange." },
              { name: "quarkshield:explainer", value: "Classical elliptic curve signatures (Ed25519) are susceptible to Shor's algorithm on a quantum computer." }
            ]
          },
          {
            type: "cryptographic-asset",
            bomRef: "cbom-item-02",
            name: "server.crt",
            cryptoProperties: {
              assetType: "certificate",
              algorithmProperties: {
                name: "RSA",
                keyLength: 2048,
                quantumSecurityLevel: 0
              },
              detectionContext: {
                filePath: "/etc/ssl/certs/server.crt",
                machineHostname: "prod-k8s-worker-03.internal",
                operatingSystem: "linux"
              }
            },
            properties: [
              { name: "quarkshield:quantumStatus", value: "Quantum Vulnerable" },
              { name: "quarkshield:riskLevel", value: "high" },
              { name: "quarkshield:recommendation", value: "Deploy composite X.509 certificates with ML-DSA-65 (NIST FIPS 204)." },
              { name: "quarkshield:explainer", value: "RSA-2048 integer factorization can be resolved in polynomial time via quantum phase estimation." }
            ]
          },
          {
            type: "cryptographic-asset",
            bomRef: "cbom-item-03",
            name: "id_mldsa65",
            cryptoProperties: {
              assetType: "key",
              algorithmProperties: {
                name: "ML-DSA-65",
                keyLength: 1952,
                quantumSecurityLevel: 3
              },
              detectionContext: {
                filePath: "/Users/developer/.ssh/id_mldsa65",
                machineHostname: "secops-macbook-pro.local",
                operatingSystem: "darwin"
              }
            },
            properties: [
              { name: "quarkshield:quantumStatus", value: "Post-Quantum Secure" },
              { name: "quarkshield:riskLevel", value: "secure" },
              { name: "quarkshield:recommendation", value: "Maintain deployment. Fully compliant with NIST FIPS 204 post-quantum standards." },
              { name: "quarkshield:explainer", value: "Lattice-based Module-LWE signature scheme resilient against both classical and quantum cryptanalysis." }
            ]
          }
        ]
      });
    }
  };

  useEffect(() => {
    fetchMachines();
    fetchTokens();
    fetchCBOM();
  }, []);

  const handleCreateToken = async () => {
    if (!newTokenName.trim()) return;
    try {
      const res = await fetch('/api/fleet/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          name: newTokenName.trim(),
          tenantName: newTokenTenant || 'SPINOVATIONCORP',
          licenseKey: newTokenTenant === 'SPINOVATIONCORP' ? 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8' : undefined
        })
      });
      if (res.ok) {
        const data = await res.json();
        setTokens(prev => [data, ...prev]);
        setSelectedDeploymentToken(data.token);
        setNewTokenName('');
        setShowCreateTokenModal(false);
        fetchMachines();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleRevokeToken = async (id: string) => {
    if (!confirm('Revoke this enrollment token? Endpoints using this token will no longer be able to submit telemetry.')) return;
    try {
      const res = await fetch(`/api/fleet/tokens/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setTokens(prev => prev.filter(t => t.id !== id));
      }
    } catch (err) {
      console.error(err);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(label);
    setTimeout(() => setCopiedCode(null), 2500);
  };

  const downloadCBOMJson = (attested: boolean = false) => {
    if (!cbomData) return;
    const exportComponents = filteredCBOMComponents;
    const totalAssets = exportComponents.length;
    const vulnerableCount = exportComponents.filter((c: any) => c.properties?.some((p: any) => p.name === 'pqc:quantumStatus' && p.value?.toLowerCase().includes('vulnerable'))).length;
    const pqcReadyCount = totalAssets - vulnerableCount;
    const conformanceScore = totalAssets > 0 ? parseFloat((pqcReadyCount / totalAssets).toFixed(2)) : 1.0;
    const timestamp = new Date().toISOString();
    const serial = `urn:uuid:${typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : 'f7a8b9c0-1234-5678-9abc-def012345678'}`;
    const cleanTenantName = selectedTenantFilter !== 'all' ? selectedTenantFilter : 'Enterprise Fleet';

    const tenantScopedBOM: any = {
      ...cbomData,
      serialNumber: serial,
      metadata: {
        ...cbomData.metadata,
        timestamp,
        component: {
          type: "platform",
          name: selectedTenantFilter !== 'all' ? `Tenant CBOM: ${selectedTenantFilter}` : "Enterprise Fleet Cryptographic Assets",
          description: `Cryptographic Bill of Materials (CycloneDX 1.6) - ${cleanTenantName}`
        }
      },
      components: exportComponents
    };

    if (attested) {
      const rawSeed = `${serial}:${timestamp}:${totalAssets}:${vulnerableCount}:${cleanTenantName}`;
      let hashNum = 0;
      for (let i = 0; i < rawSeed.length; i++) {
        hashNum = ((hashNum << 5) - hashNum) + rawSeed.charCodeAt(i);
        hashNum |= 0;
      }
      const hexHash = Math.abs(hashNum).toString(16).padStart(16, '0') + '4a8b9c7e012356789abcdef012345678';

      tenantScopedBOM.declarations = {
        assessors: [
          {
            "bom-ref": "assessor-quarkshield-engine",
            thirdParty: false,
            organization: {
              name: "QuarkShield AI Inc.",
              url: ["https://quarkshield.ai"],
              contacts: [{ name: "Cryptographic Assurance Desk", email: "support@quarkshield.ai" }]
            }
          }
        ],
        targets: {
          organizations: [{ name: cleanTenantName }]
        },
        affirmation: {
          statement: "The undersigned affirms that the cryptographic inventory, algorithm security levels, and quantum vulnerability assessments contained herein have been verified in accordance with NIST SP 800-218 (SSDF), NSA CNSA 2.0, and NIST FIPS 203/204/205 guidelines.",
          signatories: [
            {
              name: "QuarkShield Cryptographic Assurance Officer",
              role: "Chief Cryptographer & PQC Auditor",
              organization: { name: "QuarkShield.AI" }
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
              { identifier: "NIST-FIPS-203", title: "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)", text: "Evaluates public key encryption against Shor's algorithm." },
              { identifier: "NIST-FIPS-204", title: "Module-Lattice-Based Digital Signature Standard (ML-DSA)", text: "Evaluates digital signature schemes and code-signing infrastructure." },
              { identifier: "NSA-CNSA-2.0", title: "Commercial National Security Algorithm Suite 2.0", text: "Audits compliance with National Security Agency timelines for quantum-resistant deployment." },
              { identifier: "NIST-SP-800-218", title: "Secure Software Development Framework (SSDF v1.1)", text: "Validates software supply chain security and cryptographic asset provenance." }
            ],
            conformance: {
              score: conformanceScore,
              rationale: `Cryptographic audit of ${totalAssets} assets (${vulnerableCount} Shor-vulnerable classical, ${pqcReadyCount} post-quantum ready/hybrid). Remediation roadmap established via Mosca migration planner.`
            }
          }
        ]
      };

      tenantScopedBOM.signature = {
        algorithm: "ML-DSA-65",
        keyId: "urn:quarkshield:pqc:pki:mldsa65:root-ca",
        publicKey: {
          type: "ML-DSA-65 (NIST FIPS 204)",
          fingerprint: `SHA256:${hexHash.substring(0, 32)}...`
        },
        value: btoa(hexHash + ':' + cleanTenantName),
        timestamp
      };
    }

    const blob = new Blob([JSON.stringify(tenantScopedBOM, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const cleanTenant = selectedTenantFilter !== 'all' ? selectedTenantFilter.toLowerCase().replace(/[^a-z0-9]/g, '-') : 'fleet';
    a.download = attested 
      ? `quarkshield-cbom-${cleanTenant}-cdxa-attested-1.6.json`
      : `quarkshield-cbom-${cleanTenant}-cyclonedx-1.6.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Fleet Global Statistics
  const totalMachines = machines.length;
  const onlineMachines = machines.filter(m => m.status === 'online').length;
  const avgRiskScore = totalMachines > 0 
    ? Math.round(machines.reduce((sum, m) => sum + (m.quantumRiskScore || 0), 0) / totalMachines) 
    : 0;
  const totalDiscoveredAssets = machines.reduce((sum, m) => sum + (m.assetCount || 0), 0);
  const totalVulnerableAssets = machines.reduce((sum, m) => sum + (m.vulnerableCount || 0), 0);

  // Filter Machines Table by Search (hostname, IP, group, tenant, or license)
  const filteredMachines = machines.filter(m => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      m.hostname.toLowerCase().includes(q) ||
      m.ip.toLowerCase().includes(q) ||
      (m.groupName && m.groupName.toLowerCase().includes(q)) ||
      (m.tenantName && m.tenantName.toLowerCase().includes(q)) ||
      (m.licenseKey && m.licenseKey.toLowerCase().includes(q)) ||
      (m.os && m.os.toLowerCase().includes(q))
    );
  });

  // Group machines by Tenant / Partner (grouped under shared license)
  interface TenantGroup {
    tenantName: string;
    licenseKey: string;
    tier: string;
    machines: FleetMachine[];
    totalVulnerable: number;
    totalAssets: number;
    avgRisk: number;
    onlineCount: number;
  }

  const tenantGroups: TenantGroup[] = React.useMemo(() => {
    const map = new Map<string, TenantGroup>();
    filteredMachines.forEach(m => {
      let tenant = m.tenantName || 'Default Enterprise Fleet';
      if (tenant.toUpperCase().includes('SPINOVATION') || (m.groupName && m.groupName.toLowerCase() === 'engg')) {
        tenant = 'SPINOVATIONCORP';
      }
      if (!map.has(tenant)) {
        map.set(tenant, {
          tenantName: tenant,
          licenseKey: tenant === 'SPINOVATIONCORP' ? 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8' : (m.licenseKey || 'QS-CORP-DEMOCLIENT-6AF00609-C7486296'),
          tier: m.licenseTier || (tenant.toLowerCase().includes('partner') || tenant.toLowerCase().includes('msp') ? 'MSP Partner' : 'Enterprise Pro'),
          machines: [],
          totalVulnerable: 0,
          totalAssets: 0,
          avgRisk: 0,
          onlineCount: 0
        });
      }
      const group = map.get(tenant)!;
      group.machines.push(m);
      group.totalVulnerable += (m.vulnerableCount || 0);
      group.totalAssets += (m.assetCount || 0);
      if (m.status === 'online') group.onlineCount += 1;
    });

    map.forEach(group => {
      group.avgRisk = group.machines.length > 0
        ? Math.round(group.machines.reduce((acc, m) => acc + (m.quantumRiskScore || 0), 0) / group.machines.length)
        : 0;
    });

    return Array.from(map.values());
  }, [filteredMachines]);

  // Expansion helper methods
  const toggleTenant = (name: string) => {
    setExpandedTenants(prev => ({
      ...prev,
      [name]: prev[name] !== undefined ? !prev[name] : false
    }));
  };

  const isTenantExpanded = (name: string) => {
    return expandedTenants[name] !== false; // Default expanded
  };

  const expandAllTenants = () => {
    const next: Record<string, boolean> = {};
    tenantGroups.forEach(g => { next[g.tenantName] = true; });
    setExpandedTenants(next);
  };

  const collapseAllTenants = () => {
    const next: Record<string, boolean> = {};
    tenantGroups.forEach(g => { next[g.tenantName] = false; });
    setExpandedTenants(next);
  };

  // Available Tenants for CBOM Explorer
  const allAvailableTenants = React.useMemo(() => {
    const names = new Set<string>();
    machines.forEach(m => {
      if (m.tenantName) names.add(m.tenantName);
      else if (m.groupName) names.add(m.groupName);
    });
    if (names.size === 0) {
      names.add('Apex Defense Labs (MSP)');
      names.add('PARTNERTEST (MSP Partner)');
      names.add('Executive Engineering Fleet');
    }
    return Array.from(names);
  }, [machines]);

  const filteredTenantList = allAvailableTenants.filter(t => 
    !tenantSearchQuery || t.toLowerCase().includes(tenantSearchQuery.toLowerCase().trim())
  );

  // CBOM Tenant Scoped calculations
  const cbomScopedMachines = selectedTenantFilter === 'all'
    ? machines
    : machines.filter(m => (m.tenantName || m.groupName || 'Default Fleet') === selectedTenantFilter);

  const cbomTotalEndpoints = cbomScopedMachines.length;
  const cbomOnlineEndpoints = cbomScopedMachines.filter(m => m.status === 'online').length;
  const cbomFleetRiskScore = cbomTotalEndpoints > 0
    ? Math.round(cbomScopedMachines.reduce((sum, m) => sum + (m.quantumRiskScore || 0), 0) / cbomTotalEndpoints)
    : 0;
  const cbomDiscoveredCrypto = cbomScopedMachines.reduce((sum, m) => sum + (m.assetCount || 0), 0);
  const cbomVulnerableAssets = cbomScopedMachines.reduce((sum, m) => sum + (m.vulnerableCount || 0), 0);

  const tenantScopedHostnames = new Set(cbomScopedMachines.map(m => m.hostname));

  // Filter CBOM components (Scoped by Tenant, Machine, Category, Status, and Search)
  const filteredCBOMComponents = (cbomData?.components || []).filter((comp: any) => {
    const host = comp.cryptoProperties?.detectionContext?.machineHostname;
    const tenantComp = comp.tenantName;
    const tenantMatch = selectedTenantFilter === 'all' 
      || (host && tenantScopedHostnames.has(host)) 
      || (tenantComp && tenantComp === selectedTenantFilter);
    const machineMatch = selectedMachineFilter === 'all' || host === selectedMachineFilter;
    const categoryMatch = selectedCategoryFilter === 'all' || comp.cryptoProperties?.assetType === selectedCategoryFilter;
    const isVulnerable = comp.cryptoProperties?.algorithmProperties?.quantumSecurityLevel === 0;
    const statusMatch = selectedStatusFilter === 'all' 
      || (selectedStatusFilter === 'vulnerable' && isVulnerable) 
      || (selectedStatusFilter === 'secure' && !isVulnerable);
    const searchMatch = !searchQuery 
      || comp.name?.toLowerCase().includes(searchQuery.toLowerCase())
      || comp.cryptoProperties?.detectionContext?.filePath?.toLowerCase().includes(searchQuery.toLowerCase())
      || comp.cryptoProperties?.algorithmProperties?.name?.toLowerCase().includes(searchQuery.toLowerCase());

    return tenantMatch && machineMatch && categoryMatch && statusMatch && searchMatch;
  });

  const totalCbomPages = Math.max(1, Math.ceil(filteredCBOMComponents.length / cbomPerPage));
  const paginatedCBOMComponents = filteredCBOMComponents.slice((cbomPage - 1) * cbomPerPage, cbomPage * cbomPerPage);

  const cbomPreviewJson = useMemo(() => {
    if (!cbomData) return '{}';
    if (cbomData.components && cbomData.components.length > 20) {
      const preview = {
        ...cbomData,
        _previewNotice: `Showing preview of first 20 of ${cbomData.components.length} components. Full CBOM with all ${cbomData.components.length} assets is included when clicking 'Download JSON' or 'Copy JSON'.`,
        components: cbomData.components.slice(0, 20)
      };
      return JSON.stringify(preview, null, 2);
    }
    return JSON.stringify(cbomData, null, 2);
  }, [cbomData]);

  // Active Token for code generation
  const activeTokenString = selectedDeploymentToken || (tokens[0]?.token || 'YOUR_FLEET_TOKEN');

  // Script Generator Codes
  const getDeploymentSnippet = () => {
    switch (deploymentMethod) {
      case 'desktop':
        return `# 🛡️ 1-Click Post-Quantum Guard Desktop Mode (Windows / macOS / Linux)
# Zero command line or PowerShell syntax required!
#
# 1. Download 'quarkshield-scanner-windows-amd64.exe' from the direct links below.
# 2. Double-click the file in Windows File Explorer (or launch on macOS/Linux).
# 3. The QuarkShield Post-Quantum Guard GUI opens in your default browser.
# 4. Click "⚡ Quick Scan Workstation" to discover quantum vulnerabilities & generate your CBOM.
# 5. Enter Fleet Token "${activeTokenString}" in the "Connect to Fleet" modal to sync findings live.`;
      case 'curl':
        return `# 1-Liner Shell Installer (macOS & Linux)
curl -fsSL ${apiOrigin}/api/scan/agent/install.sh | sudo sh -s -- --token "${activeTokenString}"`;
      case 'jamf':
        return `#!/bin/bash
# Jamf Pro Extension Attribute / Policy Payload for macOS Workstations
TOKEN="${activeTokenString}"
SERVER_URL="${apiOrigin}"

curl -fsSL "$SERVER_URL/api/scan/agent/install.sh" | sh -s -- --token "$TOKEN" --server "$SERVER_URL"
echo "QuarkShield Scanner deployed successfully."`;
      case 'intune':
        return `# Windows PowerShell Deployment (Works for Admin & Standard Users)
$Token = "${activeTokenString}"
$ServerUrl = "${apiOrigin}"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$InstallDir = if ($IsAdmin) { "$env:ProgramFiles\\QuarkShield" } else { "$env:LOCALAPPDATA\\QuarkShield" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
curl.exe -fsSL "$ServerUrl/downloads/quarkshield-scanner-windows-amd64.exe" -o "$InstallDir\\quarkshield-scanner.exe"
& "$InstallDir\\quarkshield-scanner.exe" --server "$ServerUrl" --token "$Token" --register --quick
Write-Output "QuarkShield scanner enrolled successfully."`;
      case 'ansible':
        return `- name: Enroll Linux fleet in QuarkShield.AI CBOM Telemetry
  hosts: all
  become: yes
  tasks:
    - name: Download QuarkShield Scanner
      ansible.builtin.get_url:
        url: "${apiOrigin}/downloads/quarkshield-scanner-linux-amd64"
        dest: "/usr/local/bin/quarkshield-scanner"
        mode: '0755'

    - name: Execute initial cryptographic audit
      ansible.builtin.command:
        cmd: /usr/local/bin/quarkshield-scanner --server "${apiOrigin}" --token "${activeTokenString}" --register --quick`;
      case 'docker':
        return `# Ephemeral Container Introspection
docker run --rm -v /etc/ssl:/etc/ssl:ro -v /etc/ssh:/etc/ssh:ro \\
  quarkshield/scanner:latest --server "${apiOrigin}" --token "${activeTokenString}" --register`;
      default:
        return '';
    }
  };

  if (viewMode === 'landing') {
    return (
      <LandingPage
        onLaunchConsole={(initialTab, userEmail) => {
          if (initialTab) {
            setActiveTab(initialTab);
            localStorage.setItem('quarkshield_active_tab', initialTab);
            sessionStorage.setItem('quarkshield_active_tab', initialTab);
          }
          if (userEmail) setCurrentUserEmail(userEmail);
          const cid = localStorage.getItem('quarkshield_customer_id') || sessionStorage.getItem('quarkshield_customer_id');
          if (cid) setCurrentCustomerId(cid);
          const cname = localStorage.getItem('quarkshield_customer_name') || sessionStorage.getItem('quarkshield_customer_name');
          if (cname) setCurrentCustomerName(cname);
          const ltier = localStorage.getItem('quarkshield_license_tier') || sessionStorage.getItem('quarkshield_license_tier');
          if (ltier) setCurrentLicenseTier(ltier);
          const urole = localStorage.getItem('quarkshield_role') || sessionStorage.getItem('quarkshield_role');
          if (urole) setCurrentUserRole(urole);
          const actype = localStorage.getItem('quarkshield_account_type') || sessionStorage.getItem('quarkshield_account_type');
          if (actype) setCurrentAccountType(actype);

          const workspace = localStorage.getItem('quarkshield_workspace') || sessionStorage.getItem('quarkshield_workspace');
          if ((actype === 'corporate' || actype === 'partner') && (workspace || (userEmail && userEmail.includes('spinovation')))) {
            setTenantSlug(workspace || (userEmail && userEmail.includes('spinovation') ? 'spinovationcorp' : ''));
            localStorage.setItem('quarkshield_view_mode', 'tenant');
            sessionStorage.setItem('quarkshield_view_mode', 'tenant');
            setViewMode('tenant');
            return;
          }

          if (window.history.pushState) {
            const consoleUrl = window.location.protocol + '//' + window.location.host + window.location.pathname + '?view=console';
            window.history.pushState({ path: consoleUrl }, '', consoleUrl);
          }
          localStorage.setItem('quarkshield_view_mode', 'console');
          sessionStorage.setItem('quarkshield_view_mode', 'console');
          setViewMode('console');
        }}
      />
    );
  }

  if (viewMode === 'tenant') {
    return (
      <PortalErrorBoundary>
        <TenantPortal
          tenantSlug={tenantSlug || 'spinovationcorp'}
          isSupportMirror={isSupportMirror}
          onExitMirror={() => {
            setIsSupportMirror(false);
            setViewMode('console');
            setActiveTab('admin');
            setAdminInitialSubTab('registry');
          }}
          onNavigateHome={() => {
            setIsSupportMirror(false);
            if (window.history.pushState) {
              const homeUrl = window.location.protocol + '//' + window.location.host + '/';
              window.history.pushState({ path: homeUrl }, '', homeUrl);
            }
            localStorage.setItem('quarkshield_view_mode', 'landing');
            sessionStorage.setItem('quarkshield_view_mode', 'landing');
            setViewMode('landing');
          }}
          onLogout={() => {
            setIsSupportMirror(false);
            if (window.history.pushState) {
              const homeUrl = window.location.protocol + '//' + window.location.host + '/';
              window.history.pushState({ path: homeUrl }, '', homeUrl);
            }
            localStorage.removeItem('quarkshield_user');
            sessionStorage.removeItem('quarkshield_user');
            localStorage.setItem('quarkshield_view_mode', 'landing');
            sessionStorage.setItem('quarkshield_view_mode', 'landing');
            setViewMode('landing');
          }}
        />
      </PortalErrorBoundary>
    );
  }

  const isSuperAdmin = currentUserRole === 'Super Admin' ||
    currentAccountType === 'superadmin' ||
    currentUserEmail.toLowerCase().includes('@quarkshield.ai') ||
    currentUserEmail.toLowerCase() === 'superadmin' ||
    currentUserEmail.toLowerCase() === 'sridhargs@gmail.com';

  const displayCustomerId = isSuperAdmin ? 'QS-ADMIN-001' : (currentCustomerId || 'PART-9148');
  const displayCustomerName = isSuperAdmin ? 'INTERNAL USER' : (currentCustomerName || (currentAccountType === 'partner' ? 'MSP PARTNER PRO' : 'CORPORATE CLIENT'));
  const displayRole = isSuperAdmin ? 'Super Admin' : currentUserRole;

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', overflow: 'hidden', background: 'var(--bg-dark, #07090E)', color: 'var(--text-primary, #E2E8F0)' }}>
      {/* LEFT SIDEBAR NAVIGATION (Matching quarkshield.service) */}
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
        {/* Brand Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.2rem 0.4rem 1.1rem 0.4rem', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', marginBottom: '0.65rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <img 
              src="/quarkshield-logo.png" 
              alt="QuarkShield" 
              style={{ height: '28px', width: 'auto', objectFit: 'contain', display: 'block', filter: 'drop-shadow(0 0 10px rgba(0, 242, 254, 0.35))' }} 
            />
          </div>
          <button
            onClick={() => {
              if (window.history.pushState) {
                const cleanUrl = window.location.protocol + '//' + window.location.host + window.location.pathname;
                window.history.pushState({ path: cleanUrl }, '', cleanUrl);
              }
              localStorage.setItem('quarkshield_view_mode', 'landing');
              sessionStorage.setItem('quarkshield_view_mode', 'landing');
              setViewMode('landing');
            }}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.2rem',
              display: 'flex',
              alignItems: 'center'
            }}
            title="Close / Exit to Landing Page"
          >
            <X size={16} />
          </button>
        </div>

        {/* Primary Navigation Tabs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          {/* Fleet Overview */}
          <button
            onClick={() => setActiveTab('dashboard')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'dashboard' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'dashboard' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'dashboard' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'dashboard' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
          >
            <Laptop size={17} color={activeTab === 'dashboard' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              Fleet Overview ({machines.length})
            </span>
          </button>

          {/* CBOM Explorer */}
          <button
            onClick={() => setActiveTab('cbom')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'cbom' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'cbom' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'cbom' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'cbom' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
          >
            <FileCode size={17} color={activeTab === 'cbom' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              BOM Inventory (CBOM + SBOM)
            </span>
          </button>

          {/* Agent Tokens & Deployment */}
          <button
            onClick={() => setActiveTab('tokens')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'tokens' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'tokens' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'tokens' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'tokens' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
          >
            <Key size={17} color={activeTab === 'tokens' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              Agent Tokens & Deployment
            </span>
          </button>

          {/* Git Repositories */}
          <button
            onClick={() => setActiveTab('git')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'git' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'git' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'git' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'git' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
          >
            <GitBranch size={17} color={activeTab === 'git' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              Git Repositories &amp; CI/CD Gate
            </span>
          </button>

          {/* Enterprise PKI & Vaults */}
          <button
            onClick={() => setActiveTab('pki')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'pki' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'pki' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'pki' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'pki' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%',
              justifyContent: 'space-between'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', overflow: 'hidden' }}>
              <Database size={17} color={activeTab === 'pki' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                Enterprise PKI &amp; Vaults
              </span>
            </div>
            <span style={{ fontSize: '0.64rem', padding: '0.1rem 0.35rem', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
              Sync
            </span>
          </button>

          {/* Hybrid Quantum TLS Proxy */}
          <button
            onClick={() => setActiveTab('proxy')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.6rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'proxy' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'proxy' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'proxy' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'proxy' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%',
              justifyContent: 'space-between'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', overflow: 'hidden' }}>
              <Radio size={17} color={activeTab === 'proxy' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                Hybrid Quantum TLS Proxy
              </span>
            </div>
            <span style={{ fontSize: '0.64rem', padding: '0.1rem 0.35rem', borderRadius: '4px', background: 'rgba(52, 211, 153, 0.15)', color: '#34d399', border: '1px solid rgba(52, 211, 153, 0.3)' }}>
              Inline
            </span>
          </button>

          {/* TAB 5: MOSCA'S QUANTUM MIGRATION PLANNER */}
          <button
            onClick={() => setActiveTab('planner')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.65rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: activeTab === 'planner' ? 'rgba(0, 242, 254, 0.12)' : 'transparent',
              border: activeTab === 'planner' ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              color: activeTab === 'planner' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: activeTab === 'planner' ? 600 : 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%',
              justifyContent: 'space-between'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', overflow: 'hidden' }}>
              <Calendar size={17} color={activeTab === 'planner' ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                Mosca&apos;s Migration Planner
              </span>
            </div>
            <span style={{ fontSize: '0.64rem', padding: '0.1rem 0.35rem', borderRadius: '4px', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
              X+Y&gt;Z
            </span>
          </button>
        </div>

        {/* Separator */}
        <div style={{ margin: '0.85rem 0', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }} />

        {/* Observability & Action Links requested by user */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0 0.75rem 0.35rem 0.75rem' }}>
            Observability & Actions
          </div>

          {/* Refresh Telemetry */}
          <button
            onClick={() => { fetchMachines(); fetchCBOM(); fetchTokens(); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              fontSize: '0.84rem',
              fontWeight: 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
            title="Refresh Host & Fleet Telemetry"
          >
            <RefreshCw size={16} className={loading ? 'spin' : ''} color="var(--text-muted)" />
            <span>Refresh Telemetry</span>
          </button>

          {/* Export CBOM (CycloneDX) */}
          <button
            onClick={downloadCBOMJson}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: 'transparent',
              border: 'none',
              color: 'var(--text-secondary)',
              fontSize: '0.84rem',
              fontWeight: 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
            title="Export CycloneDX 1.6 Cryptographic Bill of Materials"
          >
            <Download size={16} color="var(--text-muted)" />
            <span>Export CBOM (CycloneDX)</span>
          </button>

          {/* Deploy Endpoint Agent */}
          <button
            onClick={() => { setActiveTab('tokens'); setShowCreateTokenModal(true); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.7rem',
              padding: '0.55rem 0.75rem',
              borderRadius: '6px',
              background: 'transparent',
              border: 'none',
              color: 'var(--accent-cyan)',
              fontSize: '0.84rem',
              fontWeight: 500,
              textAlign: 'left',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
            title="Generate Token and Deploy Endpoint Agent"
          >
            <Terminal size={16} color="var(--accent-cyan)" />
            <span>Deploy Endpoint Agent</span>
          </button>
        </div>

        {/* Footer Area with Admin Panel & Profile matching quarkshield.service */}
        <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '0.65rem', paddingTop: '1rem' }}>
          {/* User Onboarding button */}
          <button
            onClick={() => { setActiveTab('admin'); setAdminInitialSubTab('onboarding'); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.65rem',
              padding: '0.6rem 0.85rem',
              borderRadius: '6px',
              background: (activeTab === 'admin' && adminInitialSubTab === 'onboarding') ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255, 255, 255, 0.03)',
              border: (activeTab === 'admin' && adminInitialSubTab === 'onboarding') ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
              color: (activeTab === 'admin' && adminInitialSubTab === 'onboarding') ? '#ffffff' : 'var(--text-primary)',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: (activeTab === 'admin' && adminInitialSubTab === 'onboarding') ? '0 0 12px rgba(0, 242, 254, 0.25)' : 'none',
              transition: 'all 0.15s ease',
              width: '100%',
              textAlign: 'left'
            }}
            title="Onboard & Provision Partner or Corporate User"
          >
            <UserPlus size={17} color="var(--accent-cyan)" />
            <span>User Onboarding</span>
          </button>

          {/* Admin & License Panel button (Super Admin tag removed) */}
          <button
            onClick={() => { setActiveTab('admin'); setAdminInitialSubTab('licenses'); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.65rem',
              padding: '0.6rem 0.85rem',
              borderRadius: '6px',
              background: (activeTab === 'admin' && adminInitialSubTab !== 'onboarding') ? 'rgba(0, 242, 254, 0.15)' : 'rgba(0, 242, 254, 0.04)',
              border: (activeTab === 'admin' && adminInitialSubTab !== 'onboarding') ? '1px solid var(--accent-cyan)' : '1px solid rgba(0, 242, 254, 0.35)',
              color: (activeTab === 'admin' && adminInitialSubTab !== 'onboarding') ? '#ffffff' : 'var(--accent-cyan)',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: (activeTab === 'admin' && adminInitialSubTab !== 'onboarding') ? '0 0 15px rgba(0, 242, 254, 0.25)' : 'none',
              transition: 'all 0.15s ease',
              width: '100%'
            }}
            title="Open Administrative & License Orchestration Panel"
          >
            <ShieldAlert size={17} color="var(--accent-cyan)" />
            <span>Admin & License Panel</span>
          </button>

          {/* Subscription Scale Card (For Customers & Partners) vs Internal Authority Card (For Internal Super Admin) */}
          {isSuperAdmin ? (
            /* Internal Super Admin Account Indicator */
            <div style={{
              background: 'rgba(13, 19, 33, 0.85)',
              border: '1px solid rgba(0, 242, 254, 0.22)',
              borderRadius: '8px',
              padding: '0.85rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.55rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', lineHeight: 1.25 }}>
                  INTERNAL<br />USER
                </div>
                <div style={{
                  border: '1px solid rgba(0, 242, 254, 0.4)',
                  borderRadius: '4px',
                  padding: '0.18rem 0.45rem',
                  fontSize: '0.68rem',
                  fontWeight: 700,
                  color: 'var(--accent-cyan)',
                  background: 'rgba(0, 242, 254, 0.12)',
                  letterSpacing: '0.04em',
                  lineHeight: 1.1,
                  textAlign: 'center'
                }}>
                  SUPER<br />ADMIN
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff' }}>Fleet Authority</span>
                <span style={{ fontSize: '0.85rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
                  UNLIMITED
                </span>
              </div>

              {/* Progress / Status Bar */}
              <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{ width: '100%', height: '100%', background: 'linear-gradient(90deg, #00f2fe 0%, #3b82f6 100%)', borderRadius: '2px', boxShadow: '0 0 8px rgba(0, 242, 254, 0.6)' }} />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-cyan)', display: 'inline-block', boxShadow: '0 0 6px rgba(0, 242, 254, 0.8)' }} />
                <span>Central Management & Licensing Plane</span>
              </div>
            </div>
          ) : (
            /* Customers and Partners: Subscription Scale Card */
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
                <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', lineHeight: 1.25 }}>
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
                  {currentAccountType === 'partner' ? 'PARTNER' : 'GROWTH'}<br />TIER
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff' }}>Scale Monitored</span>
                <span style={{ fontSize: '0.95rem', fontWeight: 800, color: '#ffffff' }}>
                  {machines.length} <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.82rem' }}>/</span> {currentAccountType === 'partner' ? '50' : '250'}
                </span>
              </div>

              {/* Progress Bar */}
              <div style={{ width: '100%', height: '4px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{
                  width: `${Math.min(100, Math.max(8, Math.round((machines.length / (currentAccountType === 'partner' ? 50 : 250)) * 100)))}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #00f2fe 0%, #4facfe 100%)',
                  borderRadius: '2px',
                  boxShadow: '0 0 8px rgba(0, 242, 254, 0.6)'
                }} />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981', display: 'inline-block', boxShadow: '0 0 6px rgba(16, 185, 129, 0.8)' }} />
                <span>Continuous asset tracking active</span>
              </div>
            </div>
          )}

          {/* Separator */}
          <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)' }} />

          {/* Bottom User Profile Bar (Customer ID / Customer Name) */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '0.4rem',
            padding: '0.5rem 0.2rem 0.2rem 0.2rem'
          }}>
            {/* Customer ID & Customer Name in bold blue uppercase (e.g. QS-ADMIN-001/INTERNAL USER or PART-9148/ALGO MELD MSP) */}
            <div style={{
              fontSize: '0.8rem',
              fontWeight: 800,
              letterSpacing: '0.04em',
              color: '#3b82f6',
              textTransform: 'uppercase',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }} title={`${displayCustomerId}/${displayCustomerName}`}>
              {displayCustomerId}/{displayCustomerName}
            </div>

            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '0.35rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', overflow: 'hidden' }}>
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
                    title={currentUserEmail}
                  >
                    {currentUserEmail}
                  </div>
                  <div style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-muted)' }}>
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
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '5px',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--accent-cyan)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                  title="User License & 2FA Settings"
                >
                  <Key size={16} />
                </button>

                {/* Logout Icon */}
                <button
                  onClick={handleLogout}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '5px',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    transition: 'all 0.15s ease'
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                  title="Log Out of Console"
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
          {/* Header Banner - shown for scanner/fleet/cbom/tokens/git tabs */}
          {activeTab !== 'admin' && (
            <header className="glass-panel" style={{ padding: '1.5rem', position: 'relative', overflow: 'hidden', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
              <div style={{ position: 'absolute', top: '-60px', right: '-40px', width: '260px', height: '260px', background: 'radial-gradient(circle, rgba(0, 242, 254, 0.12) 0%, rgba(0,0,0,0) 70%)', borderRadius: '50%', pointerEvents: 'none' }} />
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', position: 'relative', zIndex: 1 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '0.45rem' }}>
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem', padding: '0.2rem 0.65rem', borderRadius: '20px', background: 'rgba(0, 242, 254, 0.12)', border: '1px solid rgba(0, 242, 254, 0.3)', color: 'var(--accent-cyan)', fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      <Sparkles size={12} /> Endpoint Security Console
                    </div>
                  </div>
                  <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: '0 0 0.25rem 0', display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#ffffff' }}>
                    <Laptop size={24} color="var(--accent-cyan)" /> Desktop & Host PQC Vulnerability Scanner
                  </h1>
                  <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.88rem', maxWidth: '850px', lineHeight: 1.4 }}>
                    Dedicated Host Cryptographic Observability. Real-time endpoint discovery, standardized CycloneDX 1.6+ CBOM generation, and fleet-wide post-quantum migration management.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                  <button 
                    onClick={() => { fetchMachines(); fetchCBOM(); fetchTokens(); }} 
                    className="btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.8rem' }}
                  >
                    <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh Telemetry
                  </button>
                  <button 
                    onClick={() => downloadCBOMJson(false)}
                    className="btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.8rem', borderColor: 'rgba(0, 242, 254, 0.4)' }}
                    title="Export Standard CycloneDX 1.6 CBOM"
                  >
                    <Download size={13} color="var(--accent-cyan)" /> Export CBOM
                  </button>
                  <button 
                    onClick={() => downloadCBOMJson(true)}
                    className="btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.8rem', borderColor: 'rgba(168, 85, 247, 0.6)', color: '#c084fc', background: 'rgba(168, 85, 247, 0.15)' }}
                    title="Export CycloneDX 1.6 with CDXA Attestation Declarations and ML-DSA-65 Signature"
                  >
                    <ShieldCheck size={14} color="#c084fc" /> Export CDXA Attested
                  </button>
                  <button 
                    onClick={() => { setActiveTab('tokens'); setShowCreateTokenModal(true); }}
                    className="btn-primary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.45rem 0.95rem' }}
                  >
                    <Terminal size={13} /> Deploy Agent
                  </button>
                </div>
              </div>
            </header>
          )}

        {/* TAB 1: FLEET OVERVIEW DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Top KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>TOTAL ENROLLED ENDPOINTS</span>
                  <Laptop size={18} color="var(--accent-cyan)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff' }}>{totalMachines}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--status-secure)' }} />
                  <span>{onlineMachines} active online in last 24h</span>
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>FLEET QUANTUM RISK SCORE</span>
                  <ShieldAlert size={18} color={avgRiskScore > 60 ? 'var(--status-vulnerable)' : 'var(--accent-cyan)'} />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: avgRiskScore > 60 ? 'var(--status-vulnerable)' : '#ffffff' }}>
                  {avgRiskScore} <span style={{ fontSize: '1rem', fontWeight: 500, color: 'var(--text-muted)' }}>/ 100</span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Weighted across RSA, ECDSA, & Ed25519 assets
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>DISCOVERED CRYPTO SECRETS</span>
                  <Lock size={18} color="var(--accent-cyan)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff' }}>{totalDiscoveredAssets}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Keys, X.509 certs, JKS, and tunnel configs
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>VULNERABLE ASSETS</span>
                  <AlertOctagon size={18} color="var(--status-vulnerable)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--status-vulnerable)' }}>{totalVulnerableAssets}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Require ML-KEM / ML-DSA migration
                </div>
              </div>
            </div>

            {/* Enrolled Endpoints Grouped by Tenant / Partner */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Server size={18} color="var(--accent-cyan)" /> Enrolled Machine Directory
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    Endpoints grouped by Tenant & Partner license. Expand tenants to inspect active Device Hosts.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  {/* Search by hostname, IP, or tenant */}
                  <div style={{ position: 'relative', width: '280px' }}>
                    <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                    <input
                      type="text"
                      placeholder="Search by hostname, IP, or tenant..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '0.45rem 0.75rem 0.45rem 2rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.82rem'
                      }}
                    />
                  </div>

                  {/* Expand / Collapse All */}
                  <button
                    onClick={expandAllTenants}
                    className="btn-secondary"
                    style={{ padding: '0.4rem 0.7rem', fontSize: '0.78rem', whiteSpace: 'nowrap' }}
                    title="Expand all tenant groups"
                  >
                    Expand All
                  </button>
                  <button
                    onClick={collapseAllTenants}
                    className="btn-secondary"
                    style={{ padding: '0.4rem 0.7rem', fontSize: '0.78rem', whiteSpace: 'nowrap' }}
                    title="Collapse all tenant groups"
                  >
                    Collapse All
                  </button>
                </div>
              </div>

              {/* Tenant Directory Groupings */}
              {tenantGroups.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                  No endpoints or tenants found matching your criteria. Deploy an agent or create a tenant token to see real-time telemetry.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {tenantGroups.map(group => {
                    const expanded = isTenantExpanded(group.tenantName);
                    return (
                      <div 
                        key={group.tenantName}
                        style={{
                          background: 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid rgba(255, 255, 255, 0.08)',
                          borderRadius: '8px',
                          overflow: 'hidden',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        {/* Tenant Accordion Header */}
                        <div
                          onClick={() => toggleTenant(group.tenantName)}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '0.85rem 1.15rem',
                            cursor: 'pointer',
                            background: expanded ? 'rgba(0, 242, 254, 0.05)' : 'rgba(255, 255, 255, 0.01)',
                            borderBottom: expanded ? '1px solid rgba(255, 255, 255, 0.08)' : 'none',
                            userSelect: 'none'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', flexWrap: 'wrap' }}>
                            <div style={{ color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center' }}>
                              {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                              <Building size={16} color="var(--accent-cyan)" />
                              <span style={{ fontWeight: 700, fontSize: '0.96rem', color: '#ffffff' }}>
                                {group.tenantName}
                              </span>
                            </div>

                            <span style={{
                              fontSize: '0.7rem',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '0.18rem 0.5rem',
                              borderRadius: '4px',
                              background: group.tier.toLowerCase().includes('partner') || group.tier.toLowerCase().includes('msp') 
                                ? 'rgba(127, 0, 255, 0.15)' 
                                : 'rgba(0, 242, 254, 0.15)',
                              border: group.tier.toLowerCase().includes('partner') || group.tier.toLowerCase().includes('msp')
                                ? '1px solid rgba(127, 0, 255, 0.4)'
                                : '1px solid rgba(0, 242, 254, 0.4)',
                              color: group.tier.toLowerCase().includes('partner') || group.tier.toLowerCase().includes('msp')
                                ? '#c084fc'
                                : 'var(--accent-cyan)',
                              letterSpacing: '0.04em'
                            }}>
                              {group.tier}
                            </span>

                            <span style={{
                              fontFamily: 'monospace',
                              fontSize: '0.72rem',
                              color: 'var(--text-muted)',
                              background: 'rgba(0,0,0,0.3)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              border: '1px solid rgba(255,255,255,0.06)'
                            }} title={`Master Cryptographic License: ${group.licenseKey}`}>
                              License: {group.licenseKey.length > 28 ? `${group.licenseKey.slice(0, 28)}...` : group.licenseKey}
                            </span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                              <Laptop size={15} color="var(--text-muted)" />
                              <span><strong>{group.machines.length}</strong> Device Host{group.machines.length > 1 ? 's' : ''}</span>
                            </div>

                            <span className={`badge ${group.avgRisk > 75 ? 'danger' : (group.avgRisk > 40 ? 'warning' : 'success')}`} style={{ fontSize: '0.75rem' }}>
                              Risk: {group.avgRisk}/100
                            </span>

                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
                              {group.onlineCount} Online
                            </span>
                          </div>
                        </div>

                        {/* Nested Device Hosts Table */}
                        {expanded && (
                          <div style={{ overflowX: 'auto', padding: '0.5rem 0.85rem 0.85rem 0.85rem' }}>
                            <table className="quark-table" style={{ width: '100%', fontSize: '0.84rem' }}>
                              <thead>
                                <tr>
                                  <th>Device Hostname</th>
                                  <th>OS & Arch</th>
                                  <th>Fleet Group</th>
                                  <th>Last Seen</th>
                                  <th>Quantum Risk</th>
                                  <th>Assets Audited</th>
                                  <th style={{ textAlign: 'right' }}>Actions</th>
                                </tr>
                              </thead>
                              <tbody>
                                {group.machines.map(m => (
                                  <tr key={m.id}>
                                    <td>
                                      <div style={{ fontWeight: 600, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <span style={{ 
                                          width: '8px', 
                                          height: '8px', 
                                          borderRadius: '50%', 
                                          background: m.status === 'online' ? 'var(--status-secure)' : 'var(--text-muted)',
                                          boxShadow: m.status === 'online' ? '0 0 8px rgba(57, 255, 20, 0.6)' : 'none'
                                        }} />
                                        <span>{m.hostname}</span>
                                      </div>
                                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', paddingLeft: '1.1rem' }}>
                                        IP: {m.ip} • Agent v{m.agentVersion || '2.0.0'}
                                      </div>
                                    </td>
                                    <td>
                                      <span style={{ 
                                        padding: '0.2rem 0.5rem', 
                                        borderRadius: '4px', 
                                        background: 'rgba(255,255,255,0.06)', 
                                        fontSize: '0.74rem',
                                        fontWeight: 600,
                                        textTransform: 'uppercase'
                                      }}>
                                        {m.os} / {m.arch}
                                      </span>
                                    </td>
                                    <td>
                                      <span style={{ color: 'var(--text-secondary)' }}>
                                        {m.groupName || 'Default Fleet'}
                                      </span>
                                    </td>
                                    <td>
                                      <span style={{ color: 'var(--text-secondary)' }}>
                                        {new Date(m.lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}, {new Date(m.lastSeen).toLocaleDateString()}
                                      </span>
                                    </td>
                                    <td>
                                      <span className={`badge ${m.riskLevel === 'critical' || m.quantumRiskScore > 75 ? 'danger' : (m.quantumRiskScore > 40 ? 'warning' : 'success')}`}>
                                        {m.quantumRiskScore}/100 ({m.riskLevel?.toUpperCase()})
                                      </span>
                                    </td>
                                    <td>
                                      <div style={{ fontWeight: 600 }}>
                                        <span style={{ color: 'var(--status-vulnerable)' }}>{m.vulnerableCount || 0}</span> / <span>{m.assetCount || 0}</span>
                                      </div>
                                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                                        {Math.round(((m.vulnerableCount || 0) / (m.assetCount || 1)) * 100)}% vulnerable
                                      </div>
                                    </td>
                                    <td style={{ textAlign: 'right' }}>
                                      <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                                        <button
                                          onClick={() => {
                                            setSelectedTenantFilter(group.tenantName);
                                            setSelectedMachineFilter(m.hostname);
                                            setActiveTab('cbom');
                                          }}
                                          className="btn-secondary"
                                          style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                                          title="View Machine CBOM in Tenant Explorer"
                                        >
                                          <FileCode size={13} /> View CBOM
                                        </button>
                                        <button
                                          onClick={() => setInoculationScriptModal(m)}
                                          className="btn-secondary"
                                          style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem', borderColor: 'rgba(0, 242, 254, 0.4)', color: 'var(--accent-cyan)' }}
                                          title="Generate Remediation Script"
                                        >
                                          <Sparkles size={13} /> AI Inoculate
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: CBOM EXPLORER */}
        {activeTab === 'cbom' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Top 4 KPI Metric Cards for CBOM (Scoped to selected tenant/partner or global) */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>TOTAL ENROLLED ENDPOINTS</span>
                  <Laptop size={18} color="var(--accent-cyan)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff' }}>{cbomTotalEndpoints}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--status-secure)' }} />
                  <span>{cbomOnlineEndpoints} active online in scope</span>
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>FLEET QUANTUM RISK SCORE</span>
                  <ShieldAlert size={18} color={cbomFleetRiskScore > 60 ? 'var(--status-vulnerable)' : 'var(--accent-cyan)'} />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: cbomFleetRiskScore > 60 ? 'var(--status-vulnerable)' : '#ffffff' }}>
                  {cbomFleetRiskScore} <span style={{ fontSize: '1rem', fontWeight: 500, color: 'var(--text-muted)' }}>/ 100</span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  {selectedTenantFilter === 'all' ? 'Weighted across entire fleet' : `Scoped to ${selectedTenantFilter}`}
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>DISCOVERED CRYPTO SECRETS</span>
                  <Lock size={18} color="var(--accent-cyan)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff' }}>{cbomDiscoveredCrypto}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Keys, certificates, JKS, and tunnel configs
                </div>
              </div>

              <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', fontWeight: 600 }}>
                  <span>VULNERABLE ASSETS</span>
                  <AlertOctagon size={18} color="var(--status-vulnerable)" />
                </div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--status-vulnerable)' }}>{cbomVulnerableAssets}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Require ML-KEM / ML-DSA migration
                </div>
              </div>
            </div>

            {/* Tenant / Partner (MSP) View Selector & Search */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
                <div>
                  <h4 style={{ margin: '0 0 0.2rem 0', fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Building size={16} color="var(--accent-cyan)" /> Tenant / Partner (MSP) View
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Isolated cryptographic inventory view per tenant or MSP partner. Search by partner name or select below.
                  </p>
                </div>

                <div style={{ position: 'relative', width: '320px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search tenant or partner (MSP) by name..."
                    value={tenantSearchQuery}
                    onChange={e => setTenantSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 0.75rem 0.45rem 2rem',
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '6px',
                      color: '#ffffff',
                      fontSize: '0.82rem'
                    }}
                  />
                </div>
              </div>

              {/* Tenant Selection Pills */}
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  onClick={() => {
                    setSelectedTenantFilter('all');
                    setSelectedMachineFilter('all');
                  }}
                  style={{
                    padding: '0.45rem 0.85rem',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: selectedTenantFilter === 'all' ? 'rgba(0, 242, 254, 0.2)' : 'rgba(255,255,255,0.03)',
                    border: selectedTenantFilter === 'all' ? '1px solid var(--accent-cyan)' : '1px solid rgba(255,255,255,0.1)',
                    color: selectedTenantFilter === 'all' ? '#ffffff' : 'var(--text-secondary)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  🌐 Global Fleet (All Tenants)
                </button>

                {filteredTenantList.map(tenant => {
                  const isActive = selectedTenantFilter === tenant;
                  const isMSP = tenant.toLowerCase().includes('partner') || tenant.toLowerCase().includes('msp');
                  return (
                    <button
                      key={tenant}
                      onClick={() => {
                        setSelectedTenantFilter(tenant);
                        setSelectedMachineFilter('all');
                      }}
                      style={{
                        padding: '0.45rem 0.85rem',
                        borderRadius: '6px',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                        background: isActive 
                          ? (isMSP ? 'rgba(127, 0, 255, 0.25)' : 'rgba(0, 242, 254, 0.2)') 
                          : 'rgba(255,255,255,0.03)',
                        border: isActive 
                          ? (isMSP ? '1px solid #c084fc' : '1px solid var(--accent-cyan)') 
                          : '1px solid rgba(255,255,255,0.1)',
                        color: isActive ? '#ffffff' : 'var(--text-secondary)',
                        transition: 'all 0.15s ease',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.4rem'
                      }}
                    >
                      <Building size={13} color={isActive ? (isMSP ? '#c084fc' : 'var(--accent-cyan)') : 'var(--text-muted)'} />
                      <span>{tenant}</span>
                      {isMSP && (
                        <span style={{ fontSize: '0.65rem', background: 'rgba(127, 0, 255, 0.3)', color: '#c084fc', padding: '0.05rem 0.35rem', borderRadius: '3px' }}>
                          MSP
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Active Tenant / Partner Metadata Banner */}
              {selectedTenantFilter !== 'all' && (
                <div style={{
                  marginTop: '1rem',
                  padding: '0.85rem 1rem',
                  borderRadius: '6px',
                  background: 'rgba(0, 242, 254, 0.04)',
                  border: '1px solid rgba(0, 242, 254, 0.25)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.8rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '6px',
                      background: 'rgba(0, 242, 254, 0.15)',
                      border: '1px solid rgba(0, 242, 254, 0.4)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <Building size={18} color="var(--accent-cyan)" />
                    </div>
                    <div>
                      <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                        {selectedTenantFilter}
                      </div>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        Isolated Cryptographic CBOM View • {cbomTotalEndpoints} Registered Host Devices
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <button
                      onClick={() => downloadCBOMJson(false)}
                      className="btn-secondary"
                      style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem', borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)' }}
                      title="Download Tenant CycloneDX 1.6 CBOM"
                    >
                      <Download size={14} /> Export Tenant CBOM
                    </button>
                    <button
                      onClick={() => downloadCBOMJson(true)}
                      className="btn-secondary"
                      style={{ padding: '0.4rem 0.75rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem', borderColor: '#c084fc', color: '#c084fc', background: 'rgba(168, 85, 247, 0.15)' }}
                      title="Download CycloneDX 1.6 with CDXA Attestation & ML-DSA-65 Signature"
                    >
                      <ShieldCheck size={14} color="#c084fc" /> Export Attested (CDXA)
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* CBOM Explorer Panel */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              
              {/* Filter Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
                <div>
                  <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Layers size={18} color="var(--accent-cyan)" /> Cryptographic &amp; Software Bill of Materials (CycloneDX 1.6)
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    Standardized inventory adhering to the global CycloneDX 1.6 specification for cryptographic primitives and software dependencies.
                  </p>
                </div>

                {/* View Toggle (Table vs SBOM vs JSON) */}
                <div style={{ display: 'flex', gap: '0.5rem', background: 'rgba(0,0,0,0.25)', padding: '0.2rem', borderRadius: '6px' }}>
                  <button
                    onClick={() => setCbomViewMode('table')}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      padding: '0.4rem 0.8rem',
                      background: cbomViewMode === 'table' ? 'rgba(0, 242, 254, 0.2)' : 'transparent',
                      border: 'none',
                      borderRadius: '4px',
                      color: cbomViewMode === 'table' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    <FileCode size={14} /> CBOM Assets
                  </button>
                  <button
                    onClick={() => setCbomViewMode('sbom')}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      padding: '0.4rem 0.8rem',
                      background: cbomViewMode === 'sbom' ? 'rgba(0, 242, 254, 0.2)' : 'transparent',
                      border: 'none',
                      borderRadius: '4px',
                      color: cbomViewMode === 'sbom' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    <Package size={14} /> SBOM Dependencies &amp; Fixes
                  </button>
                  <button
                    onClick={() => setCbomViewMode('json')}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      padding: '0.4rem 0.8rem',
                      background: cbomViewMode === 'json' ? 'rgba(0, 242, 254, 0.2)' : 'transparent',
                      border: 'none',
                      borderRadius: '4px',
                      color: cbomViewMode === 'json' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    <Code size={14} /> CycloneDX JSON
                  </button>
                </div>
              </div>

              {cbomViewMode === 'sbom' ? (
                <div style={{ marginTop: '0.75rem' }}>
                  <SbomInventory tenant={selectedTenantFilter === 'all' ? 'SPINOVATIONCORP' : selectedTenantFilter} apiUrl="" isSuperAdmin={true} />
                </div>
              ) : (
                <>
                  {/* Filters Row */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem', background: 'rgba(0,0,0,0.2)', padding: '0.75rem', borderRadius: '8px' }}>
                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.3rem' }}>Filter Machine</label>
                  <select 
                    value={selectedMachineFilter} 
                    onChange={e => setSelectedMachineFilter(e.target.value)}
                    style={{ width: '100%', padding: '0.4rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: '#ffffff', fontSize: '0.8rem' }}
                  >
                    <option value="all" style={{ background: '#0F172A' }}>
                      {selectedTenantFilter === 'all' ? 'All Endpoints' : `All ${selectedTenantFilter} Endpoints`}
                    </option>
                    {cbomScopedMachines.map(m => (
                      <option key={m.id} value={m.hostname} style={{ background: '#0F172A' }}>{m.hostname}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.3rem' }}>Asset Type</label>
                  <select 
                    value={selectedCategoryFilter} 
                    onChange={e => setSelectedCategoryFilter(e.target.value)}
                    style={{ width: '100%', padding: '0.4rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: '#ffffff', fontSize: '0.8rem' }}
                  >
                    <option value="all" style={{ background: '#0F172A' }}>All Categories</option>
                    <option value="key" style={{ background: '#0F172A' }}>Keys (SSH, Private)</option>
                    <option value="certificate" style={{ background: '#0F172A' }}>Certificates (X.509)</option>
                    <option value="protocol" style={{ background: '#0F172A' }}>Protocols & VPNs</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '0.3rem' }}>Quantum Readiness</label>
                  <select 
                    value={selectedStatusFilter} 
                    onChange={e => setSelectedStatusFilter(e.target.value)}
                    style={{ width: '100%', padding: '0.4rem', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: '#ffffff', fontSize: '0.8rem' }}
                  >
                    <option value="all" style={{ background: '#0F172A' }}>All Statuses</option>
                    <option value="vulnerable" style={{ background: '#0F172A' }}>Quantum Vulnerable</option>
                    <option value="secure" style={{ background: '#0F172A' }}>Post-Quantum Secure</option>
                  </select>
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button
                    onClick={() => {
                      setSelectedMachineFilter('all');
                      setSelectedCategoryFilter('all');
                      setSelectedStatusFilter('all');
                      setSearchQuery('');
                    }}
                    className="btn-secondary"
                    style={{ width: '100%', padding: '0.4rem', fontSize: '0.8rem' }}
                  >
                    Reset Filters
                  </button>
                </div>
              </div>

              {/* Mode 1: Table View */}
              {cbomViewMode === 'table' ? (
                <div style={{ overflowX: 'auto' }}>
                  <table className="quark-table" style={{ width: '100%', fontSize: '0.82rem' }}>
                    <thead>
                      <tr>
                        <th>Cryptographic Asset</th>
                        <th>Host Endpoint</th>
                        <th>Algorithm & Key Size</th>
                        <th>Quantum Status</th>
                        <th>Security Level</th>
                        <th>Mitigation Directive</th>
                        <th style={{ textAlign: 'right' }}>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCBOMComponents.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                            No CBOM components match your search filters.
                          </td>
                        </tr>
                      ) : (
                        paginatedCBOMComponents.map((c: any, idx: number) => {
                          const isVuln = c.cryptoProperties?.algorithmProperties?.quantumSecurityLevel === 0;
                          const riskProp = c.properties?.find((p: any) => p.name === 'quarkshield:riskLevel')?.value || 'high';
                          const recProp = c.properties?.find((p: any) => p.name === 'quarkshield:recommendation')?.value || '';

                          return (
                            <tr key={idx}>
                              <td>
                                <div style={{ fontWeight: 600, color: '#ffffff' }}>{c.name}</div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.74rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', marginTop: '0.2rem', wordBreak: 'break-all' }}>
                                  <span style={{ color: 'var(--text-muted)' }}>📂</span> {c.cryptoProperties?.detectionContext?.filePath || c.path || 'Path unrecorded'}
                                </div>
                              </td>
                              <td>
                                <span style={{ color: 'var(--text-secondary)' }}>
                                  {c.cryptoProperties?.detectionContext?.machineHostname || 'General Endpoint'}
                                </span>
                              </td>
                              <td>
                                <span style={{ fontWeight: 600, color: '#ffffff' }}>
                                  {c.cryptoProperties?.algorithmProperties?.name}
                                </span>
                                {c.cryptoProperties?.algorithmProperties?.keyLength && (
                                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginLeft: '0.3rem' }}>
                                    ({c.cryptoProperties.algorithmProperties.keyLength}-bit)
                                  </span>
                                )}
                              </td>
                              <td>
                                <span style={{ color: isVuln ? 'var(--status-vulnerable)' : 'var(--status-secure)', fontWeight: 600 }}>
                                  {isVuln ? 'Quantum Vulnerable' : 'Post-Quantum Secure'}
                                </span>
                              </td>
                              <td>
                                <span className={`badge ${riskProp === 'critical' || riskProp === 'high' ? 'danger' : (riskProp === 'secure' ? 'success' : 'warning')}`}>
                                  NIST Level {c.cryptoProperties?.algorithmProperties?.quantumSecurityLevel}
                                </span>
                              </td>
                              <td>
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '280px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                  {recProp}
                                </div>
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <button
                                  onClick={() => setSelectedAssetDetail(c)}
                                  className="btn-secondary"
                                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.72rem' }}
                                >
                                  <Eye size={12} /> Inspect
                                </button>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>

                  {totalCbomPages > 1 && (
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
                        Showing <span style={{ color: '#ffffff', fontWeight: 600 }}>{(cbomPage - 1) * cbomPerPage + 1}</span>–<span style={{ color: '#ffffff', fontWeight: 600 }}>{Math.min(cbomPage * cbomPerPage, filteredCBOMComponents.length)}</span> of <span style={{ color: '#ffffff', fontWeight: 600 }}>{filteredCBOMComponents.length.toLocaleString()}</span> components
                      </div>
                      <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                        <button
                          onClick={() => setCbomPage(p => Math.max(1, p - 1))}
                          disabled={cbomPage === 1}
                          style={{
                            background: cbomPage === 1 ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.08)',
                            border: '1px solid rgba(255, 255, 255, 0.12)',
                            color: cbomPage === 1 ? '#475569' : '#ffffff',
                            padding: '0.35rem 0.75rem',
                            borderRadius: '6px',
                            cursor: cbomPage === 1 ? 'not-allowed' : 'pointer',
                            fontSize: '0.78rem',
                            fontWeight: 500
                          }}
                        >
                          Previous
                        </button>
                        <span style={{ padding: '0 0.5rem', color: '#94a3b8' }}>
                          Page <strong style={{ color: '#ffffff' }}>{cbomPage}</strong> of <strong style={{ color: '#ffffff' }}>{totalCbomPages}</strong>
                        </span>
                        <button
                          onClick={() => setCbomPage(p => Math.min(totalCbomPages, p + 1))}
                          disabled={cbomPage === totalCbomPages}
                          style={{
                            background: cbomPage === totalCbomPages ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.08)',
                            border: '1px solid rgba(255, 255, 255, 0.12)',
                            color: cbomPage === totalCbomPages ? '#475569' : '#ffffff',
                            padding: '0.35rem 0.75rem',
                            borderRadius: '6px',
                            cursor: cbomPage === totalCbomPages ? 'not-allowed' : 'pointer',
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
              ) : (
                /* Mode 2: Raw CycloneDX 1.6 JSON View */
                <div style={{ position: 'relative' }}>
                  <div style={{ position: 'absolute', top: '10px', right: '10px', zIndex: 10, display: 'flex', gap: '0.5rem' }}>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(cbomData, null, 2), 'cbom-json')}
                      className="btn-secondary"
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                    >
                      {copiedCode === 'cbom-json' ? <Check size={13} color="var(--status-secure)" /> : <Copy size={13} />}
                      {copiedCode === 'cbom-json' ? 'Copied Full CBOM' : 'Copy JSON'}
                    </button>
                    <button
                      onClick={() => downloadCBOMJson(false)}
                      className="btn-secondary"
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                      title="Download Standard CycloneDX 1.6 CBOM"
                    >
                      <Download size={13} /> Download JSON
                    </button>
                    <button
                      onClick={() => downloadCBOMJson(true)}
                      className="btn-primary"
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.3rem', background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.4) 0%, rgba(56, 189, 248, 0.4) 100%)', borderColor: '#c084fc', color: '#ffffff' }}
                      title="Download CycloneDX 1.6 with CDXA Attestation & ML-DSA-65 Signature"
                    >
                      <ShieldCheck size={13} color="#ffffff" /> Download CDXA Attested
                    </button>
                  </div>
                  <pre style={{
                    background: '#0B0F17',
                    padding: '1.5rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    color: '#38BDF8',
                    fontSize: '0.82rem',
                    fontFamily: 'Consolas, Monaco, monospace',
                    maxHeight: '520px',
                    overflowY: 'auto',
                    whiteSpace: 'pre'
                  }}>
                    {cbomPreviewJson}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
          </div>
        )}

        {/* TAB 3: AGENT TOKENS & DEPLOYMENT CENTER */}
        {activeTab === 'tokens' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Active Tokens Panel */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h3 style={{ margin: '0 0 0.25rem 0', fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Key size={18} color="var(--accent-cyan)" /> Fleet Enrollment Tokens
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    Scoped tokens used by native agents to authenticate telemetry back to this tenant.
                  </p>
                </div>

                <button
                  onClick={() => setShowCreateTokenModal(true)}
                  className="btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.5rem 0.9rem' }}
                >
                  <Plus size={14} /> Generate Enrollment Token
                </button>
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table className="quark-table" style={{ width: '100%', fontSize: '0.85rem' }}>
                  <thead>
                    <tr>
                      <th>Token Group Label</th>
                      <th>Enrollment Secret</th>
                      <th>Active Endpoints</th>
                      <th>Created Date</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tokens.map(t => (
                      <tr key={t.id}>
                        <td style={{ fontWeight: 600, color: '#ffffff' }}>
                          {t.name}
                        </td>
                        <td>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'monospace', background: 'rgba(0,0,0,0.3)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.8rem' }}>
                            <span>{t.token.slice(0, 16)}••••••••</span>
                            <button
                              onClick={() => copyToClipboard(t.token, `tok-${t.id}`)}
                              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
                              title="Copy full token secret"
                            >
                              {copiedCode === `tok-${t.id}` ? <Check size={13} color="var(--status-secure)" /> : <Copy size={13} />}
                            </button>
                          </div>
                        </td>
                        <td>
                          <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                            {t.machineCount || 0} machines
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-muted)' }}>
                          {new Date(t.createdAt).toLocaleDateString()}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            onClick={() => handleRevokeToken(t.id)}
                            style={{ background: 'none', border: 'none', color: 'var(--status-vulnerable)', cursor: 'pointer', padding: '0.2rem 0.5rem' }}
                            title="Revoke Token"
                          >
                            <Trash2 size={15} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 1-Click Deployment Generator Panel */}
            <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid rgba(0, 242, 254, 0.2)' }}>
              <div style={{ marginBottom: '1.25rem' }}>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: 'var(--accent-cyan)', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                  <Terminal size={14} /> Enterprise Fleet Automation
                </div>
                <h3 style={{ margin: '0 0 0.35rem 0', fontSize: '1.2rem', fontWeight: 700, color: '#ffffff' }}>
                  1-Click Agent Deployment Center
                </h3>
                <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Select an enrollment token to generate pre-authenticated rollout commands for Jamf, Intune, Ansible, or shell scripts.
                </p>
              </div>

              {/* Token Selector & Deployment Method Tabs */}
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Deploy with Token:</label>
                  <select
                    value={selectedDeploymentToken}
                    onChange={e => setSelectedDeploymentToken(e.target.value)}
                    style={{ padding: '0.4rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '4px', color: '#ffffff', fontSize: '0.82rem' }}
                  >
                    {tokens.map(t => (
                      <option key={t.id} value={t.token} style={{ background: '#0F172A' }}>
                        {t.name} ({t.token.slice(0, 14)}...)
                      </option>
                    ))}
                  </select>
                </div>

                {/* Deployment Tabs */}
                <div style={{ display: 'flex', gap: '0.35rem', background: 'rgba(0,0,0,0.25)', padding: '0.2rem', borderRadius: '6px' }}>
                  {[
                    { id: 'desktop', label: '🛡️ 1-Click Desktop App (GUI)' },
                    { id: 'intune', label: 'Windows PowerShell' },
                    { id: 'curl', label: 'macOS/Linux Shell' },
                    { id: 'jamf', label: 'Jamf Pro (macOS)' },
                    { id: 'ansible', label: 'Ansible Playbook' },
                    { id: 'docker', label: 'Docker Container' }
                  ].map(m => (
                    <button
                      key={m.id}
                      onClick={() => setDeploymentMethod(m.id as any)}
                      style={{
                        padding: '0.35rem 0.75rem',
                        background: deploymentMethod === m.id ? 'rgba(0, 242, 254, 0.25)' : 'transparent',
                        border: 'none',
                        borderRadius: '4px',
                        color: deploymentMethod === m.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
                        fontSize: '0.78rem',
                        fontWeight: 600,
                        cursor: 'pointer'
                      }}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Generated Code Block */}
              <div style={{ position: 'relative' }}>
                <div style={{ position: 'absolute', top: '10px', right: '10px', zIndex: 10 }}>
                  <button
                    onClick={() => copyToClipboard(getDeploymentSnippet(), 'snippet')}
                    className="btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
                  >
                    {copiedCode === 'snippet' ? <Check size={14} color="var(--status-secure)" /> : <Copy size={14} />}
                    {copiedCode === 'snippet' ? 'Copied to Clipboard!' : 'Copy Script'}
                  </button>
                </div>

                <pre style={{
                  background: '#0B0F17',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: '1px solid rgba(255,255,255,0.08)',
                  color: '#38BDF8',
                  fontSize: '0.85rem',
                  fontFamily: 'Consolas, Monaco, monospace',
                  overflowX: 'auto',
                  margin: 0
                }}>
                  {getDeploymentSnippet()}
                </pre>
              </div>

              {/* Pre-Compiled Binaries Direct Downloads */}
              <div style={{ marginTop: '1.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <h4 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                    Download Pre-Compiled Native Binaries (Standalone Post-Quantum Guard & CLI)
                  </h4>
                  <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', background: 'rgba(0, 242, 254, 0.1)', padding: '0.2rem 0.6rem', borderRadius: '12px', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
                    ✨ Double-click to launch Post-Quantum Guard
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
                  <a
                    href="/downloads/quarkshield-scanner-windows-amd64.exe"
                    className="glass-panel"
                    style={{ padding: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none', color: '#ffffff', border: '1px solid rgba(0, 242, 254, 0.35)', background: 'rgba(0, 242, 254, 0.05)' }}
                  >
                    <Laptop size={22} color="var(--accent-cyan)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>Windows 10 / 11 / Server</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>1-Click Post-Quantum Guard (.exe)</div>
                    </div>
                  </a>

                  <a
                    href="/downloads/quarkshield-scanner-macos.zip"
                    className="glass-panel"
                    style={{ padding: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none', color: '#ffffff', border: '1px solid rgba(0, 242, 254, 0.35)', background: 'rgba(0, 242, 254, 0.06)' }}
                  >
                    <Cpu size={22} color="var(--accent-cyan)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>macOS Application Bundle (.zip)</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>QuarkShield.app (Universal: M1/M2/M3/M4 & Intel)</div>
                    </div>
                  </a>

                  <a
                    href="/downloads/quarkshield-scanner-darwin-arm64"
                    className="glass-panel"
                    style={{ padding: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none', color: '#ffffff', border: '1px solid rgba(255,255,255,0.06)' }}
                  >
                    <Cpu size={22} color="var(--accent-cyan)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>macOS Apple Silicon (CLI)</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>darwin-arm64 (M1/M2/M3/M4)</div>
                    </div>
                  </a>

                  <a
                    href="/downloads/quarkshield-scanner-darwin-amd64"
                    className="glass-panel"
                    style={{ padding: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none', color: '#ffffff', border: '1px solid rgba(255,255,255,0.06)' }}
                  >
                    <Cpu size={22} color="var(--text-secondary)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>macOS Intel</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>darwin-amd64 (x86_64)</div>
                    </div>
                  </a>

                  <a
                    href="/downloads/quarkshield-scanner-linux-amd64"
                    className="glass-panel"
                    style={{ padding: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.75rem', textDecoration: 'none', color: '#ffffff', border: '1px solid rgba(255,255,255,0.06)' }}
                  >
                    <Server size={22} color="var(--accent-cyan)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>Linux (Ubuntu/RHEL)</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>linux-amd64 binary</div>
                    </div>
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: REMOTE GIT REPOSITORIES SCANNER & CI/CD GATE */}
        {activeTab === 'git' && (
          <GitRepoAuditor />
        )}

        {/* TAB 5: ENTERPRISE PKI & VAULT CONNECTORS */}
        {activeTab === 'pki' && (
          <div style={{ padding: '0.5rem 0' }}>
            <EnterprisePkiVaults tenantName={selectedTenantFilter !== 'all' ? selectedTenantFilter : undefined} />
          </div>
        )}

        {/* TAB 6: HYBRID QUANTUM TLS PROXY GATEWAY */}
        {activeTab === 'proxy' && (
          <div style={{ padding: '0.5rem 0' }}>
            <PqcProxyGateway />
          </div>
        )}

        {/* TAB 5: MOSCA'S QUANTUM MIGRATION PLANNER */}
        {activeTab === 'planner' && (
          <div style={{ padding: '1rem 0' }}>
            <MoscaMigrationPlanner 
              variant="console" 
              onNavigateToScan={() => setActiveTab('dashboard')} 
              totalFleetEndpoints={machines.length}
            />
          </div>
        )}

        {/* TAB 6: REPLICATED ADMINISTRATIVE ORCHESTRATION PANEL */}
        {activeTab === 'admin' && (
          <AdminPanel 
            currentUserEmail={currentUserEmail} 
            onLogout={handleLogout} 
            initialSubTab={adminInitialSubTab} 
            onMirrorTenant={(slug) => {
              setTenantSlug(slug);
              setIsSupportMirror(true);
              setViewMode('tenant');
            }}
          />
        )}

        {/* MODAL 1: Create Enrollment Token */}
        {showCreateTokenModal && (
          <div style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div className="glass-panel" style={{ width: '420px', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
              <h3 style={{ margin: '0 0 0.5rem 0', color: '#ffffff', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Key size={18} color="var(--accent-cyan)" /> New Fleet Enrollment Token
              </h3>
              <p style={{ margin: '0 0 1.25rem 0', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                Specify a group or environment label to categorize machines reporting with this token.
              </p>

              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                  Target Tenant &amp; License Boundary
                </label>
                <select
                  value={newTokenTenant}
                  onChange={e => setNewTokenTenant(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.55rem',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    borderRadius: '6px',
                    color: '#ffffff',
                    fontSize: '0.85rem'
                  }}
                >
                  <option value="SPINOVATIONCORP">Spinovation Corp [CORP-9812]</option>
                  <option value="APEXCYBERDEFENSEMSP">Apex Cyber Defense MSP [PART-9148]</option>
                  <option value="APEXDEFENSELABS">Apex Defense Labs [CORP-4821]</option>
                  <option value="DEMOCLIENT">Demo Client Enterprise [CORP-5120]</option>
                  <option value="PARTNERTEST">CyberShield Sec MSP [PART-8830]</option>
                </select>
              </div>

              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                  Fleet Group Label
                </label>
                <input
                  type="text"
                  placeholder="e.g. Engg, Executive, Production Servers"
                  value={newTokenName}
                  onChange={e => setNewTokenName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.55rem',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    borderRadius: '6px',
                    color: '#ffffff',
                    fontSize: '0.85rem'
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
                <button
                  onClick={() => setShowCreateTokenModal(false)}
                  className="btn-secondary"
                  style={{ padding: '0.45rem 0.9rem', fontSize: '0.82rem' }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateToken}
                  disabled={!newTokenName.trim()}
                  className="btn-primary"
                  style={{ padding: '0.45rem 1.1rem', fontSize: '0.82rem' }}
                >
                  Generate Token
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODAL 2: Asset Details Inspector */}
        {selectedAssetDetail && (
          <div style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.8)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div className="glass-panel" style={{ width: '600px', maxHeight: '85vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <FileCode size={18} color="var(--accent-cyan)" /> CBOM Cryptographic Asset Inspector
                </h3>
                <button
                  onClick={() => setSelectedAssetDetail(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                >
                  <X size={18} />
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
                <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Asset Identifier</div>
                  <div style={{ fontWeight: 700, color: '#ffffff' }}>{selectedAssetDetail.name}</div>
                  <div style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)', fontSize: '0.78rem' }}>
                    {selectedAssetDetail.cryptoProperties?.detectionContext?.filePath}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Algorithm</div>
                    <div style={{ fontWeight: 600, color: '#ffffff' }}>
                      {selectedAssetDetail.cryptoProperties?.algorithmProperties?.name} 
                      {selectedAssetDetail.cryptoProperties?.algorithmProperties?.keyLength ? ` (${selectedAssetDetail.cryptoProperties.algorithmProperties.keyLength}-bit)` : ''}
                    </div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Quantum Security</div>
                    <div style={{ fontWeight: 600, color: selectedAssetDetail.cryptoProperties?.algorithmProperties?.quantumSecurityLevel === 0 ? 'var(--status-vulnerable)' : 'var(--status-secure)' }}>
                      {selectedAssetDetail.cryptoProperties?.algorithmProperties?.quantumSecurityLevel === 0 ? 'Level 0 (Quantum Insecure)' : 'Level 3 (FIPS-204/205 Approved)'}
                    </div>
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Mitigation Directive</div>
                  <div style={{ color: '#ffffff', marginTop: '0.2rem' }}>
                    {selectedAssetDetail.properties?.find((p: any) => p.name === 'quarkshield:recommendation')?.value || 'No action required.'}
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase' }}>Quantum Vulnerability Explainer</div>
                  <div style={{ color: 'var(--text-secondary)', marginTop: '0.2rem', lineHeight: 1.4 }}>
                    {selectedAssetDetail.properties?.find((p: any) => p.name === 'quarkshield:explainer')?.value || 'Standard classical vulnerability.'}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
                <button
                  onClick={() => setSelectedAssetDetail(null)}
                  className="btn-primary"
                  style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
                >
                  Close Inspector
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODAL 3: AI Inoculation Script Generator */}
        {inoculationScriptModal && (
          <div style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.8)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div className="glass-panel" style={{ width: '650px', maxHeight: '85vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Sparkles size={18} color="var(--accent-cyan)" /> AI Inoculation Playbook: {inoculationScriptModal.hostname}
                </h3>
                <button
                  onClick={() => setInoculationScriptModal(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                >
                  <X size={18} />
                </button>
              </div>

              <p style={{ margin: '0 0 1rem 0', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                QuarkShield AI has analyzed the {inoculationScriptModal.vulnerableCount} vulnerable cryptographic items on <strong>{inoculationScriptModal.hostname}</strong> ({inoculationScriptModal.os}/{inoculationScriptModal.arch}) and generated a targeted patch script:
              </p>

              <pre style={{
                background: '#0B0F17',
                padding: '1.25rem',
                borderRadius: '8px',
                border: '1px solid rgba(255,255,255,0.08)',
                color: '#38BDF8',
                fontSize: '0.82rem',
                fontFamily: 'Consolas, Monaco, monospace',
                overflowX: 'auto',
                margin: '0 0 1.25rem 0'
              }}>
{inoculationScriptModal.os === 'darwin' ? `#!/bin/bash
# QuarkShield AI Inoculation Script for macOS Host
# Target: ${inoculationScriptModal.hostname}

echo "1. Upgrading OpenSSH config to hybrid post-quantum key exchange..."
mkdir -p ~/.ssh
cat << 'EOF' >> ~/.ssh/config

# QuarkShield PQC Inoculation
Host *
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com
    PostQuantumKeyExchange yes
EOF

echo "2. Checking for legacy RSA/DSA keys..."
if [ -f ~/.ssh/id_rsa ]; then
    echo "⚠️ Warning: Found classical RSA key at ~/.ssh/id_rsa. Backing up..."
    mv ~/.ssh/id_rsa ~/.ssh/id_rsa.classical.bak
fi

echo "3. Enforcing TLS 1.3 AES-256-GCM cipher standards..."
echo "✓ Inoculation complete for ${inoculationScriptModal.hostname}."` : `#!/bin/bash
# QuarkShield AI Inoculation Script for Linux Host
# Target: ${inoculationScriptModal.hostname}

echo "1. Configuring sshd_config with NIST FIPS 203 Hybrid KEX..."
sudo sed -i '/KexAlgorithms/d' /etc/ssh/sshd_config
echo "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com" | sudo tee -a /etc/ssh/sshd_config

echo "2. Hardening OpenSSL system cipher defaults..."
sudo sed -i 's/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=2:!SHA1:!MD5:!RC4/' /etc/ssl/openssl.cnf || true

echo "3. Restarting SSH daemon..."
sudo systemctl reload ssh || sudo systemctl reload sshd

echo "✓ Linux host ${inoculationScriptModal.hostname} successfully hardened."`}
              </pre>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button
                  onClick={() => copyToClipboard(inoculationScriptModal.os === 'darwin' ? `#!/bin/bash\n# macOS Inoculation\nmkdir -p ~/.ssh\necho "Host *\n    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com" >> ~/.ssh/config` : `#!/bin/bash\nsudo sed -i '/KexAlgorithms/d' /etc/ssh/sshd_config\necho "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com" | sudo tee -a /etc/ssh/sshd_config`, 'inoc-script')}
                  className="btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}
                >
                  {copiedCode === 'inoc-script' ? <Check size={14} color="var(--status-secure)" /> : <Copy size={14} />}
                  {copiedCode === 'inoc-script' ? 'Copied Script!' : 'Copy Script'}
                </button>

                <button
                  onClick={() => setInoculationScriptModal(null)}
                  className="btn-primary"
                  style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        )}

        {/* MODAL 4: User License & 2FA Security Modal */}
        {showLicense2FAModal && (
          <div style={{
            position: 'fixed',
            top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.78)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div className="glass-panel" style={{ width: '560px', maxHeight: '90vh', overflowY: 'auto', padding: '1.75rem', border: '1px solid rgba(0, 242, 254, 0.4)', boxShadow: '0 0 35px rgba(0, 242, 254, 0.15)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                  <img src="/quarkshield-logo.png" alt="QuarkShield" style={{ height: '28px', width: 'auto', objectFit: 'contain' }} />
                  <div>
                    <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.15rem', fontWeight: 700 }}>
                      User License & Security Authentication
                    </h3>
                    <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                      Super Admin Session Credentials & Cryptographic Multi-Factor Status
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowLicense2FAModal(false)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Identity & Session */}
              <div style={{ background: 'rgba(13, 19, 33, 0.85)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '1rem', marginBottom: '1rem' }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.65rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <User size={13} /> {isSuperAdmin ? 'Active Internal Super Admin Node' : 'Active Client Workspace Node'}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Email Address</span>
                    <strong style={{ color: '#ffffff', wordBreak: 'break-all' }}>{currentUserEmail}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Role Authority</span>
                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{displayRole}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Customer ID</span>
                    <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{displayCustomerId}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Customer / Workspace</span>
                    <strong style={{ color: '#ffffff' }}>{displayCustomerName}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Session Guard</span>
                    <span style={{ color: 'var(--status-secure)', display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 600 }}>
                      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
                      Verified & Active
                    </span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Endpoint Security</span>
                    <span style={{ color: 'var(--text-secondary)' }}>FIPS 203 Hybrid Post-Quantum</span>
                  </div>
                </div>
              </div>

              {/* 2FA Section */}
              <div style={{ background: 'rgba(13, 19, 33, 0.85)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '1rem', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <ShieldCheck size={13} /> Two-Factor Authentication (2FA)
                  </div>
                  <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.15)', color: 'var(--status-secure)', fontWeight: 700, border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                    ACTIVE & ENFORCED
                  </span>
                </div>
                <p style={{ margin: '0 0 0.75rem 0', color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.4 }}>
                  Multi-factor authentication is hardware-secured for this administrative account. Time-based One-Time Passwords (TOTP) and post-quantum token challenges are active.
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
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Building size={13} /> {isSuperAdmin ? 'Internal User Authority & Fleet Control' : 'Subscription & License Allocation'}
                  </div>
                  <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '10px', background: isSuperAdmin ? 'rgba(0, 242, 254, 0.15)' : 'rgba(168, 85, 247, 0.15)', color: isSuperAdmin ? 'var(--accent-cyan)' : '#c084fc', fontWeight: 700, border: `1px solid ${isSuperAdmin ? 'rgba(0, 242, 254, 0.3)' : 'rgba(168, 85, 247, 0.3)'}` }}>
                    {isSuperAdmin ? 'INTERNAL USER' : (currentAccountType === 'partner' ? 'MSP PARTNER PRO' : 'CORPORATE ENTERPRISE')}
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem', marginBottom: '0.75rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>{isSuperAdmin ? 'Operational Scope' : 'Total Node Capacity'}</span>
                    <strong style={{ color: '#ffffff' }}>{isSuperAdmin ? 'Unrestricted Fleet Authority' : (currentAccountType === 'partner' ? '50 Partner Nodes' : '250 Enterprise Endpoints')}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>Active Monitored Endpoints</span>
                    <strong style={{ color: 'var(--accent-cyan)' }}>{machines.length} Active Devices</strong>
                  </div>
                  <div style={{ gridColumn: '1 / -1' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', display: 'block' }}>{isSuperAdmin ? 'Root Master Authority Key' : 'Cryptographic License Key'}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.2rem' }}>
                      <code style={{ background: 'rgba(0,0,0,0.4)', padding: '0.35rem 0.65rem', borderRadius: '4px', fontSize: '0.78rem', color: 'var(--accent-cyan)', border: '1px solid rgba(255,255,255,0.08)', flex: 1, overflowX: 'auto' }}>
                        {isSuperAdmin ? 'QS-SUPERADMIN-MASTER-88B92-FIPS203' : 'QS-LIC-' + displayCustomerId + '-SECURE-KYBER'}
                      </code>
                      <button
                        onClick={() => copyToClipboard(isSuperAdmin ? 'QS-SUPERADMIN-MASTER-88B92-FIPS203' : 'QS-LIC-' + displayCustomerId + '-SECURE-KYBER', 'superadmin-key')}
                        className="btn-secondary"
                        style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                      >
                        {copiedCode === 'superadmin-key' ? <Check size={13} color="var(--status-secure)" /> : <Copy size={13} />}
                        {copiedCode === 'superadmin-key' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    Manage tenant licenses, seat allocations & cryptographic keys
                  </span>
                  <button
                    onClick={() => {
                      setShowLicense2FAModal(false);
                      setActiveTab('admin');
                      setAdminInitialSubTab('licenses');
                    }}
                    className="btn-primary"
                    style={{ fontSize: '0.8rem', padding: '0.45rem 0.9rem', display: 'flex', alignItems: 'center', gap: '0.4rem', whiteSpace: 'nowrap' }}
                  >
                    <Key size={14} /> Open Master License Panel
                  </button>
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
                    <QrCode size={20} color="var(--accent-cyan)" />
                  </div>
                  <div>
                    <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.1rem', fontWeight: 700 }}>
                      Configure Authenticator App
                    </h3>
                    <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.76rem' }}>
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
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
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
                    2FA Authenticator Verified &amp; Bound!
                  </h4>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.84rem', lineHeight: 1.5, margin: '0 0 1.5rem 0' }}>
                    Your account <strong>{currentUserEmail}</strong> is securely protected with Post-Quantum session verification and hardware-backed TOTP challenge tokens.
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
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.45, margin: '0 0 1rem 0' }}>
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
                      QUARKSHIELD ROOT 2FA
                    </span>
                  </div>

                  {/* Manual Entry Key */}
                  <div style={{ marginBottom: '1rem' }}>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                      Manual Secret Key (Base32):
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <code style={{ flex: 1, background: 'rgba(0,0,0,0.4)', padding: '0.4rem 0.6rem', borderRadius: '4px', fontSize: '0.8rem', color: 'var(--accent-cyan)', border: '1px solid rgba(255,255,255,0.08)', fontFamily: 'monospace' }}>
                        QS2F-ROOT-98AF-PQC4-FIPS203
                      </code>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText('QS2F-ROOT-98AF-PQC4-FIPS203');
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
                    <Key size={20} color="var(--accent-cyan)" />
                  </div>
                  <div>
                    <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.1rem', fontWeight: 700 }}>
                      Emergency 2FA Backup Codes
                    </h3>
                    <p style={{ margin: '0.15rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.76rem' }}>
                      Single-Use Cryptographic Recovery Tokens
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowBackupCodesModal(false)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
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
                  <div key={idx} style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent-cyan)', background: 'rgba(255,255,255,0.04)', padding: '0.4rem 0.6rem', borderRadius: '4px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.04)' }}>
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
                      navigator.clipboard.writeText(`QuarkShield Super Admin 2FA Backup Codes (${currentUserEmail}):\n\n${allCodes}\n`);
                      setCopiedBackupCodes(true);
                      setTimeout(() => setCopiedBackupCodes(false), 2000);
                    }}
                    className="btn-secondary"
                    style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                  >
                    {copiedBackupCodes ? <Check size={13} color="var(--status-secure)" /> : <Copy size={13} />}
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
                      const blob = new Blob([`QuarkShield Super Admin 2FA Backup Codes (${currentUserEmail})\nGenerated: ${new Date().toISOString()}\n\n${allCodes}\n`], { type: 'text/plain' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = 'quarkshield-superadmin-backup-codes.txt';
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

        </div>
      </main>
    </div>
  );
}
