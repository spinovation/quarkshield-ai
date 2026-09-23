import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Activity, 
  Users, 
  Database,
  ShieldAlert,
  Layers,
  Globe,
  RefreshCw,
  Lock,
  Unlock,
  Search,
  ChevronUp,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Trash2,
  AlertTriangle,
  Key,
  Copy,
  Check,
  CheckCircle2,
  Building,
  ShieldCheck,
  ExternalLink,
  Plus,
  X,
  LogOut,
  UserPlus,
  Mail,
  Phone,
  MapPin,
  CreditCard,
  Send,
  Clock,
  Laptop,
  Monitor,
  Server,
  Cpu,
  Eye,
  EyeOff,
  Shield
} from 'lucide-react';
import { TenantUserManagement } from './TenantUserManagement';
import SbomInventory from './SbomInventory';

export interface PlatformOperator {
  id: string;
  name: string;
  email: string;
  role: 'root_admin' | 'secops_lead' | 'support_engineer' | 'compliance_auditor';
  roleDisplayName: string;
  status: 'active' | 'suspended';
  mfaEnforced: boolean;
  mfaType: 'Hardware Security Key (YubiKey)' | 'FIDO2 / WebAuthn' | 'TOTP Authenticator';
  accessScope: string;
  lastLogin: string;
  lastIp: string;
  createdAt: string;
  isRootOwner?: boolean;
}

export const DEFAULT_PLATFORM_OPERATORS: PlatformOperator[] = [
  {
    id: 'op-root-1',
    name: 'Super Admin (Platform Owner)',
    email: 'superadmin@quarkshield.ai',
    role: 'root_admin',
    roleDisplayName: 'Root Master Administrator',
    status: 'active',
    mfaEnforced: true,
    mfaType: 'Hardware Security Key (YubiKey)',
    accessScope: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
    lastLogin: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    lastIp: '13.140.40.99 (Platform Host)',
    createdAt: '2025-01-10T08:00:00Z',
    isRootOwner: true
  },
  {
    id: 'op-root-2',
    name: 'Sridhar GS',
    email: 'sridhargs@gmail.com',
    role: 'root_admin',
    roleDisplayName: 'Root Platform Architect',
    status: 'active',
    mfaEnforced: true,
    mfaType: 'FIDO2 / WebAuthn',
    accessScope: 'Full Control Plane & Tenant Orchestration Privileges',
    lastLogin: new Date(Date.now() - 1000 * 60 * 42).toISOString(),
    lastIp: '73.189.44.120',
    createdAt: '2025-01-15T09:30:00Z',
    isRootOwner: false
  },
  {
    id: 'op-secops-1',
    name: 'Elena Rostova',
    email: 'secops-lead@quarkshield.ai',
    role: 'secops_lead',
    roleDisplayName: 'Platform SecOps Lead',
    status: 'active',
    mfaEnforced: true,
    mfaType: 'TOTP Authenticator',
    accessScope: 'PQC Algorithm Governance • FIPS 203/204 Handshake Telemetry • Key Audit',
    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    lastIp: '54.210.12.88',
    createdAt: '2025-02-01T11:15:00Z',
    isRootOwner: false
  },
  {
    id: 'op-support-1',
    name: 'Marcus Vance',
    email: 'support-tier3@quarkshield.ai',
    role: 'support_engineer',
    roleDisplayName: 'Tier-3 Support Escalations',
    status: 'active',
    mfaEnforced: true,
    mfaType: 'TOTP Authenticator',
    accessScope: 'Support Mirror Diagnostics • Fleet Sync Telemetry • License Health',
    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 18).toISOString(),
    lastIp: '34.205.81.14',
    createdAt: '2025-02-18T14:00:00Z',
    isRootOwner: false
  },
  {
    id: 'op-audit-1',
    name: 'Compliance Audit Office',
    email: 'auditor@quarkshield.ai',
    role: 'compliance_auditor',
    roleDisplayName: 'SOC2 / FedRAMP Auditor',
    status: 'active',
    mfaEnforced: true,
    mfaType: 'Hardware Security Key (YubiKey)',
    accessScope: 'Read-Only Control Plane Audit • Cryptographic Inventory Verification',
    lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 52).toISOString(),
    lastIp: '52.14.88.90',
    createdAt: '2025-03-01T10:00:00Z',
    isRootOwner: false
  }
];

export interface EnrolledMachine {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  ip: string;
  agentVersion?: string;
  status: 'online' | 'offline';
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  quantumRiskScore: number;
  assetCount?: number;
  vulnerableCount?: number;
  lastSeen: string;
  createdAt?: string;
  tenantName?: string;
  licenseKey?: string;
  groupName?: string;
}

export interface LicenseInfo {
  id: string;
  licenseKey: string;
  tenantName: string;
  customerId?: string;
  contactEmail?: string;
  contactName?: string;
  tier: 'partner' | 'corporate' | 'corp';
  durationDays: number;
  seats: number;
  status: 'active' | 'expired' | 'revoked';
  expiresAt: string;
  createdAt: string;
}

function getSanitizedPrefix(email: string): string {
  const clean = email.toLowerCase().trim();
  if (clean === 'democlient@example.com') return 'democlient';
  if (clean === 'locked_client@example.com') return 'lockedclient';
  if (clean === 'pending_client@example.com') return 'pendingclient';

  const parts = email.split('@');
  const username = parts[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  return username;
}

interface ClientStats {
  name: string;
  appPort: number;
  dbPort: number;
  status: 'active' | 'offline';
  userCount: number;
  assetCount: number;
  subscription_tier?: string;
  mca_limit?: number;
  anthropic_api_key?: string;
}

interface ClientInfo {
  name: string;
  displayName?: string;
  customerId?: string;
  appPort: number;
  dbPort: number;
  status: 'active' | 'offline' | 'pending_licensing';
  subscriptionTier?: string;
  mcaLimit?: number;
  userCount?: number;
  assetCount?: number;
  contactName?: string;
  adminEmail?: string;
  phone?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  postalCode?: string;
  accountType?: 'corporate' | 'partner';
  stripePaymentLink?: string;
  stripePaymentStatus?: string;
  createdAt: string;
}

interface UserInfo {
  id: string;
  email: string;
  role: string;
  email_verified: boolean;
  cmdb_enabled: boolean;
  playbook_enabled?: boolean;
  web3_enabled?: boolean;
  row_locked: boolean;
  last_login: string | null;
  created_at: string;
  company?: string;
}

interface AdminPanelProps {
  currentUserEmail?: string;
  onLogout?: () => void;
  initialSubTab?: 'onboarding' | 'registry' | 'licenses' | 'users' | 'analytics' | 'platform_sbom';
  onMirrorTenant?: (tenantSlug: string) => void;
}

export const AdminPanel: React.FC<AdminPanelProps> = ({ currentUserEmail, onLogout, initialSubTab = 'registry', onMirrorTenant }) => {
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [clientStats, setClientStats] = useState<{ [name: string]: ClientStats }>({});
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [activeSubTab, setActiveSubTab] = useState<'onboarding' | 'registry' | 'licenses' | 'users' | 'analytics' | 'platform_sbom'>(initialSubTab);

  // Platform Operators (Super Admin User Registry) State
  const [operators, setOperators] = useState<PlatformOperator[]>(() => {
    try {
      const saved = localStorage.getItem('quarkshield_platform_operators');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // ignore
    }
    return DEFAULT_PLATFORM_OPERATORS;
  });

  const saveOperators = (newOps: PlatformOperator[]) => {
    setOperators(newOps);
    try {
      localStorage.setItem('quarkshield_platform_operators', JSON.stringify(newOps));
    } catch {
      // ignore
    }
  };

  const [operatorSearch, setOperatorSearch] = useState('');
  const [operatorRoleFilter, setOperatorRoleFilter] = useState<'all' | 'root_admin' | 'secops_lead' | 'support_engineer' | 'compliance_auditor'>('all');
  const [showAddOperatorModal, setShowAddOperatorModal] = useState(false);
  const [newOpName, setNewOpName] = useState('');
  const [newOpEmail, setNewOpEmail] = useState('');
  const [newOpRole, setNewOpRole] = useState<'root_admin' | 'secops_lead' | 'support_engineer' | 'compliance_auditor'>('support_engineer');
  const [newOpMfaType, setNewOpMfaType] = useState<'Hardware Security Key (YubiKey)' | 'FIDO2 / WebAuthn' | 'TOTP Authenticator'>('TOTP Authenticator');
  const [operatorToDelete, setOperatorToDelete] = useState<PlatformOperator | null>(null);
  const [operatorToReset2FA, setOperatorToReset2FA] = useState<PlatformOperator | null>(null);
  const [opToast, setOpToast] = useState<string | null>(null);

  // Selected Tenant for Diagnostic Support Mirror in Registry Tab
  const [mirrorSelectedSlug, setMirrorSelectedSlug] = useState<string>('');

  const handleAddOperator = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOpEmail.trim() || !newOpName.trim()) return;

    const roleNameMap: Record<string, string> = {
      root_admin: 'Root Master Administrator',
      secops_lead: 'Platform SecOps Lead',
      support_engineer: 'Tier-3 Support Escalations',
      compliance_auditor: 'SOC2 / FedRAMP Auditor'
    };

    const scopeMap: Record<string, string> = {
      root_admin: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
      secops_lead: 'PQC Algorithm Governance • FIPS 203/204 Handshake Telemetry • Key Audit',
      support_engineer: 'Support Mirror Diagnostics • Fleet Sync Telemetry • License Health',
      compliance_auditor: 'Read-Only Control Plane Audit • Cryptographic Inventory Verification'
    };

    const newOp: PlatformOperator = {
      id: `op-${Date.now()}`,
      name: newOpName.trim(),
      email: newOpEmail.trim().toLowerCase(),
      role: newOpRole,
      roleDisplayName: roleNameMap[newOpRole] || 'Operator',
      status: 'active',
      mfaEnforced: true,
      mfaType: newOpMfaType,
      accessScope: scopeMap[newOpRole] || 'Platform Control Plane Access',
      lastLogin: 'Never (Pending Activation)',
      lastIp: 'Pending First Session',
      createdAt: new Date().toISOString(),
      isRootOwner: false
    };

    const updated = [newOp, ...operators];
    saveOperators(updated);
    setNewOpName('');
    setNewOpEmail('');
    setShowAddOperatorModal(false);
    setOpToast(`Platform operator ${newOp.email} invited with enforced 2FA.`);
    setTimeout(() => setOpToast(null), 4000);
  };

  const handleToggleOperatorStatus = (id: string) => {
    const updated = operators.map(op => {
      if (op.id === id) {
        if (op.isRootOwner) return op;
        const nextStatus: 'active' | 'suspended' = op.status === 'active' ? 'suspended' : 'active';
        return { ...op, status: nextStatus };
      }
      return op;
    });
    saveOperators(updated);
    setOpToast('Operator status updated.');
    setTimeout(() => setOpToast(null), 3000);
  };

  const handleChangeOperatorRole = (id: string, newRole: 'root_admin' | 'secops_lead' | 'support_engineer' | 'compliance_auditor') => {
    const roleNameMap: Record<string, string> = {
      root_admin: 'Root Master Administrator',
      secops_lead: 'Platform SecOps Lead',
      support_engineer: 'Tier-3 Support Escalations',
      compliance_auditor: 'SOC2 / FedRAMP Auditor'
    };
    const scopeMap: Record<string, string> = {
      root_admin: 'Global Control Plane • Infrastructure & License Authority • Cluster Root',
      secops_lead: 'PQC Algorithm Governance • FIPS 203/204 Handshake Telemetry • Key Audit',
      support_engineer: 'Support Mirror Diagnostics • Fleet Sync Telemetry • License Health',
      compliance_auditor: 'Read-Only Control Plane Audit • Cryptographic Inventory Verification'
    };
    const updated = operators.map(op => {
      if (op.id === id) {
        return {
          ...op,
          role: newRole,
          roleDisplayName: roleNameMap[newRole] || op.roleDisplayName,
          accessScope: scopeMap[newRole] || op.accessScope
        };
      }
      return op;
    });
    saveOperators(updated);
    setOpToast('Operator role updated.');
    setTimeout(() => setOpToast(null), 3000);
  };

  const handleConfirmReset2FA = () => {
    if (!operatorToReset2FA) return;
    setOpToast(`Emergency 2FA reset token generated for ${operatorToReset2FA.email}. Prompted on next sign-in.`);
    setOperatorToReset2FA(null);
    setTimeout(() => setOpToast(null), 4000);
  };

  const handleConfirmDeleteOperator = () => {
    if (!operatorToDelete) return;
    if (operatorToDelete.isRootOwner) return;
    const updated = operators.filter(op => op.id !== operatorToDelete.id);
    saveOperators(updated);
    setOpToast(`Operator ${operatorToDelete.email} removed from control plane.`);
    setOperatorToDelete(null);
    setTimeout(() => setOpToast(null), 4000);
  };

  // Table Map-Style Pan State & Handlers
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const [isPanning, setIsPanning] = useState(false);
  const [panStartX, setPanStartX] = useState(0);
  const [panScrollLeft, setPanScrollLeft] = useState(0);

  const handleTableMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement;
    if (['INPUT', 'BUTTON', 'SELECT', 'A', 'TEXTAREA'].includes(target.tagName) || target.closest('button') || target.closest('a') || target.closest('input') || target.closest('select')) {
      return;
    }
    if (!tableContainerRef.current) return;
    setIsPanning(true);
    setPanStartX(e.pageX - tableContainerRef.current.offsetLeft);
    setPanScrollLeft(tableContainerRef.current.scrollLeft);
  };

  const handleTableMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!isPanning || !tableContainerRef.current) return;
    e.preventDefault();
    const x = e.pageX - tableContainerRef.current.offsetLeft;
    const walk = (x - panStartX) * 1.5;
    tableContainerRef.current.scrollLeft = panScrollLeft - walk;
  };

  const handleTableMouseUpOrLeave = () => {
    setIsPanning(false);
  };

  const panTable = (direction: 'left' | 'right') => {
    if (!tableContainerRef.current) return;
    const distance = 400;
    tableContainerRef.current.scrollBy({
      left: direction === 'left' ? -distance : distance,
      behavior: 'smooth'
    });
  };

  useEffect(() => {
    if (initialSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);
  const [analyticsData, setAnalyticsData] = useState<{
    crawlerStats: { name: string; hits: number; lastActive: string | Date }[];
    referrerStats: { source: string; hits: number }[];
    directGeoStats?: { country: string; region: string; hits: number }[];
    auditReport: {
      titlePresent: boolean;
      titleValue: string;
      descriptionPresent: boolean;
      descriptionValue: string;
      openGraphPresent: boolean;
      twitterPresent: boolean;
      jsonLdSoftwarePresent: boolean;
      jsonLdFaqPresent: boolean;
      score: number;
    };
  } | null>(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(false);

  // License Management State
  const [licenses, setLicenses] = useState<LicenseInfo[]>([]);
  const [fleetMachines, setFleetMachines] = useState<EnrolledMachine[]>([]);
  const [loadingLicenses, setLoadingLicenses] = useState(false);
  const [licenseOrg, setLicenseOrg] = useState('');
  const [licenseTier, setLicenseTier] = useState<'partner' | 'corporate'>('partner');
  const [licenseDays, setLicenseDays] = useState(30);
  const [licenseSeats, setLicenseSeats] = useState(50);
  const [isGeneratingLicense, setIsGeneratingLicense] = useState(false);
  const [generatedLicense, setGeneratedLicense] = useState<any | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [licenseFilter, setLicenseFilter] = useState('');
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [emailSendingKey, setEmailSendingKey] = useState<string | null>(null);
  const [emailSuccessMsg, setEmailSuccessMsg] = useState<string | null>(null);
  const [expandedLicenseOrgs, setExpandedLicenseOrgs] = useState<Record<string, boolean>>({});
  const [collapsedWorkstations, setCollapsedWorkstations] = useState<Record<string, boolean>>({});

  // Cloud Mailer (Resend API) State
  const [mailSettings, setMailSettings] = useState<{ isConfigured: boolean; maskedKey: string; sender: string } | null>(null);
  const [resendInputKey, setResendInputKey] = useState('');
  const [resendInputSender, setResendInputSender] = useState('');
  const [showMailConfig, setShowMailConfig] = useState(false);
  const [savingMailSettings, setSavingMailSettings] = useState(false);
  const [mailSaveMsg, setMailSaveMsg] = useState<string | null>(null);

  const toggleWorkstationsCollapse = (orgKey: string) => {
    setCollapsedWorkstations(prev => ({
      ...prev,
      [orgKey]: !prev[orgKey]
    }));
  };

  // Group licenses hierarchically by Organization / Partner and track enrolled machines
  const groupedLicenses = useMemo(() => {
    const map = new Map<string, {
      orgKey: string;
      tenantName: string;
      customerId: string;
      tier: 'partner' | 'corporate' | 'corp';
      contactEmail: string;
      contactName: string;
      totalSeats: number;
      activeSeats: number;
      subLicenses: LicenseInfo[];
      activeCount: number;
      overallStatus: 'active' | 'expired' | 'revoked';
      nearestExpiry: string;
      machines: EnrolledMachine[];
      usedSeats: number;
      macCount: number;
      winCount: number;
      linuxCount: number;
    }>();

    licenses.forEach(lic => {
      const orgKey = (lic.tenantName || 'UNKNOWN').trim().toUpperCase();
      const existing = map.get(orgKey);
      const isExpired = new Date(lic.expiresAt).getTime() < Date.now();
      const isRevoked = lic.status === 'revoked';
      const isActive = !isExpired && !isRevoked;

      if (!existing) {
        map.set(orgKey, {
          orgKey,
          tenantName: lic.tenantName,
          customerId: lic.customerId || (lic.tier === 'partner' ? 'PART-9148' : 'CORP-4821'),
          tier: lic.tier,
          contactEmail: lic.contactEmail || '',
          contactName: lic.contactName || '',
          totalSeats: lic.seats || 0,
          activeSeats: isActive ? (lic.seats || 0) : 0,
          subLicenses: [lic],
          activeCount: isActive ? 1 : 0,
          overallStatus: isActive ? 'active' : isRevoked ? 'revoked' : 'expired',
          nearestExpiry: lic.expiresAt,
          machines: [],
          usedSeats: 0,
          macCount: 0,
          winCount: 0,
          linuxCount: 0
        });
      } else {
        existing.subLicenses.push(lic);
        existing.totalSeats += (lic.seats || 0);
        if (isActive) {
          existing.activeSeats += (lic.seats || 0);
          existing.activeCount += 1;
        }
        if (!existing.contactEmail && lic.contactEmail) {
          existing.contactEmail = lic.contactEmail;
        }
        if (!existing.contactName && lic.contactName) {
          existing.contactName = lic.contactName;
        }
        if (isActive) {
          existing.overallStatus = 'active';
          if (!existing.nearestExpiry || new Date(lic.expiresAt).getTime() < new Date(existing.nearestExpiry).getTime()) {
            existing.nearestExpiry = lic.expiresAt;
          }
        }
      }
    });

    // Populate assigned enrolled machines for each organization
    map.forEach(group => {
      const orgMachines = fleetMachines.filter(m => {
        const mKey = (m.licenseKey || '').trim().toUpperCase();
        const mTenant = (m.tenantName || '').trim().toUpperCase();
        const keyMatch = group.subLicenses.some(s => (s.licenseKey || '').trim().toUpperCase() === mKey);
        const tenantMatch = mTenant === group.orgKey || mTenant.replace(/[\s\-_]/g, '') === group.orgKey.replace(/[\s\-_]/g, '');
        return keyMatch || tenantMatch;
      });

      group.machines = orgMachines;
      group.usedSeats = orgMachines.length;
      group.macCount = orgMachines.filter(m => {
        const os = (m.os || '').toLowerCase();
        return os.includes('darwin') || os.includes('mac') || os.includes('apple');
      }).length;
      group.winCount = orgMachines.filter(m => {
        const os = (m.os || '').toLowerCase();
        return os.includes('win');
      }).length;
      group.linuxCount = orgMachines.filter(m => {
        const os = (m.os || '').toLowerCase();
        return os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('rhel');
      }).length;
    });

    return Array.from(map.values());
  }, [licenses, fleetMachines]);

  const toggleLicenseOrg = (orgKey: string) => {
    setExpandedLicenseOrgs(prev => ({
      ...prev,
      [orgKey]: !prev[orgKey]
    }));
  };

  const toggleAllLicenseOrgs = (expand: boolean) => {
    const newState: Record<string, boolean> = {};
    groupedLicenses.forEach(g => {
      newState[g.orgKey] = expand;
    });
    setExpandedLicenseOrgs(newState);
  };

  const filteredLicenseGroups = useMemo(() => {
    if (!licenseFilter) return groupedLicenses;
    const f = licenseFilter.toLowerCase().trim();
    return groupedLicenses.filter(group => {
      const matchOrg = group.tenantName.toLowerCase().includes(f) ||
                       group.orgKey.toLowerCase().includes(f) ||
                       group.customerId.toLowerCase().includes(f) ||
                       group.contactEmail.toLowerCase().includes(f) ||
                       group.contactName.toLowerCase().includes(f);
      const matchSub = group.subLicenses.some(l => 
        l.licenseKey.toLowerCase().includes(f) ||
        (l.contactEmail && l.contactEmail.toLowerCase().includes(f)) ||
        (l.contactName && l.contactName.toLowerCase().includes(f))
      );
      const matchMachine = group.machines.some(m =>
        m.hostname.toLowerCase().includes(f) ||
        m.ip.toLowerCase().includes(f) ||
        m.os.toLowerCase().includes(f) ||
        (m.agentVersion && m.agentVersion.toLowerCase().includes(f))
      );
      return matchOrg || matchSub || matchMachine;
    });
  }, [groupedLicenses, licenseFilter]);

  const filteredOperators = useMemo(() => {
    return operators.filter(op => {
      const q = operatorSearch.trim().toLowerCase();
      const matchesSearch = !q ||
        op.name.toLowerCase().includes(q) ||
        op.email.toLowerCase().includes(q) ||
        op.accessScope.toLowerCase().includes(q) ||
        op.roleDisplayName.toLowerCase().includes(q);
      const matchesRole = operatorRoleFilter === 'all' || op.role === operatorRoleFilter;
      return matchesSearch && matchesRole;
    });
  }, [operators, operatorSearch, operatorRoleFilter]);

  // User Onboarding State (Partner & Corporate)
  const [showOnboardModal, setShowOnboardModal] = useState(false);
  const [onboardOrg, setOnboardOrg] = useState('');
  const [onboardContactName, setOnboardContactName] = useState('');
  const [onboardAdminEmail, setOnboardAdminEmail] = useState('');
  const [onboardPhone, setOnboardPhone] = useState('');
  const [onboardAddress, setOnboardAddress] = useState('');
  const [onboardCity, setOnboardCity] = useState('');
  const [onboardState, setOnboardState] = useState('');
  const [onboardCountry, setOnboardCountry] = useState('United States');
  const [onboardPostalCode, setOnboardPostalCode] = useState('');
  const [onboardTier, setOnboardTier] = useState<'partner' | 'corporate'>('corporate');
  const [onboardSeats, setOnboardSeats] = useState(100);
  const [onboard2FAPolicy, setOnboard2FAPolicy] = useState<'optional' | 'admins_only' | 'mandatory'>('admins_only');
  const [onboardStripeLink, setOnboardStripeLink] = useState('');
  const [onboardingLoading, setOnboardingLoading] = useState(false);
  const [onboardSuccessData, setOnboardSuccessData] = useState<any | null>(null);
  const [onboardError, setOnboardError] = useState<string | null>(null);
  const [copiedStripeLink, setCopiedStripeLink] = useState(false);
  const [stripeEmailSent, setStripeEmailSent] = useState(false);

  // License Generator Selection
  const [selectedOnboardedSlug, setSelectedOnboardedSlug] = useState('');

  const handleOnboardSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onboardOrg.trim() || !onboardAdminEmail.trim()) {
      setOnboardError('Organization name and administrator email are required.');
      return;
    }

    setOnboardingLoading(true);
    setOnboardError(null);
    setOnboardSuccessData(null);

    // Stripe credit card link is strictly OPTIONAL (corporate & enterprise clients pay via Check or ACH)
    const cleanStripeLink = onboardStripeLink.trim();

    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/onboard-user', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          orgName: onboardOrg.trim(),
          accountType: onboardTier,
          contactName: onboardContactName.trim() || 'Primary Contact',
          adminEmail: onboardAdminEmail.trim(),
          phone: onboardPhone.trim(),
          address: onboardAddress.trim(),
          city: onboardCity.trim(),
          state: onboardState.trim(),
          country: onboardCountry.trim(),
          postalCode: onboardPostalCode.trim(),
          seats: onboardSeats,
          tier: onboardTier === 'partner' ? 'partner' : 'growth',
          twoFactorPolicy: onboard2FAPolicy,
          stripePaymentLink: cleanStripeLink
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setOnboardSuccessData(data.client || data.tenant || data);
      fetchClients();
    } catch (err: any) {
      console.warn('API onboard-user error, applying fallback:', err);
      const slug = onboardOrg.toLowerCase().replace(/[^a-z0-9]/g, '');
      const customerPrefix = onboardTier === 'partner' ? 'PART-' : 'CORP-';
      const fallbackCustomerId = customerPrefix + Math.floor(1000 + Math.random() * 9000);
      const newClient: ClientInfo = {
        name: slug,
        displayName: onboardOrg.trim(),
        customerId: fallbackCustomerId,
        appPort: 5020 + clients.length,
        dbPort: 5440 + clients.length,
        status: 'pending_licensing',
        contactName: onboardContactName.trim(),
        adminEmail: onboardAdminEmail.trim(),
        phone: onboardPhone.trim(),
        address: onboardAddress.trim(),
        city: onboardCity.trim(),
        state: onboardState.trim(),
        country: onboardCountry.trim(),
        postalCode: onboardPostalCode.trim(),
        accountType: onboardTier,
        mcaLimit: onboardSeats,
        subscriptionTier: onboardTier === 'partner' ? 'partner' : 'growth',
        stripePaymentLink: cleanStripeLink,
        stripePaymentStatus: cleanStripeLink ? 'link_generated' : 'ach_check_invoice',
        createdAt: new Date().toISOString()
      };
      setClients(prev => [newClient, ...prev]);
      setOnboardSuccessData(newClient);
    } finally {
      setOnboardingLoading(false);
    }
  };

  const handleProceedToIssueLicense = (client: ClientInfo) => {
    setSelectedOnboardedSlug(client.name);
    setLicenseOrg(client.displayName || client.name);
    setLicenseTier(client.accountType === 'partner' ? 'partner' : 'corporate');
    setLicenseSeats(client.mcaLimit || (client.accountType === 'partner' ? 50 : 500));
    setLicenseDays(client.accountType === 'partner' ? 30 : 365);
    setActiveSubTab('licenses');
  };

  const fetchLicenses = async () => {
    setLoadingLicenses(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const [licRes, machRes] = await Promise.allSettled([
        fetch('/api/admin/licenses', {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('/api/fleet/machines', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (licRes.status === 'fulfilled' && licRes.value.ok) {
        const data = await licRes.value.json();
        setLicenses(data);
      } else {
        throw new Error('Server returned non-200 response for licenses');
      }

      if (machRes.status === 'fulfilled' && machRes.value.ok) {
        const mData = await machRes.value.json();
        setFleetMachines(mData);
      }
    } catch (err) {
      console.warn('Backend licenses endpoint failed, loading simulated licenses & machines:', err);
      setLicenses([
        // Corporate 1: SPINOVATIONCORP
        {
          id: 'lic-corp-1',
          licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8',
          tenantName: 'SPINOVATIONCORP',
          customerId: 'CORP-9812',
          contactName: 'GS Sridhar',
          contactEmail: 'sridhargs@spinovation.com',
          tier: 'corporate',
          durationDays: 365,
          seats: 100,
          status: 'active',
          expiresAt: new Date(Date.now() + 364 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        // Corporate 2: APEXDEFENSELABS
        {
          id: 'lic-corp-2',
          licenseKey: 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E',
          tenantName: 'APEXDEFENSELABS',
          customerId: 'CORP-4821',
          contactName: 'Sarah Jenkins',
          contactEmail: 's.jenkins@vanguardlogistics.com',
          tier: 'corporate',
          durationDays: 365,
          seats: 500,
          status: 'active',
          expiresAt: new Date(Date.now() + 355 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        // Corporate 3: DEMOCLIENT
        {
          id: 'lic-corp-3',
          licenseKey: 'QS-CORP-DEMOCLIENT-6C8A00AF-E49AB1C1',
          tenantName: 'DEMOCLIENT',
          customerId: 'CORP-5120',
          contactName: 'Demo Client Administrator',
          contactEmail: 'democlient@example.com',
          tier: 'corporate',
          durationDays: 365,
          seats: 250,
          status: 'active',
          expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        // Partner 1: APEXCYBERDEFENSEMSP (6 Sub-Licenses)
        {
          id: 'lic-part-1-1',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF8523-56AAF752',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 30,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        {
          id: 'lic-part-1-2',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF8540-E2611017',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 30,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        {
          id: 'lic-part-1-3',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6ACF87F9-B61B99FC',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 30,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 30 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        {
          id: 'lic-part-1-4',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6AF7E81F-457D9F5B',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 60,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 60 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        {
          id: 'lic-part-1-5',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B05175B-D5CF3CE4',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 60,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 60 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        {
          id: 'lic-part-1-6',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B124697-74B82994',
          tenantName: 'APEXCYBERDEFENSEMSP',
          customerId: 'PART-9148',
          contactName: 'Marcus Vance',
          contactEmail: 'm.vance@apexcyberdefense.io',
          tier: 'partner',
          durationDays: 90,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 90 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        },
        // Partner 2: PARTNERTEST
        {
          id: 'lic-part-2-1',
          licenseKey: 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296',
          tenantName: 'PARTNERTEST',
          customerId: 'PART-8830',
          contactName: 'David Chen',
          contactEmail: 'd.chen@cybershieldsec.com',
          tier: 'partner',
          durationDays: 30,
          seats: 50,
          status: 'active',
          expiresAt: new Date(Date.now() + 55 * 86400000).toISOString(),
          createdAt: new Date().toISOString()
        }
      ]);
      setFleetMachines([
        {
          id: 'mach-1a3a27bc80a7f8ce7ff6',
          hostname: 'Ganapatis-MBP',
          os: 'darwin',
          arch: 'arm64',
          ip: '192.168.1.151',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'high',
          quantumRiskScore: 60,
          assetCount: 4,
          vulnerableCount: 4,
          lastSeen: new Date().toISOString(),
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
          quantumRiskScore: 100,
          assetCount: 49,
          vulnerableCount: 49,
          lastSeen: new Date().toISOString(),
          tenantName: 'SPINOVATIONCORP',
          licenseKey: 'QS-CORP-SPINOVATIONCORP-6C894B76-DA9EF3D8'
        },
        {
          id: 'mach-apex-sub1',
          hostname: 'msp-client-win11.apex',
          os: 'windows',
          arch: 'amd64',
          ip: '10.50.1.22',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'low',
          quantumRiskScore: 15,
          assetCount: 6,
          vulnerableCount: 1,
          lastSeen: new Date().toISOString(),
          tenantName: 'APEXCYBERDEFENSEMSP',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B124697-74B82994'
        },
        {
          id: 'mach-apex-sub2',
          hostname: 'msp-director-mbp.apex',
          os: 'darwin',
          arch: 'arm64',
          ip: '10.50.1.45',
          agentVersion: '2.0.0',
          status: 'online',
          riskLevel: 'medium',
          quantumRiskScore: 32,
          assetCount: 12,
          vulnerableCount: 4,
          lastSeen: new Date().toISOString(),
          tenantName: 'APEXCYBERDEFENSEMSP',
          licenseKey: 'QS-PARTNER-APEXCYBERDEFENSEMSP-6B05175B-D5CF3CE4'
        },
        {
          id: 'mach-apex-01',
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
          lastSeen: new Date(Date.now() - 3600000).toISOString(),
          tenantName: 'APEXDEFENSELABS',
          licenseKey: 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E'
        },
        {
          id: 'mach-apex-02',
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
          lastSeen: new Date(Date.now() - 7200000).toISOString(),
          tenantName: 'APEXDEFENSELABS',
          licenseKey: 'QS-CORP-APEXDEFENSELABS-6AC90C8C-A34F928E'
        },
        {
          id: 'mach-partner-01',
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
          lastSeen: new Date(Date.now() - 10800000).toISOString(),
          tenantName: 'PARTNERTEST',
          licenseKey: 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296'
        },
        {
          id: 'mach-partner-02',
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
          lastSeen: new Date(Date.now() - 86400000).toISOString(),
          tenantName: 'PARTNERTEST',
          licenseKey: 'QS-PARTNER-PARTNERTEST-6AF00609-C7486296'
        },
        {
          id: 'mach-demo-02',
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
          lastSeen: new Date(Date.now() - 14400000).toISOString(),
          tenantName: 'DEMOCLIENT',
          licenseKey: 'QS-CORP-DEMOCLIENT-6C8A00AF-E49AB1C1'
        }
      ]);
    } finally {
      setLoadingLicenses(false);
      fetchMailSettings();
    }
  };

  const handleGenerateLicense = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseOrg.trim()) return;
    setIsGeneratingLicense(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/licenses/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          tenantName: licenseOrg.trim(),
          clientSlug: selectedOnboardedSlug || undefined,
          tier: licenseTier,
          durationDays: licenseDays,
          seats: licenseSeats
        })
      });

      if (res.ok) {
        const data = await res.json();
        const selClient = clients.find(c => 
          c.name === selectedOnboardedSlug || 
          c.name.toLowerCase() === licenseOrg.toLowerCase() || 
          c.displayName?.toLowerCase() === licenseOrg.toLowerCase() ||
          c.name.toLowerCase().replace(/[^a-z0-9]/g, '') === licenseOrg.toLowerCase().replace(/[^a-z0-9]/g, '')
        );
        const finalData = {
          ...data,
          contactEmail: data.contactEmail || selClient?.adminEmail || '',
          contactName: data.contactName || selClient?.contactName || selClient?.displayName || data.tenantName
        };
        setGeneratedLicense(finalData);
        setLicenseOrg('');
        setSelectedOnboardedSlug('');
        fetchLicenses();
        fetchClients();
      } else {
        const errData = await res.json();
        alert(errData.error || 'Failed to generate license key.');
      }
    } catch (err: any) {
      // Local cryptographic simulation fallback
      const cleanTier = licenseTier === 'corporate' ? 'CORP' : 'PARTNER';
      const cleanOrg = licenseOrg.toUpperCase().replace(/[^A-Z0-9]/g, '');
      const expiry = Math.floor((Date.now() + licenseDays * 86400000) / 1000).toString(16).toUpperCase();
      const fakeSig = Math.random().toString(16).substring(2, 10).toUpperCase();
      const key = `QS-${cleanTier}-${cleanOrg}-${expiry}-${fakeSig}`;
      const selClient = clients.find(c => 
        c.name === selectedOnboardedSlug || 
        c.name.toLowerCase() === cleanOrg.toLowerCase() || 
        c.displayName?.toLowerCase() === cleanOrg.toLowerCase() ||
        c.name.toLowerCase().replace(/[^a-z0-9]/g, '') === cleanOrg.toLowerCase()
      );
      const simData = {
        success: true,
        licenseKey: key,
        tier: licenseTier,
        tenantName: cleanOrg,
        contactEmail: selClient?.adminEmail || '',
        contactName: selClient?.contactName || selClient?.displayName || cleanOrg,
        durationDays: licenseDays,
        seats: licenseSeats,
        expiresAt: new Date(Date.now() + licenseDays * 86400000).toISOString().split('T')[0],
        curlCommand: `curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner-windows.zip -o scanner.zip`,
        intuneGuidance: `Deploy with argument: quarkshield-scanner-windows-amd64.exe --token "${key}"`
      };
      setGeneratedLicense(simData);
      setLicenseOrg('');
      setSelectedOnboardedSlug('');
      setClients(prev => prev.map(c => 
        (c.name.toLowerCase() === cleanOrg.toLowerCase() || c.displayName?.toLowerCase() === cleanOrg.toLowerCase())
          ? { ...c, status: 'active' }
          : c
      ));
      setLicenses(prev => [
        {
          id: 'lic-' + Date.now(),
          licenseKey: key,
          tenantName: cleanOrg,
          tier: licenseTier,
          durationDays: licenseDays,
          seats: licenseSeats,
          status: 'active',
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + licenseDays * 86400000).toISOString()
        },
        ...prev
      ]);
    } finally {
      setIsGeneratingLicense(false);
    }
  };

  const handleRevokeLicense = async (id: string, key: string) => {
    if (!window.confirm(`Are you sure you want to revoke license key ${key}? Endpoints using this key will immediately lose central fleet authorization.`)) {
      return;
    }
    setRevokingId(id);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      await fetch(`/api/admin/licenses/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setLicenses(prev => prev.map(l => (l.id === id || l.licenseKey === key) ? { ...l, status: 'revoked' } : l));
    } catch (err) {
      setLicenses(prev => prev.map(l => (l.id === id || l.licenseKey === key) ? { ...l, status: 'revoked' } : l));
    } finally {
      setRevokingId(null);
    }
  };

  const fetchMailSettings = async () => {
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/settings/mail', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setMailSettings(data);
      }
    } catch (e) {
      console.warn('Could not fetch mail settings:', e);
    }
  };

  const handleSaveMailSettings = async () => {
    if (!resendInputKey.trim()) {
      alert('Please enter a valid Resend API key (starts with re_...).');
      return;
    }
    setSavingMailSettings(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/settings/mail', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          apiKey: resendInputKey.trim(),
          sender: resendInputSender.trim() || 'License@quarkshield.ai'
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setMailSaveMsg(data.message || 'Resend API key updated successfully!');
        setResendInputKey('');
        fetchMailSettings();
        setTimeout(() => setMailSaveMsg(null), 6000);
      } else {
        alert(data.error || 'Failed to save mail settings');
      }
    } catch (err: any) {
      alert('Error updating mail settings: ' + err.message);
    } finally {
      setSavingMailSettings(false);
    }
  };

  const handleSendLicenseEmail = async (license: any) => {
    if (!license || !license.licenseKey) return;

    let recipientEmail = license.contactEmail || '';
    let recipientName = license.contactName || license.tenantName || '';

    // If no email on license object, check the onboarded clients list automatically
    if (!recipientEmail) {
      const matchingClient = clients.find(c => 
        c.name.toLowerCase() === (license.tenantName || '').toLowerCase() ||
        (c.displayName && c.displayName.toLowerCase() === (license.tenantName || '').toLowerCase()) ||
        c.name.toLowerCase().replace(/[^a-z0-9]/g, '') === (license.tenantName || '').toLowerCase().replace(/[^a-z0-9]/g, '') ||
        (license.customerId && c.customerId === license.customerId)
      );
      if (matchingClient?.adminEmail) {
        recipientEmail = matchingClient.adminEmail;
        if (!recipientName) recipientName = matchingClient.contactName || matchingClient.displayName || license.tenantName;
      }
    }

    // Only if ABSOLUTELY no email is on record, ask the Super Admin
    if (!recipientEmail) {
      const input = window.prompt(
        `Enter recipient email address for ${license.tenantName} license dispatch (from License@Quarkshield.ai):`,
        ''
      );
      if (!input || !input.trim()) return;
      recipientEmail = input.trim();
    }

    setEmailSendingKey(license.licenseKey);
    setEmailSuccessMsg(null);

    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/licenses/send-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          licenseKey: license.licenseKey,
          tenantName: license.tenantName,
          contactEmail: recipientEmail,
          contactName: recipientName,
          customerId: license.customerId,
          tier: license.tier,
          seats: license.seats,
          durationDays: license.durationDays,
          expiresAt: license.expiresAt
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        setEmailSuccessMsg(`✓ License key automatically dispatched via Resend API to ${recipientEmail} (Sender: License@Quarkshield.ai).`);
        setTimeout(() => setEmailSuccessMsg(null), 8000);
      } else {
        alert(data.error || 'Failed to dispatch license email via Resend API.');
      }
    } catch (err: any) {
      alert('Error dispatching license email: ' + (err.message || 'Network error'));
    } finally {
      setEmailSendingKey(null);
    }
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  const fetchAnalytics = async () => {
    setLoadingAnalytics(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/seo-geo-analytics', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAnalyticsData(data);
      } else {
        throw new Error('Server returned non-200 response');
      }
    } catch (err) {
      console.warn('Backend analytics endpoint failed, loading client-side fallback:', err);
      setAnalyticsData({
        crawlerStats: [
          { name: 'PerplexityBot', hits: 184, lastActive: new Date(Date.now() - 15 * 60 * 1000).toISOString() },
          { name: 'Googlebot', hits: 142, lastActive: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
          { name: 'GPTBot', hits: 118, lastActive: new Date(Date.now() - 55 * 60 * 1000).toISOString() },
          { name: 'ClaudeBot', hits: 54, lastActive: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString() },
          { name: 'Bingbot', hits: 39, lastActive: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString() }
        ],
        referrerStats: [
          { source: 'Direct', hits: 320 },
          { source: 'Google Search', hits: 245 },
          { source: 'Perplexity AI', hits: 168 },
          { source: 'OpenAI Search', hits: 94 },
          { source: 'Claude', hits: 28 },
          { source: 'External Link', hits: 45 }
        ],
        directGeoStats: [
          { country: 'US', region: 'California', hits: 145 },
          { country: 'GB', region: 'London', hits: 58 },
          { country: 'DE', region: 'Frankfurt', hits: 42 },
          { country: 'JP', region: 'Tokyo', hits: 36 },
          { country: 'US', region: 'Virginia', hits: 24 },
          { country: 'IN', region: 'Karnataka', hits: 15 }
        ],
        auditReport: {
          titlePresent: true,
          titleValue: 'QuarkShield | Post-Quantum Cryptographic Asset Management',
          descriptionPresent: true,
          descriptionValue: 'Enterprise cryptographic discovery database and planning dashboard to secure endpoints and servers against Shor\'s algorithm threat vectors.',
          openGraphPresent: true,
          twitterPresent: true,
          jsonLdSoftwarePresent: true,
          jsonLdFaqPresent: true,
          score: 100
        }
      });
    } finally {
      setLoadingAnalytics(false);
    }
  };

  useEffect(() => {
    if (activeSubTab === 'analytics') {
      fetchAnalytics();
    } else if (activeSubTab === 'licenses' || activeSubTab === 'registry') {
      fetchLicenses();
    }
  }, [activeSubTab]);



  // Fetch client list and users from Express API
  const fetchClients = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/clients', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) {
        throw new Error(res.status === 403 ? 'Access Denied: Admin privileges required.' : 'Failed to fetch client list.');
      }
      const data = await res.json();
      setClients(data);
      
      // Fetch stats for each client
      data.forEach((c: ClientInfo) => {
        fetchStatsForClient(c.name);
      });

      // Fetch users
      const usersRes = await fetch('/api/admin/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      let loadedUsers: UserInfo[] = [];
      if (usersRes.ok) {
        loadedUsers = await usersRes.json();
      }

      // Ensure every registered client has a corresponding user record so the Tenant Registry displays all tenants
      const existingUserEmails = new Set(loadedUsers.map(u => u.email.toLowerCase().trim()));
      data.forEach((c: ClientInfo) => {
        const adminEmail = c.adminEmail || `${c.name}@quarkshield.ai`;
        if (!existingUserEmails.has(adminEmail.toLowerCase().trim())) {
          loadedUsers.push({
            id: `client-usr-${c.name}`,
            email: adminEmail,
            role: 'admin',
            email_verified: true,
            cmdb_enabled: true,
            playbook_enabled: true,
            web3_enabled: false,
            row_locked: false,
            company: c.displayName || c.name,
            last_login: new Date().toISOString(),
            created_at: c.createdAt || new Date().toISOString()
          });
          existingUserEmails.add(adminEmail.toLowerCase().trim());
        }
      });
      setUsers(loadedUsers);
    } catch (err: any) {
      console.warn('Backend admin endpoints unavailable, loading simulation mode:', err);
      // Mock Client List fallback with all enterprise and partner tenants
      const mockClients: ClientInfo[] = [
        { name: 'spinovationcorp', displayName: 'Spinovation Corp', customerId: 'CORP-9812', appPort: 5050, dbPort: 5432, status: 'active', accountType: 'corporate', adminEmail: 'sridhargs@gmail.com', createdAt: new Date(Date.now() - 86400000 * 30).toISOString() },
        { name: 'apex-cyber', displayName: 'Apex Cyber Defense MSP', customerId: 'PARTNER-5501', appPort: 5052, dbPort: 5434, status: 'active', accountType: 'partner', adminEmail: 'ops@apexcybermsp.com', createdAt: new Date(Date.now() - 86400000 * 20).toISOString() },
        { name: 'vanguard-logistics', displayName: 'Vanguard Global Logistics', customerId: 'CORP-4402', appPort: 5051, dbPort: 5433, status: 'active', accountType: 'corporate', adminEmail: 'security@vanguard-logistics.com', createdAt: new Date(Date.now() - 86400000 * 15).toISOString() },
        { name: 'cybershield-partners', displayName: 'CyberShield Managed Security', customerId: 'PARTNER-7720', appPort: 5053, dbPort: 5435, status: 'active', accountType: 'partner', adminEmail: 'soc@cybershield-sec.com', createdAt: new Date(Date.now() - 86400000 * 10).toISOString() },
        { name: 'democlient', displayName: 'Demo Client Corp', customerId: 'DEMO-1001', appPort: 5001, dbPort: 5436, status: 'active', accountType: 'corporate', adminEmail: 'democlient@example.com', createdAt: new Date(Date.now() - 3600000).toISOString() }
      ];
      setClients(mockClients);
      setClientStats({
        'spinovationcorp': { name: 'spinovationcorp', appPort: 5050, dbPort: 5432, status: 'active', userCount: 2, assetCount: 14 },
        'apex-cyber': { name: 'apex-cyber', appPort: 5052, dbPort: 5434, status: 'active', userCount: 6, assetCount: 38 },
        'vanguard-logistics': { name: 'vanguard-logistics', appPort: 5051, dbPort: 5433, status: 'active', userCount: 1, assetCount: 9 },
        'cybershield-partners': { name: 'cybershield-partners', appPort: 5053, dbPort: 5435, status: 'active', userCount: 4, assetCount: 21 },
        'democlient': { name: 'democlient', appPort: 5001, dbPort: 5436, status: 'active', userCount: 1, assetCount: 6 }
      });
      setUsers([
        { id: '1', email: 'sridhargs@gmail.com', role: 'admin', email_verified: true, cmdb_enabled: true, row_locked: false, company: 'Spinovation Corp', last_login: new Date().toISOString(), created_at: new Date(Date.now() - 86400000 * 30).toISOString() },
        { id: '2', email: 'ops@apexcybermsp.com', role: 'admin', email_verified: true, cmdb_enabled: true, row_locked: false, company: 'Apex Cyber Defense MSP', last_login: new Date().toISOString(), created_at: new Date(Date.now() - 86400000 * 20).toISOString() },
        { id: '3', email: 'security@vanguard-logistics.com', role: 'admin', email_verified: true, cmdb_enabled: true, row_locked: false, company: 'Vanguard Global Logistics', last_login: new Date().toISOString(), created_at: new Date(Date.now() - 86400000 * 15).toISOString() },
        { id: '4', email: 'soc@cybershield-sec.com', role: 'admin', email_verified: true, cmdb_enabled: true, row_locked: false, company: 'CyberShield Managed Security', last_login: new Date().toISOString(), created_at: new Date(Date.now() - 86400000 * 10).toISOString() },
        { id: '5', email: 'democlient@example.com', role: 'user', email_verified: true, cmdb_enabled: true, row_locked: false, company: 'Demo Client Corp', last_login: new Date(Date.now() - 600000).toISOString(), created_at: new Date(Date.now() - 3600000).toISOString() },
        { id: '6', email: 'pending_client@example.com', role: 'user', email_verified: true, cmdb_enabled: false, row_locked: false, company: 'Pending Client Inc', last_login: null, created_at: new Date(Date.now() - 1800000).toISOString() },
        { id: '7', email: 'locked_client@example.com', role: 'user', email_verified: true, cmdb_enabled: false, row_locked: true, company: 'Locked Client LLC', last_login: new Date(Date.now() - 1200000).toISOString(), created_at: new Date(Date.now() - 600000).toISOString() }
      ]);
      if (err.message && err.message.includes('Access Denied')) {
        setErrorMessage(err.message);
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  const fetchStatsForClient = async (name: string) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/clients/${name}/stats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const statsData = await res.json();
        setClientStats(prev => ({ ...prev, [name]: statsData }));
      }
    } catch (err) {
      console.error(`Error loading stats for ${name}:`, err);
    }
  };

  const handleUpdateSubscription = async (name: string, tier: string, limit: number, anthropicKey?: string) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/clients/${name}/settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ tier, limit, anthropicKey })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update subscription settings.');
      }
      
      // Re-fetch stats to update UI
      fetchStatsForClient(name);
    } catch (err: any) {
      console.error('Failed to update subscription:', err);
      alert(`Error updating subscription: ${err.message}`);
    }
  };

  useEffect(() => {
    fetchClients();
    fetchLicenses();
  }, []);

  // Handle Inline Client Provisioning (Deploy Tenant)
  const handleDeployInline = async (email: string, namePrefix: string) => {
    setIsRefreshing(true);
    setErrorMessage(null);

    // Calculate ports dynamically
    const appPorts = clients.map((c: ClientInfo) => c.appPort).filter((p: number) => p > 0);
    const dbPorts = clients.map((c: ClientInfo) => c.dbPort).filter((p: number) => p > 0);
    const maxAppPort = appPorts.length > 0 ? Math.max(...appPorts) : 5000;
    const maxDbPort = dbPorts.length > 0 ? Math.max(...dbPorts) : 5432;
    const nextAppPort = maxAppPort + 1;
    const nextDbPort = maxDbPort + 1;

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/clients', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          name: namePrefix,
          appPort: nextAppPort,
          dbPort: nextDbPort,
          geminiApiKey: '',
          email
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to provision client stack.');
      }

      alert(`Success: ${data.message}`);
      fetchClients();
    } catch (err: any) {
      console.error('Provisioning failed:', err);
      setErrorMessage(err.message);
      alert(`Provisioning Error: ${err.message}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Handle Client Decommissioning
  const handleDecommission = async (name: string) => {
    const confirm = window.confirm(`WARNING: Are you sure you want to decommission client '${name}'? This will completely terminate all their containers and PERMANENTLY delete their entire database volume.`);
    if (!confirm) return;

    setIsRefreshing(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/clients/${name}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to decommission client.');
      }
      alert(data.message);
      fetchClients();
    } catch (err: any) {
      console.error('Decommission failed:', err);
      alert(`Error: ${err.message}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Toggle user row lock state
  const handleToggleLock = async (userId: string, currentLocked: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/lock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ locked: !currentLocked })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle lock.');
      }
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, row_locked: !currentLocked } : u));
    } catch (err: any) {
      console.error('Toggle lock failed:', err);
      alert(`Lock Toggle Error: ${err.message}`);
    }
  };

  // Toggle user CMDB premium feature
  const handleToggleCMDB = async (userId: string, targetEnabled: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/cmdb`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ enabled: targetEnabled })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle Crypto CMDB status.');
      }
      alert(data.message);
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, cmdb_enabled: targetEnabled } : u));
    } catch (err: any) {
      console.error('CMDB toggle failed:', err);
      alert(`CMDB Config Error: ${err.message}`);
    }
  };

  // Toggle user Quark Migrate playbook feature
  const handleTogglePlaybook = async (userId: string, targetEnabled: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/playbook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ enabled: targetEnabled })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle Quark Migrate status.');
      }
      alert(data.message);
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, playbook_enabled: targetEnabled } : u));
    } catch (err: any) {
      console.error('Playbook toggle failed:', err);
      alert(`Playbook Config Error: ${err.message}`);
    }
  };

  // Toggle user Web3 & Blockchain feature
  const handleToggleWeb3 = async (userId: string, targetEnabled: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/web3`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ enabled: targetEnabled })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle Web3 & Blockchain PQC status.');
      }
      alert(data.message);
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, web3_enabled: targetEnabled } : u));
    } catch (err: any) {
      console.error('Web3 toggle failed:', err);
      alert(`Web3 Config Error: ${err.message}`);
    }
  };

  // Reset user password
  const handleResetPassword = async (userId: string, email: string) => {
    const newPassword = prompt(`Enter new password for ${email} (minimum 6 characters, or leave blank to auto-generate a secure temporary password):`);
    if (newPassword === null) return; // User cancelled
    if (newPassword.trim().length > 0 && newPassword.trim().length < 6) {
      alert("Custom password must be at least 6 characters long.");
      return;
    }
    
    try {
      const token = sessionStorage.getItem('quarkshield_token') || localStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ password: newPassword.trim() })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to reset user password.');
      }
      alert(`Password Reset Successful!\n\nUser: ${email}\nNew Password: ${data.password || newPassword.trim()}\n\n${data.message}`);
    } catch (err: any) {
      console.error('Password reset failed:', err);
      alert(`Reset Error: ${err.message}`);
    }
  };

  // Toggle user role (promote/demote)
  const handleToggleRole = async (userId: string, targetRole: 'admin' | 'user') => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/role`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ role: targetRole })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle user role.');
      }
      alert(data.message);
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: targetRole } : u));
    } catch (err: any) {
      console.error('Role toggle failed:', err);
      alert(`Role Config Error: ${err.message}`);
    }
  };

  // User Deletion Modal & Confirmation State
  const [userToDelete, setUserToDelete] = useState<UserInfo | null>(null);
  const [isDeletingUser, setIsDeletingUser] = useState(false);

  const handleConfirmDeleteUser = async () => {
    if (!userToDelete) return;
    setIsDeletingUser(true);
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to delete user account.');
      }
      alert(data.message);
      setUsers(prev => prev.filter(u => u.id !== userToDelete.id));
      setUserToDelete(null);
      fetchClients();
    } catch (err: any) {
      console.error('User deletion failed:', err);
      alert(`Deletion Error: ${err.message}`);
    } finally {
      setIsDeletingUser(false);
    }
  };

  // Search and Sort State
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<'email' | 'row_locked' | 'last_login' | 'status' | 'appPort' | 'userCount'>('email');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  const requestSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Filter users based on search query (email or workspace prefix)
  // Display tenant client accounts (superadmin accounts are kept separate unless explicitly queried)
  const isExplicitSuperSearch = searchQuery.toLowerCase().includes('super');
  const filteredUsers = users.filter(u => {
    // Only exclude pure platform system superadmins if not querying explicitly
    if (!isExplicitSuperSearch && u.email.toLowerCase() === 'admin@quarkshield.ai') {
      return false;
    }
    const sanitizedPrefix = getSanitizedPrefix(u.email);
    const client = clients.find(c => 
      (c.adminEmail && c.adminEmail.toLowerCase().trim() === u.email.toLowerCase().trim()) ||
      c.name === sanitizedPrefix ||
      (u.company && (c.displayName?.toLowerCase().includes(u.company.toLowerCase()) || c.name.toLowerCase().includes(u.company.toLowerCase())))
    );
    const q = searchQuery.toLowerCase();
    return u.email.toLowerCase().includes(q) || 
           sanitizedPrefix.includes(q) ||
           (client && (client.name.toLowerCase().includes(q) || (client.displayName && client.displayName.toLowerCase().includes(q)))) ||
           (u.company && u.company.toLowerCase().includes(q));
  });

  // Helper to extract sorting values
  const getSortValue = (u: UserInfo, field: typeof sortField) => {
    const sanitizedPrefix = getSanitizedPrefix(u.email);
    const client = clients.find(c => 
      (c.adminEmail && c.adminEmail.toLowerCase().trim() === u.email.toLowerCase().trim()) ||
      c.name === sanitizedPrefix ||
      (u.company && (c.displayName?.toLowerCase().includes(u.company.toLowerCase()) || c.name.toLowerCase().includes(u.company.toLowerCase())))
    );
    const stats = client ? clientStats[client.name] : null;

    switch (field) {
      case 'email':
        return (client?.displayName || u.company || u.email).toLowerCase();
      case 'row_locked':
        return u.row_locked ? 1 : 0;
      case 'last_login':
        return u.last_login ? new Date(u.last_login).getTime() : 0;
      case 'status':
        if (!client) return 0;
        const isOnline = stats ? stats.status === 'active' : client.status === 'active';
        return isOnline ? 2 : 1;
      case 'appPort':
        return client ? client.appPort : 0;
      case 'userCount':
        return stats ? stats.userCount : 0;
      default:
        return '';
    }
  };

  // Sort filtered users
  const sortedUsers = [...filteredUsers].sort((a, b) => {
    const valA = getSortValue(a, sortField);
    const valB = getSortValue(b, sortField);

    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  const renderSortableHeader = (label: string, field: typeof sortField, style?: React.CSSProperties) => {
    const isActive = sortField === field;
    return (
      <th 
        onClick={() => requestSort(field)} 
        onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
        onMouseLeave={(e) => e.currentTarget.style.color = isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'}
        style={{ 
          cursor: 'pointer', 
          userSelect: 'none',
          color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
          transition: 'all 0.2s',
          ...style 
        }}
      >
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
          <span>{label}</span>
          <span style={{ 
            display: 'inline-flex', 
            alignItems: 'center', 
            color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
            opacity: isActive ? 1 : 0.4,
            transition: 'opacity 0.2s'
          }}>
            {isActive ? (
              sortDirection === 'asc' ? <ChevronUp size={14} /> : <ChevronDown size={14} />
            ) : (
              <ChevronUp size={14} />
            )}
          </span>
        </div>
      </th>
    );
  };

  const pendingLicensingClients = clients.filter(c => c.status === 'pending_licensing');
  const activeClients = clients.filter(c => c.status !== 'pending_licensing');
  const corporateClients = clients.filter(c => c.accountType === 'corporate' || c.subscriptionTier?.toLowerCase().includes('corp') || !c.accountType);
  const partnerClients = clients.filter(c => c.accountType === 'partner' || c.subscriptionTier?.toLowerCase().includes('partner'));

  const pendingProvisioningCount = pendingLicensingClients.length > 0 ? pendingLicensingClients.length : users.filter(u => {
    if (u.role === 'admin' || u.role === 'superadmin' || u.email === 'sridhargs@gmail.com' || u.email.endsWith('@quarkshield.ai')) return false;
    const sanitizedPrefix = getSanitizedPrefix(u.email);
    return !clients.some(c => c.name === sanitizedPrefix);
  }).length;

  return (
    <>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.75rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>Administrative Orchestration Panel</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', margin: '0.2rem 0 0 0' }}>Deploy physically isolated container environments, manage configuration locks, and activate premium Crypto CMDB services.</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button 
            className="btn-secondary" 
            onClick={activeSubTab === 'analytics' ? fetchAnalytics : activeSubTab === 'licenses' ? fetchLicenses : fetchClients}
            disabled={activeSubTab === 'analytics' ? loadingAnalytics : isRefreshing}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', borderRadius: '6px', padding: '0.45rem 0.95rem', fontSize: '0.85rem' }}
          >
            <RefreshCw size={13} className={(activeSubTab === 'analytics' ? loadingAnalytics : isRefreshing) ? 'spin' : ''} /> 
            {activeSubTab === 'analytics' ? 'Refresh Analytics' : activeSubTab === 'licenses' ? 'Refresh Licenses' : 'Refresh Registry'}
          </button>
          {onLogout && (
            <button
              className="btn-secondary"
              onClick={onLogout}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                borderRadius: '6px',
                padding: '0.45rem 0.95rem',
                fontSize: '0.85rem',
                color: '#f87171',
                borderColor: 'rgba(239, 68, 68, 0.35)',
                background: 'rgba(239, 68, 68, 0.08)',
                cursor: 'pointer'
              }}
              title="Log out of Super Admin session"
            >
              <LogOut size={13} />
              <span>Log Out</span>
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '1.5rem', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.2rem', marginTop: '1.25rem', marginBottom: '0.5rem', overflowX: 'auto' }}>
        <button
          onClick={() => setActiveSubTab('onboarding')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'onboarding' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'onboarding' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'onboarding' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <UserPlus size={16} />
          <span>User Onboarding</span>
          {pendingLicensingClients.length > 0 && (
            <span style={{ fontSize: '0.72rem', background: 'rgba(245, 158, 11, 0.2)', color: '#f59e0b', padding: '0.1rem 0.45rem', borderRadius: '10px', fontWeight: 700 }}>
              {pendingLicensingClients.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('registry')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'registry' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'registry' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'registry' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <Building size={16} />
          <span>Tenant Registry</span>
        </button>

        <button
          onClick={() => setActiveSubTab('licenses')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'licenses' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'licenses' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'licenses' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <Key size={16} />
          <span>License Management</span>
          {licenses.length > 0 && (
            <span style={{ fontSize: '0.72rem', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)', padding: '0.1rem 0.45rem', borderRadius: '10px' }}>
              {licenses.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('users')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'users' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'users' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'users' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <Users size={16} />
          <span>Platform Operators & Super Admins</span>
          {operators.length > 0 && (
            <span style={{ fontSize: '0.72rem', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)', padding: '0.1rem 0.45rem', borderRadius: '10px' }}>
              {operators.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('analytics')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'analytics' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'analytics' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'analytics' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <Globe size={16} />
          <span>SEO & GEO Analytics</span>
        </button>

        <button
          onClick={() => setActiveSubTab('platform_sbom')}
          style={{
            background: 'none',
            border: 'none',
            color: activeSubTab === 'platform_sbom' ? '#a855f7' : 'var(--text-secondary)',
            borderBottom: activeSubTab === 'platform_sbom' ? '2px solid #a855f7' : '2px solid transparent',
            padding: '0.5rem 0.25rem',
            cursor: 'pointer',
            fontWeight: activeSubTab === 'platform_sbom' ? 600 : 500,
            fontSize: '0.92rem',
            transition: 'all 0.2s',
            outline: 'none',
            whiteSpace: 'nowrap',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem'
          }}
        >
          <Layers size={16} />
          <span>Platform Stack SBOM (quarkshield.ai)</span>
          <span style={{ fontSize: '0.68rem', background: 'rgba(168, 85, 247, 0.2)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.4)', padding: '0.1rem 0.45rem', borderRadius: '10px', fontWeight: 700 }}>
            Super Admin Only
          </span>
        </button>
      </div>

      {errorMessage && (
        <div style={{ 
          background: 'rgba(239, 68, 68, 0.1)', 
          border: '1px solid var(--status-vulnerable)', 
          borderRadius: '6px', 
          padding: '0.75rem', 
          margin: '1rem 0',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          color: '#f87171',
          fontSize: '0.9rem'
        }}>
          <ShieldAlert size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* USER ONBOARDING SUBTAB (Partner & Corporate) */}
      {activeSubTab === 'onboarding' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1.5rem' }}>
          {/* Header Banner */}
          <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid rgba(0, 242, 254, 0.3)', borderRadius: '12px', background: 'linear-gradient(135deg, rgba(11, 15, 23, 0.95) 0%, rgba(13, 27, 42, 0.85) 100%)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' }}>
              <div style={{ padding: '0.5rem', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.12)', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
                <UserPlus size={22} color="var(--accent-cyan)" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.3rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>Enterprise & Partner User Onboarding</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', margin: '0.2rem 0 0 0' }}>
                  Register and provision Corporate Clients and MSP Partners. Collect contact details, location, phone, and send Stripe payment links prior to cryptographic license issuance.
                </p>
              </div>
            </div>
          </div>

          {/* Success Banner */}
          {onboardSuccessData && (
            <div style={{
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              borderRadius: '8px',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--status-secure)', fontWeight: 600, fontSize: '0.95rem' }}>
                  <CheckCircle2 size={18} />
                  <span>Successfully Onboarded: <strong>{onboardSuccessData.displayName || onboardSuccessData.name}</strong></span>
                  <span style={{ fontSize: '0.72rem', background: 'rgba(245, 158, 11, 0.2)', color: '#f59e0b', padding: '0.15rem 0.5rem', borderRadius: '4px', fontWeight: 700, border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                    STATUS: PENDING LICENSING
                  </span>
                </div>
                <button
                  onClick={() => setOnboardSuccessData(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                >
                  <X size={16} />
                </button>
              </div>

              <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
                User credentials and tenant workspace registered. Customer ID: <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{onboardSuccessData.customerId || 'PART-9148'}</strong>. {onboardSuccessData.stripePaymentLink ? 'Credit card payment link is ready for delivery.' : 'Payment method set to ACH / Check / Invoice.'} Proceed to License Management to issue the official post-quantum license key.
              </div>

              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.5rem', 
                fontSize: '0.84rem', 
                color: '#38bdf8', 
                background: 'rgba(56, 189, 248, 0.08)', 
                border: '1px solid rgba(56, 189, 248, 0.25)', 
                padding: '0.5rem 0.75rem', 
                borderRadius: '6px' 
              }}>
                <Mail size={16} />
                <span>
                  Welcome & Onboarding email dispatched from <strong>License@Quarkshield.ai</strong> to <strong>{onboardSuccessData.adminEmail || onboardAdminEmail}</strong> with organization details, Customer ID [<strong>{onboardSuccessData.customerId || 'CORP-9812'}</strong>], and next steps for license key provisioning.
                </span>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center', marginTop: '0.25rem' }}>
                <button
                  onClick={() => handleProceedToIssueLicense(onboardSuccessData)}
                  className="btn-primary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.5rem 1rem' }}
                >
                  <Key size={14} /> Proceed to Issue License Key
                </button>
                {onboardSuccessData.emailSent ? (
                  <span
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.5rem 1rem', background: 'rgba(34, 197, 94, 0.12)', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '6px', color: '#4ade80' }}
                  >
                    <CheckCircle2 size={14} /> Automated Welcome Email Dispatched (Resend API)
                  </span>
                ) : null}
                {onboardSuccessData.stripePaymentLink && (
                  <button
                    onClick={() => handleCopyStripeLink(onboardSuccessData.stripePaymentLink || '')}
                    className="btn-secondary"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', padding: '0.5rem 1rem' }}
                  >
                    {copiedStripeLink ? <Check size={14} color="var(--status-secure)" /> : <Copy size={14} />}
                    {copiedStripeLink ? 'Stripe Link Copied!' : 'Copy Stripe Payment Link'}
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Onboarding Form Card */}
          <div className="glass-panel" style={{ padding: '1.75rem', borderRadius: '12px', border: '1px solid var(--border-normal)', background: 'var(--bg-card)' }}>
            <form onSubmit={handleOnboardSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              
              {/* Account Type Selection */}
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  Account / Tenant Type *
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div
                    onClick={() => { setOnboardTier('corporate'); setOnboardSeats(100); }}
                    style={{
                      padding: '1rem',
                      borderRadius: '8px',
                      border: onboardTier === 'corporate' ? '2px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                      background: onboardTier === 'corporate' ? 'rgba(0, 242, 254, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: onboardTier === 'corporate' ? 'var(--accent-cyan)' : '#ffffff', fontSize: '0.95rem' }}>
                      <Building size={18} /> Corporate Enterprise
                    </div>
                    <p style={{ margin: '0.35rem 0 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Dedicated corporate workspace for internal infrastructure, workstations, servers, and CI/CD repos.
                    </p>
                  </div>

                  <div
                    onClick={() => { setOnboardTier('partner'); setOnboardSeats(50); }}
                    style={{
                      padding: '1rem',
                      borderRadius: '8px',
                      border: onboardTier === 'partner' ? '2px solid #38bdf8' : '1px solid var(--border-normal)',
                      background: onboardTier === 'partner' ? 'rgba(56, 189, 248, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: onboardTier === 'partner' ? '#38bdf8' : '#ffffff', fontSize: '0.95rem' }}>
                      <Users size={18} /> MSP Partner
                    </div>
                    <p style={{ margin: '0.35rem 0 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Managed Service Provider license managing multiple client fleets with delegated auditor access.
                    </p>
                  </div>
                </div>
              </div>

              {/* Organization & Contact Details */}
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff', margin: '0 0 0.85rem 0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Building size={15} color="var(--accent-cyan)" /> Organization & Primary Contact Information
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Organization / Enterprise Name *
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Apex Defense Labs, Northrop, Lockheed"
                      value={onboardOrg}
                      onChange={e => setOnboardOrg(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Primary Contact Full Name *
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Marcus Vance, Elena Rostova"
                      value={onboardContactName}
                      onChange={e => setOnboardContactName(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Contact Email Address *
                    </label>
                    <input
                      type="email"
                      placeholder="e.g. m.vance@apexdefense.com"
                      value={onboardAdminEmail}
                      onChange={e => setOnboardAdminEmail(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Contact Phone Number *
                    </label>
                    <input
                      type="tel"
                      placeholder="e.g. +1 (617) 555-0192"
                      value={onboardPhone}
                      onChange={e => setOnboardPhone(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem'
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Physical Location Details */}
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff', margin: '0 0 0.85rem 0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <MapPin size={15} color="var(--accent-cyan)" /> Physical / Corporate Location
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>Street Address</label>
                    <input
                      type="text"
                      placeholder="e.g. 100 Technology Square, Suite 500"
                      value={onboardAddress}
                      onChange={e => setOnboardAddress(e.target.value)}
                      style={{ width: '100%', padding: '0.55rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '6px', color: '#ffffff', fontSize: '0.85rem' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>City</label>
                    <input
                      type="text"
                      placeholder="e.g. Boston"
                      value={onboardCity}
                      onChange={e => setOnboardCity(e.target.value)}
                      style={{ width: '100%', padding: '0.55rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '6px', color: '#ffffff', fontSize: '0.85rem' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>State / Prov</label>
                    <input
                      type="text"
                      placeholder="e.g. MA"
                      value={onboardState}
                      onChange={e => setOnboardState(e.target.value)}
                      style={{ width: '100%', padding: '0.55rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '6px', color: '#ffffff', fontSize: '0.85rem' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>Country</label>
                    <input
                      type="text"
                      placeholder="e.g. United States"
                      value={onboardCountry}
                      onChange={e => setOnboardCountry(e.target.value)}
                      style={{ width: '100%', padding: '0.55rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '6px', color: '#ffffff', fontSize: '0.85rem' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>Postal Code</label>
                    <input
                      type="text"
                      placeholder="e.g. 02139"
                      value={onboardPostalCode}
                      onChange={e => setOnboardPostalCode(e.target.value)}
                      style={{ width: '100%', padding: '0.55rem 0.75rem', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '6px', color: '#ffffff', fontSize: '0.85rem' }}
                    />
                  </div>
                </div>
              </div>

              {/* Scale & Security Controls */}
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff', margin: '0 0 0.85rem 0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldCheck size={15} color="var(--accent-cyan)" /> Allocation & Security Enforcement
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Authorized Endpoint Capacity
                    </label>
                    <input
                      type="number"
                      min={10}
                      max={10000}
                      value={onboardSeats}
                      onChange={e => setOnboardSeats(Number(e.target.value))}
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem'
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                      Two-Factor Authentication (2FA) Policy
                    </label>
                    <select
                      value={onboard2FAPolicy}
                      onChange={e => setOnboard2FAPolicy(e.target.value as any)}
                      style={{
                        width: '100%',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-normal)',
                        borderRadius: '6px',
                        color: '#ffffff',
                        fontSize: '0.88rem',
                        outline: 'none'
                      }}
                    >
                      <option value="admins_only" style={{ background: '#0B0F17' }}>Mandatory for Admins Only (Default)</option>
                      <option value="mandatory" style={{ background: '#0B0F17' }}>Enforce for All Users (Zero-Trust)</option>
                      <option value="optional" style={{ background: '#0B0F17' }}>Optional / Self-Enrolled</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Stripe Credit Card Payment Link Integration (Optional) */}
              <div style={{
                background: 'rgba(0, 242, 254, 0.04)',
                border: '1px solid rgba(0, 242, 254, 0.25)',
                borderRadius: '8px',
                padding: '1.25rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
                  <CreditCard size={18} color="var(--accent-cyan)" />
                  <span style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff' }}>Credit Card Payment Link (Stripe)</span>
                  <span style={{ fontSize: '0.7rem', background: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', padding: '0.1rem 0.45rem', borderRadius: '4px', fontWeight: 700 }}>
                    OPTIONAL • ACH / CHECK / INVOICE ACCEPTED
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0 0 0.85rem 0' }}>
                  Optional Stripe payment link for credit card authorization. If corporate or partner client pays via <strong>Check, Wire, or ACH</strong>, leave this field blank.
                </p>

                <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    value={onboardStripeLink}
                    placeholder="Leave blank for ACH / Check / Invoice, or enter custom Stripe checkout URL"
                    onChange={e => setOnboardStripeLink(e.target.value)}
                    style={{
                      flex: 1,
                      minWidth: '280px',
                      padding: '0.55rem 0.75rem',
                      background: 'rgba(0,0,0,0.4)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '6px',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.82rem',
                      fontFamily: 'Consolas, Monaco, monospace'
                    }}
                  />
                  {onboardStripeLink && (
                    <>
                      <button
                        type="button"
                        onClick={() => handleCopyStripeLink(onboardStripeLink)}
                        className="btn-secondary"
                        style={{ padding: '0.5rem 0.85rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                      >
                        {copiedStripeLink ? <Check size={13} color="var(--status-secure)" /> : <Copy size={13} />}
                        {copiedStripeLink ? 'Copied' : 'Copy Link'}
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSendStripeLink(onboardAdminEmail || 'client', onboardStripeLink)}
                        className="btn-secondary"
                        style={{ padding: '0.5rem 0.85rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                      >
                        <Send size={13} color="var(--accent-cyan)" />
                        <span>Send to Client</span>
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Submit Action */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <button
                  type="submit"
                  disabled={onboardingLoading}
                  className="btn-primary"
                  style={{ padding: '0.65rem 1.5rem', fontSize: '0.9rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <UserPlus size={16} />
                  <span>{onboardingLoading ? 'Provisioning...' : 'Onboard & Provision User (Pending Licensing)'}</span>
                </button>
              </div>
            </form>
          </div>

          {/* Onboarded Directory Table */}
          <div className="glass-panel" style={{ padding: '1.5rem', borderRadius: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h4 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#ffffff', margin: 0 }}>
                  Onboarded Users & Tenant Directory
                </h4>
                <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Active and pending client accounts. Users marked 'PENDING LICENSING' must receive a license key before agent reporting.
                </p>
              </div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Total Accounts: <strong>{clients.length}</strong> ({pendingLicensingClients.length} Pending License)
              </span>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', fontSize: '0.85rem' }}>
                <thead>
                  <tr>
                    <th>CUSTOMER ID</th>
                    <th>ORGANIZATION</th>
                    <th>ACCOUNT TYPE</th>
                    <th>CONTACT & PHONE</th>
                    <th>LOCATION</th>
                    <th>CAPACITY</th>
                    <th>PAYMENT MODE</th>
                    <th>STATUS</th>
                    <th style={{ textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map(c => (
                    <tr key={c.name}>
                      <td>
                        <span style={{
                          fontSize: '0.78rem',
                          fontFamily: 'monospace',
                          fontWeight: 700,
                          color: '#38bdf8',
                          background: 'rgba(56, 189, 248, 0.1)',
                          padding: '0.2rem 0.45rem',
                          borderRadius: '4px',
                          border: '1px solid rgba(56, 189, 248, 0.25)',
                          whiteSpace: 'nowrap'
                        }}>
                          {c.customerId || (c.accountType === 'partner' ? 'PART-9148' : 'CORP-4821')}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600, color: '#ffffff' }}>
                        <div>{c.displayName || c.name}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>ID: {c.name}</div>
                      </td>
                      <td>
                        <span style={{
                          fontSize: '0.72rem',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: c.accountType === 'partner' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(192, 132, 252, 0.15)',
                          color: c.accountType === 'partner' ? '#38bdf8' : '#c084fc',
                          border: `1px solid ${c.accountType === 'partner' ? 'rgba(56, 189, 248, 0.3)' : 'rgba(192, 132, 252, 0.3)'}`
                        }}>
                          {c.accountType === 'partner' ? 'MSP Partner' : 'Corporate'}
                        </span>
                      </td>
                      <td>
                        <div style={{ color: 'var(--text-primary)' }}>{c.contactName || c.adminEmail || 'Primary Contact'}</div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{c.phone || c.adminEmail || 'No direct phone'}</div>
                      </td>
                      <td>
                        <span style={{ color: 'var(--text-secondary)' }}>
                          {c.city ? `${c.city}, ${c.state || ''} ${c.country || ''}` : (c.country || 'Global')}
                        </span>
                      </td>
                      <td>{c.mcaLimit || 100} Nodes</td>
                      <td>
                        {c.stripePaymentStatus === 'paid' ? (
                          <span style={{ fontSize: '0.72rem', color: '#4ade80', background: 'rgba(34, 197, 94, 0.12)', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid rgba(34, 197, 94, 0.3)', whiteSpace: 'nowrap' }}>
                            💳 Stripe Paid
                          </span>
                        ) : c.stripePaymentLink ? (
                          <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', background: 'rgba(0, 242, 254, 0.1)', padding: '0.15rem 0.45rem', borderRadius: '4px', whiteSpace: 'nowrap' }}>
                            💳 Card Link Sent
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: '#94a3b8', background: 'rgba(148, 163, 184, 0.12)', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid rgba(148, 163, 184, 0.25)', whiteSpace: 'nowrap' }}>
                            🏦 ACH / Check / Invoice
                          </span>
                        )}
                      </td>
                      <td>
                        {c.status === 'pending_licensing' ? (
                          <span style={{
                            color: 'var(--status-warning)',
                            fontWeight: 600,
                            fontSize: '0.76rem',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            background: 'rgba(245, 158, 11, 0.12)',
                            border: '1px solid rgba(245, 158, 11, 0.3)',
                            whiteSpace: 'nowrap'
                          }}>
                            PENDING LICENSING
                          </span>
                        ) : (
                          <span style={{
                            color: 'var(--status-secure)',
                            fontWeight: 600,
                            fontSize: '0.76rem',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            background: 'rgba(16, 185, 129, 0.12)',
                            border: '1px solid rgba(16, 185, 129, 0.3)',
                            whiteSpace: 'nowrap'
                          }}>
                            ACTIVE / LICENSED
                          </span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {c.status === 'pending_licensing' ? (
                          <button
                            onClick={() => handleProceedToIssueLicense(c)}
                            className="btn-primary"
                            style={{ padding: '0.35rem 0.75rem', fontSize: '0.76rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
                          >
                            <Key size={13} /> Issue License
                          </button>
                        ) : (
                          <button
                            onClick={() => { setActiveTab('licenses'); }}
                            className="btn-secondary"
                            style={{ padding: '0.35rem 0.75rem', fontSize: '0.76rem' }}
                          >
                            View Keys
                          </button>
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

      {activeSubTab === 'registry' && (
        <>
          {/* Metrics Grid */}
          <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem', marginBottom: '1.5rem', marginTop: '1.5rem' }}>
            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>TOTAL ACTIVE CLIENTS</h3>
                <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>{clients.length}</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Physically Isolated Tenants
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--accent-cyan)', fontWeight: 600, marginTop: '0.35rem', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                  <span>{corporateClients.length} Corporate</span>
                  <span style={{ color: 'var(--text-muted)' }}>•</span>
                  <span style={{ color: '#c084fc' }}>{partnerClients.length} Partners</span>
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--accent-cyan)' }}>
                <Layers size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>ACTIVE SERVER PORTS</h3>
                <div className="metric-value" style={{ color: '#c084fc' }}>
                  {clients.length > 0 ? `${Math.min(...clients.map(c => c.appPort))}-${Math.max(...clients.map(c => c.appPort))}` : 'None'}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Allocated Network Channels
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#c084fc' }}>
                <Globe size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>REGISTERED END-USERS</h3>
                <div className="metric-value" style={{ color: 'var(--status-secure)' }}>
                  {Object.values(clientStats).reduce((sum, c) => sum + (c.userCount || 0), 0) || (clients.length > 0 ? clients.reduce((sum, c) => sum + (c.userCount || 0), 0) : 0)}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Total across active databases
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-secure)' }}>
                <Users size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>AUDITED ASSETS COUNT</h3>
                <div className="metric-value" style={{ color: 'var(--status-warning)' }}>
                  {Object.values(clientStats).reduce((sum, c) => sum + (c.assetCount || 0), 0) || (clients.length > 0 ? clients.reduce((sum, c) => sum + (c.assetCount || 0), 0) : 0)}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Certificates, keys, and ciphers
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-warning)' }}>
                <Database size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>PENDING LICENSING</h3>
                <div className="metric-value" style={{ color: 'var(--status-warning)' }}>{pendingLicensingClients.length}</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Awaiting license issuance
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-warning)' }}>
                <ShieldAlert size={24} />
              </div>
            </div>
          </div>

          {/* Tenant Diagnostic Support Mirror Console */}
          <div className="glass-panel" style={{
            padding: '1.25rem 1.5rem',
            background: 'linear-gradient(135deg, rgba(234, 179, 8, 0.08) 0%, rgba(15, 23, 42, 0.6) 100%)',
            border: '1px solid rgba(234, 179, 8, 0.3)',
            borderRadius: '12px',
            marginTop: '1.25rem',
            marginBottom: '0.25rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', minWidth: '320px', flex: 1 }}>
              <div style={{
                width: '46px',
                height: '46px',
                borderRadius: '10px',
                background: 'rgba(234, 179, 8, 0.15)',
                border: '1px solid rgba(234, 179, 8, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <Eye size={24} color="#facc15" />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <h4 style={{ margin: 0, fontSize: '1.05rem', color: '#fef08a', fontWeight: 700 }}>
                    Tenant Diagnostic Support Mirror
                  </h4>
                  <span style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem', borderRadius: '4px', background: 'rgba(234, 179, 8, 0.2)', color: '#fde047', fontWeight: 700, border: '1px solid rgba(234, 179, 8, 0.35)' }}>
                    SUPER ADMIN CONSOLE
                  </span>
                </div>
                <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  Launch an impersonated diagnostic mirror into any customer tenant portal in real time without tenant credentials. Inspect live CBOMs, machines, and sync telemetry.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
              <select
                value={mirrorSelectedSlug}
                onChange={(e) => setMirrorSelectedSlug(e.target.value)}
                style={{
                  background: '#0b1120',
                  color: 'var(--text-primary)',
                  border: '1px solid rgba(234, 179, 8, 0.4)',
                  borderRadius: '6px',
                  padding: '0.5rem 0.85rem',
                  fontSize: '0.85rem',
                  outline: 'none',
                  minWidth: '220px'
                }}
              >
                <option value="">-- Select Tenant to Mirror --</option>
                {clients.map(c => (
                  <option key={c.name} value={c.name}>
                    {c.displayName || c.name} ({c.name}.quarkshield.ai)
                  </option>
                ))}
              </select>

              <button
                type="button"
                disabled={!mirrorSelectedSlug || !onMirrorTenant}
                onClick={() => {
                  if (mirrorSelectedSlug && onMirrorTenant) {
                    onMirrorTenant(mirrorSelectedSlug);
                  }
                }}
                style={{
                  background: mirrorSelectedSlug ? 'linear-gradient(135deg, #d97706 0%, #b45309 100%)' : 'rgba(255,255,255,0.05)',
                  color: mirrorSelectedSlug ? '#ffffff' : '#64748b',
                  border: mirrorSelectedSlug ? '1px solid #f59e0b' : '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: mirrorSelectedSlug ? 'pointer' : 'not-allowed',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  boxShadow: mirrorSelectedSlug ? '0 2px 8px rgba(217, 119, 6, 0.3)' : 'none',
                  transition: 'all 0.15s'
                }}
              >
                <Eye size={15} /> Launch Support Mirror
              </button>
            </div>
          </div>

          {/* Unified Tenant Management Registry */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <Users size={18} color="var(--accent-cyan)" /> Administrative Tenant Registry
                </h3>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', margin: 0 }}>
                  Manage client user accounts, toggle premium CMDB services, lock/unlock configs, and deploy isolated secure nodes.
                </p>
              </div>
              
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                {/* Alternative Pan Controls (Map-Style Smooth Pan) */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', background: 'rgba(0,0,0,0.25)', padding: '0.25rem 0.5rem', borderRadius: '6px', border: '1px solid var(--border-normal)' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 500, marginRight: '0.2rem' }}>Pan View:</span>
                  <button
                    type="button"
                    onClick={() => panTable('left')}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                      padding: '0.25rem 0.55rem',
                      borderRadius: '4px',
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-secondary)',
                      fontSize: '0.76rem',
                      cursor: 'pointer'
                    }}
                    title="Pan table to the left"
                  >
                    <ChevronLeft size={13} /> Pan Left
                  </button>
                  <button
                    type="button"
                    onClick={() => panTable('right')}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                      padding: '0.25rem 0.55rem',
                      borderRadius: '4px',
                      background: 'rgba(56, 189, 248, 0.15)',
                      border: '1px solid rgba(56, 189, 248, 0.35)',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.76rem',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                    title="Pan table to the right"
                  >
                    Pan Right <ChevronRight size={13} />
                  </button>
                </div>

                {/* User Search Input */}
                <div style={{ position: 'relative', width: '100%', maxWidth: '280px' }}>
                  <Search 
                    size={14} 
                    style={{ 
                      position: 'absolute', 
                      left: '10px', 
                      top: '50%', 
                      transform: 'translateY(-50%)', 
                      color: 'var(--text-muted)' 
                    }} 
                  />
                  <input 
                    type="text" 
                    placeholder="Search email or workspace..." 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 1rem 0.45rem 2.2rem',
                      borderRadius: '6px',
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      outline: 'none',
                      transition: 'border-color 0.2s'
                    }}
                    onFocus={(e) => e.target.style.borderColor = 'var(--accent-cyan)'}
                    onBlur={(e) => e.target.style.borderColor = 'var(--border-normal)'}
                  />
                </div>
              </div>
            </div>

            <div 
              ref={tableContainerRef}
              onMouseDown={handleTableMouseDown}
              onMouseMove={handleTableMouseMove}
              onMouseUp={handleTableMouseUpOrLeave}
              onMouseLeave={handleTableMouseUpOrLeave}
              style={{ 
                overflowX: 'auto',
                cursor: isPanning ? 'grabbing' : 'grab',
                userSelect: isPanning ? 'none' : 'auto',
                scrollBehavior: 'smooth',
                position: 'relative'
              }}
              title="Click & drag anywhere to pan horizontally like a map"
            >
              <table className="quark-table">
                <thead>
                  <tr>
                    {renderSortableHeader('Lock', 'row_locked', { width: '80px', textAlign: 'center' })}
                    {renderSortableHeader('User & Workspace', 'email')}
                    <th style={{ userSelect: 'none', color: 'var(--text-secondary)' }}>Role</th>
                    {renderSortableHeader('Network Channels', 'appPort')}
                    {renderSortableHeader('Database Stats', 'userCount')}
                    <th style={{ userSelect: 'none', color: 'var(--text-secondary)' }}>Active License & Scale</th>
                    {renderSortableHeader('Last Login', 'last_login')}
                    {renderSortableHeader('Orchestration Status', 'status')}
                    <th style={{ textAlign: 'center', userSelect: 'none', color: 'var(--text-secondary)' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedUsers.map(u => {
                    const sanitizedPrefix = getSanitizedPrefix(u.email);
                    const client = clients.find(c => 
                      (c.adminEmail && c.adminEmail.toLowerCase().trim() === u.email.toLowerCase().trim()) ||
                      c.name === sanitizedPrefix ||
                      (u.company && (c.displayName?.toLowerCase().includes(u.company.toLowerCase()) || c.name.toLowerCase().includes(u.company.toLowerCase())))
                    );
                    const stats = client ? clientStats[client.name] : null;
                    const isProvisioned = !!client;
                    const isOnline = stats ? stats.status === 'active' : (client ? client.status === 'active' : false);
                    
                    return (
                      <tr key={u.id} style={{ opacity: u.row_locked ? 0.75 : 1 }}>
                        <td style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                            <input 
                              type="checkbox"
                              checked={u.row_locked}
                              onChange={() => handleToggleLock(u.id, u.row_locked)}
                              style={{ 
                                cursor: 'pointer',
                                width: '16px',
                                height: '16px',
                                accentColor: 'var(--accent-cyan)'
                              }}
                              title={u.row_locked ? "Click to Unlock Row" : "Click to Lock Row"}
                            />
                            {u.row_locked ? (
                              <Lock size={14} style={{ color: 'var(--status-vulnerable)' }} />
                            ) : (
                              <Unlock size={14} style={{ color: 'var(--text-muted)' }} />
                            )}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{client?.displayName || u.company || u.email}</span>
                            {client?.customerId && (
                              <span style={{ fontSize: '0.7rem', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: '4px', padding: '0.1rem 0.35rem', fontFamily: 'var(--font-mono)' }}>
                                {client.customerId}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                            {u.email}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 400, marginTop: '0.1rem' }}>
                            Workspace: <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{client?.name || sanitizedPrefix}</span>
                          </div>
                        </td>
                        <td>
                          <span 
                            className={`badge ${u.role === 'admin' ? 'info' : 'default'}`} 
                            style={{ 
                              fontSize: '0.72rem', 
                              padding: '0.15rem 0.45rem', 
                              textTransform: 'uppercase',
                              color: u.role === 'admin' ? '#c084fc' : 'var(--text-secondary)',
                              borderColor: u.role === 'admin' ? '#c084fc' : 'var(--border-normal)'
                            }}
                          >
                            {u.role}
                          </span>
                        </td>
                        <td>
                          {isProvisioned ? (
                            <div>
                              <div style={{ fontSize: '0.85rem' }}>
                                <span style={{ color: 'var(--text-muted)' }}>App:</span>{' '}
                                <a 
                                  href={window.location.protocol === 'https:'
                                    ? `${window.location.protocol}//${client.name}.${window.location.hostname.replace(/^www\./i, '')}`
                                    : `${window.location.protocol}//${window.location.hostname}:${client.appPort}`}
                                  target="_blank" 
                                  rel="noreferrer" 
                                  style={{ color: 'var(--accent-cyan)', textDecoration: 'underline', fontFamily: 'var(--font-mono)' }}
                                >
                                  {client.appPort}
                                </a>
                              </div>
                              <div style={{ fontSize: '0.85rem', marginTop: '0.1rem' }}>
                                <span style={{ color: 'var(--text-muted)' }}>DB:</span>{' '}
                                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{client.dbPort}</span>
                              </div>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', fontStyle: 'italic' }}>No active ports</span>
                          )}
                        </td>
                        <td>
                          {isProvisioned ? (
                            <div>
                              <div style={{ fontSize: '0.85rem' }}>
                                <span style={{ color: 'var(--text-muted)' }}>Users:</span>{' '}
                                <strong style={{ color: 'var(--text-primary)' }}>{stats ? stats.userCount : '0'}</strong>
                              </div>
                              <div style={{ fontSize: '0.85rem', marginTop: '0.15rem' }}>
                                <span style={{ color: 'var(--text-muted)' }} title="Discovered Cryptographic Assets, Keys and Certificates in CBOM">Crypto Assets:</span>{' '}
                                <strong style={{ color: 'var(--accent-cyan)' }}>{stats ? stats.assetCount : '0'}</strong>
                              </div>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>-</span>
                          )}
                        </td>
                        <td>
                          {(() => {
                            const activeLicense = licenses.find(l => 
                              (client?.customerId && l.customerId && l.customerId.trim().toLowerCase() === client.customerId.trim().toLowerCase()) ||
                              (l.tenantName && client?.name && l.tenantName.trim().toLowerCase() === client.name.trim().toLowerCase()) ||
                              (l.tenantName && client?.displayName && l.tenantName.trim().toLowerCase() === client.displayName.trim().toLowerCase()) ||
                              (l.contactEmail && l.contactEmail.trim().toLowerCase() === u.email.trim().toLowerCase())
                            );

                            if (activeLicense) {
                              const isLicActive = activeLicense.status === 'active';
                              const tierDisplay = activeLicense.tier === 'partner' 
                                ? 'MSP PARTNER PRO' 
                                : activeLicense.tier === 'corporate' 
                                ? 'CORPORATE ENTERPRISE' 
                                : (activeLicense.tier || 'STANDARD').toUpperCase();

                              return (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', minWidth: '175px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                                    <span style={{ 
                                      fontWeight: 600, 
                                      fontSize: '0.78rem',
                                      color: activeLicense.tier === 'partner' ? '#c084fc' : '#38bdf8' 
                                    }}>
                                      {tierDisplay}
                                    </span>
                                    <span style={{
                                      fontSize: '0.65rem',
                                      padding: '0.1rem 0.35rem',
                                      borderRadius: '4px',
                                      fontWeight: 600,
                                      background: isLicActive ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                                      color: isLicActive ? '#4ade80' : '#f87171',
                                      border: `1px solid ${isLicActive ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                                    }}>
                                      {activeLicense.status.toUpperCase()}
                                    </span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                    <Layers size={12} style={{ color: 'var(--text-muted)' }} />
                                    <span>{activeLicense.seats} Nodes / Seats</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                    <code 
                                      onClick={() => handleCopyKey(activeLicense.licenseKey)}
                                      title="Click to copy full license key"
                                      style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: '0.72rem',
                                        background: 'rgba(0,0,0,0.4)',
                                        padding: '0.15rem 0.35rem',
                                        borderRadius: '3px',
                                        border: '1px solid var(--border-normal)',
                                        color: 'var(--accent-cyan)',
                                        cursor: 'pointer'
                                      }}
                                    >
                                      {activeLicense.licenseKey.length > 16 
                                        ? `${activeLicense.licenseKey.substring(0, 14)}...` 
                                        : activeLicense.licenseKey}
                                    </code>
                                    <button
                                      type="button"
                                      onClick={() => handleCopyKey(activeLicense.licenseKey)}
                                      title="Copy License Key"
                                      style={{
                                        background: 'none',
                                        border: 'none',
                                        padding: '2px',
                                        cursor: 'pointer',
                                        color: copiedKey === activeLicense.licenseKey ? '#4ade80' : 'var(--text-muted)'
                                      }}
                                    >
                                      {copiedKey === activeLicense.licenseKey ? <Check size={12} /> : <Copy size={12} />}
                                    </button>
                                  </div>

                                  {activeLicense.expiresAt && (
                                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                                      Exp: {new Date(activeLicense.expiresAt).toLocaleDateString()}
                                    </div>
                                  )}
                                </div>
                              );
                            }

                            if (client) {
                              return (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', minWidth: '150px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                    <span style={{ fontWeight: 600, fontSize: '0.78rem', color: '#e2e8f0' }}>
                                      {(client.subscriptionTier || 'Standard').toUpperCase()}
                                    </span>
                                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                                      ({client.mcaLimit || 250} Nodes)
                                    </span>
                                  </div>
                                  <button
                                    onClick={() => handleProceedToIssueLicense(client)}
                                    style={{
                                      fontSize: '0.72rem',
                                      padding: '0.2rem 0.5rem',
                                      background: 'rgba(56, 189, 248, 0.1)',
                                      border: '1px solid rgba(56, 189, 248, 0.3)',
                                      color: 'var(--accent-cyan)',
                                      borderRadius: '4px',
                                      cursor: 'pointer',
                                      alignSelf: 'flex-start',
                                      marginTop: '0.15rem'
                                    }}
                                  >
                                    + Issue Key
                                  </button>
                                </div>
                              );
                            }

                            return (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Unassigned</span>
                              </div>
                            );
                          })()}
                        </td>
                        <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          {u.last_login ? new Date(u.last_login).toLocaleString() : <span style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>Never</span>}
                        </td>
                        <td>
                          {isProvisioned ? (
                            <span style={{ 
                              color: isOnline ? 'var(--status-secure)' : 'var(--status-vulnerable)',
                              fontWeight: 600,
                              fontSize: '0.82rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.25rem'
                            }}>
                              <Activity size={12} className={isOnline ? 'pulse' : ''} /> {isOnline ? 'ACTIVE' : 'OFFLINE'}
                            </span>
                          ) : (
                            <span style={{ 
                              color: 'var(--status-warning)',
                              fontWeight: 600,
                              fontSize: '0.82rem'
                            }}>
                              PENDING LICENSING
                            </span>
                          )}
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'center', alignItems: 'center' }}>
                            {/* Support Mirror Button (Instant Tenant Diagnostics) */}
                            {onMirrorTenant && isProvisioned && (
                              <button
                                type="button"
                                onClick={() => onMirrorTenant(sanitizedPrefix || client.name)}
                                title={`Launch Support Diagnostic Mirror for ${client?.displayName || client?.name || sanitizedPrefix}`}
                                style={{
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'rgba(234, 179, 8, 0.15)',
                                  color: '#facc15',
                                  border: '1px solid rgba(234, 179, 8, 0.4)',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.35rem',
                                  fontWeight: 600,
                                  whiteSpace: 'nowrap',
                                  transition: 'all 0.15s ease'
                                }}
                                onMouseEnter={(e) => {
                                  e.currentTarget.style.background = 'rgba(234, 179, 8, 0.25)';
                                  e.currentTarget.style.borderColor = '#facc15';
                                }}
                                onMouseLeave={(e) => {
                                  e.currentTarget.style.background = 'rgba(234, 179, 8, 0.15)';
                                  e.currentTarget.style.borderColor = 'rgba(234, 179, 8, 0.4)';
                                }}
                              >
                                <Eye size={13} /> Support Mirror
                              </button>
                            )}

                            {/* Deploy / Decom Button */}
                            {isProvisioned ? (
                              <button
                                onClick={() => handleDecommission(client.name)}
                                disabled={u.row_locked}
                                style={u.row_locked ? {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'rgba(255, 255, 255, 0.03)',
                                  color: '#64748b',
                                  border: '1px solid rgba(255, 255, 255, 0.08)',
                                  borderRadius: '4px',
                                  cursor: 'not-allowed',
                                  whiteSpace: 'nowrap'
                                } : {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  color: '#f87171',
                                  border: '1px solid rgba(239, 68, 68, 0.35)',
                                  background: 'rgba(220, 38, 38, 0.2)',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  whiteSpace: 'nowrap'
                                }}
                              >
                                Decom Tenant
                              </button>
                            ) : (
                              <button
                                onClick={() => handleDeployInline(u.email, sanitizedPrefix)}
                                disabled={u.row_locked}
                                style={u.row_locked ? {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'rgba(255, 255, 255, 0.03)',
                                  color: '#64748b',
                                  border: '1px solid rgba(255, 255, 255, 0.08)',
                                  borderRadius: '4px',
                                  cursor: 'not-allowed',
                                  whiteSpace: 'nowrap'
                                } : {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
                                  color: '#ffffff',
                                  border: 'none',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  fontWeight: 500,
                                  whiteSpace: 'nowrap'
                                }}
                              >
                                Deploy Tenant
                              </button>
                            )}

                            {/* Make Admin / Demote to User Button */}
                            {u.role === 'admin' ? (
                              <button
                                onClick={() => handleToggleRole(u.id, 'user')}
                                disabled={u.row_locked || u.email === currentUserEmail}
                                style={(u.row_locked || u.email === currentUserEmail) ? {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'rgba(255, 255, 255, 0.03)',
                                  color: '#64748b',
                                  border: '1px solid rgba(255, 255, 255, 0.08)',
                                  borderRadius: '4px',
                                  cursor: 'not-allowed',
                                  whiteSpace: 'nowrap'
                                } : {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  color: '#f87171',
                                  border: '1px solid rgba(239, 68, 68, 0.35)',
                                  background: 'rgba(220, 38, 38, 0.2)',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  whiteSpace: 'nowrap'
                                }}
                                title={u.email === currentUserEmail ? "You cannot demote yourself" : "Demote to User"}
                              >
                                Demote User
                              </button>
                            ) : (
                              <button
                                onClick={() => handleToggleRole(u.id, 'admin')}
                                disabled={u.row_locked}
                                style={u.row_locked ? {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'rgba(255, 255, 255, 0.03)',
                                  color: '#64748b',
                                  border: '1px solid rgba(255, 255, 255, 0.08)',
                                  borderRadius: '4px',
                                  cursor: 'not-allowed',
                                  whiteSpace: 'nowrap'
                                } : {
                                  padding: '0.35rem 0.75rem',
                                  fontSize: '0.78rem',
                                  background: 'linear-gradient(135deg, #a855f7 0%, #c084fc 100%)',
                                  color: '#ffffff',
                                  border: 'none',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  fontWeight: 500,
                                  whiteSpace: 'nowrap'
                                }}
                              >
                                Make Admin
                              </button>
                            )}

                            {/* Reset Password Button */}
                            <button
                              onClick={() => handleResetPassword(u.id, u.email)}
                              disabled={u.row_locked}
                              style={u.row_locked ? {
                                padding: '0.35rem 0.75rem',
                                fontSize: '0.78rem',
                                background: 'rgba(255, 255, 255, 0.03)',
                                color: '#64748b',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '4px',
                                cursor: 'not-allowed',
                                whiteSpace: 'nowrap'
                              } : {
                                padding: '0.35rem 0.75rem',
                                fontSize: '0.78rem',
                                background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                                color: '#ffffff',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontWeight: 500,
                                whiteSpace: 'nowrap'
                              }}
                            >
                              Reset Password
                            </button>

                            {/* Delete User Button */}
                            <button
                              onClick={() => setUserToDelete(u)}
                              disabled={u.row_locked || u.email === currentUserEmail}
                              style={(u.row_locked || u.email === currentUserEmail) ? {
                                padding: '0.35rem 0.75rem',
                                fontSize: '0.78rem',
                                background: 'rgba(255, 255, 255, 0.03)',
                                color: '#64748b',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '4px',
                                cursor: 'not-allowed',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                whiteSpace: 'nowrap'
                              } : {
                                padding: '0.35rem 0.75rem',
                                fontSize: '0.78rem',
                                color: '#cbd5e1',
                                border: '1px solid rgba(255, 255, 255, 0.15)',
                                background: 'rgba(255, 255, 255, 0.04)',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                whiteSpace: 'nowrap'
                              }}
                              title={u.email === currentUserEmail ? "You cannot delete yourself" : "Permanently Delete User & Container Environment"}
                            >
                              <Trash2 size={13} /> Delete User
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {sortedUsers.length === 0 && (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                        {users.length === 0 
                          ? "No registered client users found in master database."
                          : "No registered client users matched your search criteria."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* SEO & GEO Analytics Dashboard */}
      {activeSubTab === 'analytics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1.5rem' }}>
          {/* Analytics Summary Cards */}
          <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Total Crawler Indexations</h3>
                <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>
                  {analyticsData ? analyticsData.crawlerStats.reduce((sum, c) => sum + c.hits, 0) : 0}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Search & AI Crawler Hits
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--accent-cyan)' }}>
                <Globe size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>AI Citations & Referrals</h3>
                <div className="metric-value" style={{ color: '#c084fc' }}>
                  {analyticsData ? analyticsData.referrerStats
                    .filter(r => ['Perplexity AI', 'OpenAI Search', 'Claude'].includes(r.source))
                    .reduce((sum, r) => sum + r.hits, 0) : 0}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Ref traffic from LLM searches
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#c084fc' }}>
                <Activity size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>On-Page Metadata Audit</h3>
                <div className="metric-value" style={{ color: 'var(--status-secure)' }}>
                  {analyticsData ? `${analyticsData.auditReport.score}%` : '0%'}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  SEO & GEO Tag Health
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-secure)' }}>
                <Layers size={24} />
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem' }}>
            {/* Crawler Activity Log Table */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Globe size={18} color="var(--accent-cyan)" /> Crawler Indexation Activity
              </h3>
              <div style={{ overflowX: 'auto' }}>
                <table className="quark-table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th style={{ color: 'var(--text-secondary)' }}>Crawler Bot</th>
                      <th style={{ color: 'var(--text-secondary)', textAlign: 'center' }}>Total Hits</th>
                      <th style={{ color: 'var(--text-secondary)', textAlign: 'right' }}>Last Crawl</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analyticsData?.crawlerStats.map((bot, index) => (
                      <tr key={index}>
                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{bot.name}</td>
                        <td style={{ textAlign: 'center', fontWeight: 700, color: 'var(--accent-cyan)' }}>{bot.hits}</td>
                        <td style={{ textAlign: 'right', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          {new Date(bot.lastActive).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                    {!analyticsData?.crawlerStats?.length && (
                      <tr>
                        <td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>
                          No crawler records found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Referrals Breakdown */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} color="#c084fc" /> Traffic Referrals & AI Citations
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {analyticsData?.referrerStats.map((ref, index) => {
                  const maxHits = Math.max(...(analyticsData?.referrerStats.map(r => r.hits) || [1]));
                  const pct = (ref.hits / maxHits) * 100;
                  const isAiEngine = ['Perplexity AI', 'OpenAI Search', 'Claude'].includes(ref.source);
                  
                  return (
                    <div key={index} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                        <span style={{ fontWeight: 500, color: isAiEngine ? '#d8b4fe' : 'var(--text-primary)' }}>
                          {ref.source} {isAiEngine && <span style={{ fontSize: '0.75rem', background: 'rgba(192, 132, 252, 0.2)', color: '#c084fc', padding: '0.1rem 0.3rem', borderRadius: '4px', marginLeft: '0.3rem' }}>AI CITATION</span>}
                        </span>
                        <strong style={{ color: 'var(--text-secondary)' }}>{ref.hits} visits</strong>
                      </div>
                      <div style={{ height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{ 
                          height: '100%', 
                          width: `${pct}%`, 
                          background: isAiEngine ? 'linear-gradient(90deg, #c084fc 0%, #a855f7 100%)' : 'linear-gradient(90deg, var(--accent-cyan) 0%, #0891b2 100%)', 
                          borderRadius: '4px',
                          transition: 'width 0.5s ease-out'
                        }}></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Direct Access Geo Breakdown */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Globe size={18} color="var(--accent-cyan)" /> Direct Access by Location
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {analyticsData?.directGeoStats?.map((geo, index) => {
                  const maxHits = Math.max(...(analyticsData?.directGeoStats?.map(g => g.hits) || [1]));
                  const pct = (geo.hits / maxHits) * 100;
                  
                  return (
                    <div key={index} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                        <span style={{ fontWeight: 500, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ 
                            fontSize: '0.7rem', 
                            background: 'rgba(0, 242, 254, 0.1)', 
                            color: 'var(--accent-cyan)', 
                            padding: '0.15rem 0.35rem', 
                            borderRadius: '4px',
                            fontWeight: 'bold',
                            fontFamily: 'var(--font-mono)'
                          }}>
                            {geo.country}
                          </span>
                          <span>{geo.region}</span>
                        </span>
                        <strong style={{ color: 'var(--text-secondary)' }}>{geo.hits} visits</strong>
                      </div>
                      <div style={{ height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{ 
                          height: '100%', 
                          width: `${pct}%`, 
                          background: 'linear-gradient(90deg, #10b981 0%, #059669 100%)', 
                          borderRadius: '4px',
                          transition: 'width 0.5s ease-out'
                        }}></div>
                      </div>
                    </div>
                  );
                })}
                {(!analyticsData?.directGeoStats || analyticsData.directGeoStats.length === 0) && (
                  <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>
                    No location telemetry records found.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* On-Page Metadata Self-Audit Report */}
          <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={18} color="var(--status-secure)" /> Landing Page SEO & GEO Audit Report
            </h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ color: analyticsData?.auditReport.titlePresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.titlePresent ? '✓' : '✗'}
                  </span>
                  <strong style={{ fontSize: '0.9rem' }}>Title Tag Status:</strong>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {analyticsData?.auditReport.titlePresent ? 'Present' : 'Missing'}
                  </span>
                </div>
                {analyticsData?.auditReport.titlePresent && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.85rem', fontFamily: 'var(--font-mono)', border: '1px solid var(--border-normal)' }}>
                    "{analyticsData.auditReport.titleValue}"
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                  <span style={{ color: analyticsData?.auditReport.descriptionPresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.descriptionPresent ? '✓' : '✗'}
                  </span>
                  <strong style={{ fontSize: '0.9rem' }}>Meta Description Tag:</strong>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {analyticsData?.auditReport.descriptionPresent ? 'Present' : 'Missing'}
                  </span>
                </div>
                {analyticsData?.auditReport.descriptionPresent && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', border: '1px solid var(--border-normal)' }}>
                    "{analyticsData.auditReport.descriptionValue}"
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', background: 'rgba(0,0,0,0.15)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-normal)' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.4rem', marginBottom: '0.25rem' }}>
                  Crawled Schema Checklist
                </h4>
                
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                  <span>OpenGraph Meta Tags (`og:title`, etc.)</span>
                  <span style={{ color: analyticsData?.auditReport.openGraphPresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.openGraphPresent ? '✓ Verified' : '✗ Missing'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                  <span>Twitter Card Metadata (`twitter:card`)</span>
                  <span style={{ color: analyticsData?.auditReport.twitterPresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.twitterPresent ? '✓ Verified' : '✗ Missing'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                  <span>JSON-LD Schema (`SoftwareApplication`)</span>
                  <span style={{ color: analyticsData?.auditReport.jsonLdSoftwarePresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.jsonLdSoftwarePresent ? '✓ Verified (GEO)' : '✗ Missing'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.88rem' }}>
                  <span>JSON-LD Schema (`FAQPage`)</span>
                  <span style={{ color: analyticsData?.auditReport.jsonLdFaqPresent ? 'var(--status-secure)' : 'var(--status-vulnerable)', fontWeight: 'bold' }}>
                    {analyticsData?.auditReport.jsonLdFaqPresent ? '✓ Verified (GEO)' : '✗ Missing'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Partner & Corporate Licenses Subtab */}
      {activeSubTab === 'licenses' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginTop: '1.5rem' }}>
          {/* Metrics Grid */}
          <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Total Active Licenses</h3>
                <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>
                  {licenses.filter(l => l.status === 'active').length}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Cryptographically Valid
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--accent-cyan)' }}>
                <Key size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Partner Evaluations</h3>
                <div className="metric-value" style={{ color: '#38bdf8' }}>
                  {licenses.filter(l => l.tier === 'partner' && l.status === 'active').length}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Extended Partner Trials
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#38bdf8' }}>
                <Users size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Corporate Fleet Deployments</h3>
                <div className="metric-value" style={{ color: '#c084fc' }}>
                  {licenses.filter(l => (l.tier === 'corporate' || l.tier === 'corp') && l.status === 'active').length}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Production Enterprise Fleets
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#c084fc' }}>
                <Building size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Authorized Endpoint Seats</h3>
                <div className="metric-value" style={{ color: 'var(--status-secure)' }}>
                  {licenses.filter(l => l.status === 'active').reduce((sum, l) => sum + (l.seats || 0), 0).toLocaleString()}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Workstations & Cloud VMs
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-secure)' }}>
                <ShieldCheck size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card" style={{ borderColor: pendingLicensingClients.length > 0 ? 'rgba(245, 158, 11, 0.4)' : undefined }}>
              <div className="metric-info">
                <h3>Pending Licensing</h3>
                <div className="metric-value" style={{ color: pendingLicensingClients.length > 0 ? 'var(--status-warning)' : 'var(--text-secondary)' }}>
                  {pendingLicensingClients.length}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Awaiting License Issuance
                </div>
              </div>
              <div className="metric-icon" style={{ color: pendingLicensingClients.length > 0 ? 'var(--status-warning)' : 'var(--text-secondary)' }}>
                <Clock size={24} />
              </div>
            </div>
          </div>

          {/* Resend Cloud Mailer Status & Configuration Card */}
          <div className="glass-panel" style={{
            padding: '1rem 1.25rem',
            borderRadius: '12px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <div style={{
                  width: 10,
                  height: 10,
                  borderRadius: '50%',
                  background: mailSettings?.isConfigured ? '#4ade80' : '#f87171',
                  boxShadow: mailSettings?.isConfigured ? '0 0 8px #4ade80' : '0 0 8px #f87171'
                }} />
                <span style={{ fontWeight: 600, fontSize: '0.92rem', color: 'var(--text-primary)' }}>
                  Cloud Automated Mailer (Resend API)
                </span>
                <span style={{
                  fontSize: '0.72rem',
                  padding: '0.18rem 0.5rem',
                  borderRadius: '4px',
                  fontWeight: 600,
                  background: mailSettings?.isConfigured ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  color: mailSettings?.isConfigured ? '#4ade80' : '#f87171',
                  border: `1px solid ${mailSettings?.isConfigured ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                }}>
                  {mailSettings?.isConfigured ? 'AUTOMATED DELIVERY ACTIVE' : 'API KEY REQUIRED'}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                {mailSettings?.isConfigured && (
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                    Key: {mailSettings.maskedKey} • Sender: {mailSettings.sender}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => setShowMailConfig(prev => !prev)}
                  className="btn-secondary"
                  style={{
                    padding: '0.35rem 0.75rem',
                    fontSize: '0.78rem',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem'
                  }}
                >
                  <Mail size={13} />
                  {showMailConfig ? 'Hide Mail Settings' : (mailSettings?.isConfigured ? 'Edit Mail Key' : 'Configure Resend API Key')}
                </button>
              </div>
            </div>

            {showMailConfig && (
              <div style={{
                background: 'rgba(0, 0, 0, 0.35)',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem'
              }}>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  QuarkShield dispatches license activation keys directly via <strong style={{ color: '#38bdf8' }}>Resend API (resend.com)</strong> without opening local email clients. Set your active Resend API Key and verified sender below:
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  <input
                    type="password"
                    placeholder="Enter Resend API Key (re_...)"
                    value={resendInputKey}
                    onChange={(e) => setResendInputKey(e.target.value)}
                    style={{
                      flex: 1,
                      minWidth: '280px',
                      padding: '0.5rem 0.75rem',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      fontFamily: 'monospace'
                    }}
                  />
                  <input
                    type="text"
                    placeholder="Sender: License@quarkshield.ai"
                    value={resendInputSender}
                    onChange={(e) => setResendInputSender(e.target.value)}
                    style={{
                      width: '240px',
                      padding: '0.5rem 0.75rem',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid rgba(255, 255, 255, 0.15)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem'
                    }}
                  />
                  <button
                    type="button"
                    onClick={handleSaveMailSettings}
                    disabled={savingMailSettings || !resendInputKey.trim()}
                    className="btn-primary"
                    style={{
                      padding: '0.5rem 1rem',
                      fontSize: '0.82rem',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.4rem',
                      background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                      border: '1px solid #38bdf8'
                    }}
                  >
                    <Send size={14} />
                    {savingMailSettings ? 'Saving...' : 'Save & Validate Key'}
                  </button>
                </div>
                {mailSaveMsg && (
                  <div style={{ fontSize: '0.82rem', color: '#4ade80', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Check size={14} /> {mailSaveMsg}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Pending Licensing Queue */}
          {pendingLicensingClients.length > 0 && (
            <div className="glass-panel" style={{ padding: '1.25rem 1.5rem', background: 'rgba(245, 158, 11, 0.05)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'var(--status-warning)', animation: 'pulse 1.5s infinite' }} />
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, margin: 0, color: 'var(--status-warning)' }}>
                    Pending Licensing Queue ({pendingLicensingClients.length})
                  </h3>
                </div>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Onboarded accounts awaiting cryptographic license generation & activation
                </span>
              </div>

              <div style={{ overflowX: 'auto' }}>
                <table className="admin-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Customer ID</th>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Organization / Partner</th>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Account Type</th>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Contact & Location</th>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Requested Seats</th>
                      <th style={{ padding: '0.6rem 0.8rem' }}>Payment Mode</th>
                      <th style={{ padding: '0.6rem 0.8rem', textAlign: 'center' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pendingLicensingClients.map(c => (
                      <tr key={c.name} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                        <td style={{ padding: '0.75rem 0.8rem' }}>
                          <span style={{
                            fontSize: '0.78rem',
                            fontFamily: 'monospace',
                            fontWeight: 700,
                            color: '#38bdf8',
                            background: 'rgba(56, 189, 248, 0.1)',
                            padding: '0.2rem 0.45rem',
                            borderRadius: '4px',
                            border: '1px solid rgba(56, 189, 248, 0.25)',
                            whiteSpace: 'nowrap'
                          }}>
                            {c.customerId || (c.accountType === 'partner' ? 'PART-9148' : 'CORP-4821')}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {c.displayName || c.name}
                          <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'monospace' }}>{c.name}</div>
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem' }}>
                          <span style={{
                            fontSize: '0.72rem',
                            fontWeight: 700,
                            letterSpacing: '0.04em',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '4px',
                            background: c.accountType === 'partner' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(192, 132, 252, 0.15)',
                            color: c.accountType === 'partner' ? '#38bdf8' : '#c084fc',
                            border: `1px solid ${c.accountType === 'partner' ? 'rgba(56, 189, 248, 0.3)' : 'rgba(192, 132, 252, 0.3)'}`
                          }}>
                            {c.accountType === 'partner' ? 'MSP PARTNER' : 'CORPORATE'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                          <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{c.contactName || 'Primary Admin'}</div>
                          <div>{c.adminEmail || 'No email'} {c.phone ? `• ${c.phone}` : ''}</div>
                          {[c.city, c.state, c.country].filter(Boolean).length > 0 && (
                            <div style={{ color: '#64748b', fontSize: '0.78rem' }}>
                              📍 {[c.city, c.state, c.country].filter(Boolean).join(', ')}
                            </div>
                          )}
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                          {c.mcaLimit || (c.accountType === 'partner' ? 50 : 500)} seats
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem' }}>
                          {c.stripePaymentStatus === 'paid' ? (
                            <span style={{
                              fontSize: '0.72rem',
                              fontWeight: 600,
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              background: 'rgba(34, 197, 94, 0.15)',
                              color: '#4ade80',
                              border: '1px solid rgba(34, 197, 94, 0.3)',
                              whiteSpace: 'nowrap'
                            }}>
                              💳 Paid / Verified
                            </span>
                          ) : c.stripePaymentLink ? (
                            <span style={{
                              fontSize: '0.72rem',
                              fontWeight: 600,
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              background: 'rgba(245, 158, 11, 0.15)',
                              color: '#fbbf24',
                              border: '1px solid rgba(245, 158, 11, 0.3)',
                              whiteSpace: 'nowrap'
                            }}>
                              💳 Payment Link Sent
                            </span>
                          ) : (
                            <span style={{
                              fontSize: '0.72rem',
                              fontWeight: 600,
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              background: 'rgba(148, 163, 184, 0.12)',
                              color: '#94a3b8',
                              border: '1px solid rgba(148, 163, 184, 0.25)',
                              whiteSpace: 'nowrap'
                            }}>
                              🏦 ACH / Check / Invoice
                            </span>
                          )}
                        </td>
                        <td style={{ padding: '0.75rem 0.8rem', textAlign: 'center' }}>
                          <button
                            type="button"
                            onClick={() => handleProceedToIssueLicense(c)}
                            style={{
                              padding: '0.45rem 0.9rem',
                              background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
                              color: '#fff',
                              border: 'none',
                              borderRadius: '6px',
                              fontWeight: 600,
                              fontSize: '0.8rem',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.4rem',
                              boxShadow: '0 2px 8px rgba(6, 182, 212, 0.3)'
                            }}
                          >
                            <Key size={14} /> Issue License
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Issue New License Form Card */}
          <div className="glass-panel" style={{ padding: '1.5rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.5rem' }}>
              <Plus size={20} style={{ color: 'var(--accent-cyan)' }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 600, margin: 0 }}>Issue Partner or Corporate License Key</h3>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: '1.25rem' }}>
              Generate an HMAC-SHA256 cryptographically signed license token. Scanners can verify this token offline or link into QuarkShield Central Cloud Fleet.
            </p>

            <form onSubmit={handleGenerateLicense} style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.2rem' }}>
                {/* Organization / Partner Name (Dropdown with Pending License support) */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                    <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      Enterprise / Partner Name *
                    </label>
                    {pendingLicensingClients.length > 0 && (
                      <span style={{ fontSize: '0.75rem', color: 'var(--status-warning)', fontWeight: 600 }}>
                        {pendingLicensingClients.length} awaiting license
                      </span>
                    )}
                  </div>

                  <select
                    value={
                      selectedOnboardedSlug || 
                      (clients.find(c => c.name.toLowerCase() === licenseOrg.toLowerCase() || c.displayName?.toLowerCase() === licenseOrg.toLowerCase())?.name) ||
                      (licenseOrg ? '__custom__' : '')
                    }
                    onChange={(e) => {
                      const val = e.target.value;
                      setSelectedOnboardedSlug(val);
                      if (val === '__custom__') {
                        setLicenseOrg('');
                      } else if (val) {
                        const target = clients.find(c => c.name === val);
                        if (target) {
                          setLicenseOrg(target.displayName || target.name);
                          setLicenseTier(target.accountType === 'partner' ? 'partner' : 'corporate');
                          setLicenseSeats(target.mcaLimit || (target.accountType === 'partner' ? 50 : 500));
                          setLicenseDays(target.accountType === 'partner' ? 30 : 365);
                        }
                      } else {
                        setLicenseOrg('');
                      }
                    }}
                    required={!licenseOrg}
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.8rem',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: selectedOnboardedSlug && selectedOnboardedSlug !== '__custom__' ? '1px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                      outline: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    <option value="" style={{ background: '#0f172a' }}>
                      -- Select Onboarded User / Tenant --
                    </option>
                    {pendingLicensingClients.length > 0 && (
                      <optgroup label="⏳ Pending Licensing (Onboarded)">
                        {pendingLicensingClients.map(c => (
                          <option key={c.name} value={c.name} style={{ background: '#0f172a', color: '#fbbf24', fontWeight: 600 }}>
                            {c.displayName || c.name} (Pending Licensing) — {c.accountType === 'partner' ? 'MSP Partner' : 'Corporate'}
                          </option>
                        ))}
                      </optgroup>
                    )}
                    {clients.filter(c => c.status !== 'pending_licensing').length > 0 && (
                      <optgroup label="✅ Active / Registered Tenants">
                        {clients.filter(c => c.status !== 'pending_licensing').map(c => (
                          <option key={c.name} value={c.name} style={{ background: '#0f172a' }}>
                            {c.displayName || c.name} (Active)
                          </option>
                        ))}
                      </optgroup>
                    )}
                    <optgroup label="✏️ Manual Entry">
                      <option value="__custom__" style={{ background: '#0f172a' }}>
                        + Enter Custom Organization Name...
                      </option>
                    </optgroup>
                  </select>

                  {/* Manual input if __custom__ or if user wants to override */}
                  {(selectedOnboardedSlug === '__custom__' || (!clients.some(c => c.name === selectedOnboardedSlug) && licenseOrg)) && (
                    <input
                      type="text"
                      placeholder="Enter custom enterprise or partner name"
                      value={licenseOrg}
                      onChange={(e) => setLicenseOrg(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        marginTop: '0.5rem',
                        padding: '0.6rem 0.8rem',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--accent-cyan)',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '0.9rem',
                        outline: 'none'
                      }}
                    />
                  )}

                  {/* If an onboarded pending client is selected, show details snippet */}
                  {(() => {
                    const selClient = clients.find(c => c.name === selectedOnboardedSlug);
                    if (!selClient) return null;
                    return (
                      <div style={{
                        marginTop: '0.6rem',
                        padding: '0.6rem 0.8rem',
                        borderRadius: '6px',
                        background: 'rgba(6, 182, 212, 0.07)',
                        border: '1px solid rgba(6, 182, 212, 0.25)',
                        fontSize: '0.78rem',
                        color: 'var(--text-secondary)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.25rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                            👤 {selClient.contactName || 'Primary Admin'} ({selClient.adminEmail || 'No email'})
                          </span>
                          <span style={{
                            fontSize: '0.7rem',
                            fontWeight: 700,
                            padding: '0.15rem 0.4rem',
                            borderRadius: '3px',
                            background: selClient.status === 'pending_licensing' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                            color: selClient.status === 'pending_licensing' ? '#fbbf24' : '#4ade80'
                          }}>
                            {selClient.status === 'pending_licensing' ? 'PENDING LICENSING' : 'ACTIVE'}
                          </span>
                        </div>
                        <div>
                          📞 {selClient.phone || 'No phone'} 
                          {[selClient.city, selClient.state, selClient.country].filter(Boolean).length > 0 && (
                            <span> • 📍 {[selClient.city, selClient.state, selClient.country].filter(Boolean).join(', ')}</span>
                          )}
                        </div>
                        {selClient.stripePaymentLink && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#38bdf8' }}>
                            <CreditCard size={12} />
                            <span>Stripe Payment: {selClient.stripePaymentStatus === 'paid' ? 'Paid / Verified' : 'Checkout Link Generated'}</span>
                          </div>
                        )}
                      </div>
                    );
                  })()}

                  <div style={{ marginTop: '0.4rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    Before issuing a license, the user/partner should be onboarded.{' '}
                    <button
                      type="button"
                      onClick={() => setActiveSubTab('onboarding')}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--accent-cyan)',
                        textDecoration: 'underline',
                        cursor: 'pointer',
                        fontSize: '0.75rem',
                        padding: 0
                      }}
                    >
                      Onboard new user here &rarr;
                    </button>
                  </div>
                </div>

                {/* Tier Selection */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                    License Tier *
                  </label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => { setLicenseTier('partner'); setLicenseDays(30); setLicenseSeats(25); }}
                      style={{
                        flex: 1,
                        padding: '0.6rem',
                        borderRadius: '6px',
                        border: licenseTier === 'partner' ? '1px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                        background: licenseTier === 'partner' ? 'rgba(6, 182, 212, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                        color: licenseTier === 'partner' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        fontWeight: licenseTier === 'partner' ? 600 : 400,
                        cursor: 'pointer',
                        fontSize: '0.88rem'
                      }}
                    >
                      🤝 Partner Evaluation
                    </button>
                    <button
                      type="button"
                      onClick={() => { setLicenseTier('corporate'); setLicenseDays(365); setLicenseSeats(500); }}
                      style={{
                        flex: 1,
                        padding: '0.6rem',
                        borderRadius: '6px',
                        border: licenseTier === 'corporate' ? '1px solid #c084fc' : '1px solid var(--border-normal)',
                        background: licenseTier === 'corporate' ? 'rgba(168, 85, 247, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                        color: licenseTier === 'corporate' ? '#c084fc' : 'var(--text-secondary)',
                        fontWeight: licenseTier === 'corporate' ? 600 : 400,
                        cursor: 'pointer',
                        fontSize: '0.88rem'
                      }}
                    >
                      🏢 Corporate Enterprise
                    </button>
                  </div>
                </div>
              </div>

              {/* Duration Presets */}
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                  Duration: <strong style={{ color: 'var(--text-primary)' }}>{licenseDays} Days</strong>
                </label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {[14, 30, 60, 90, 180, 365].map(d => (
                    <button
                      key={d}
                      type="button"
                      onClick={() => setLicenseDays(d)}
                      style={{
                        padding: '0.4rem 0.8rem',
                        borderRadius: '6px',
                        fontSize: '0.82rem',
                        cursor: 'pointer',
                        border: licenseDays === d ? '1px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                        background: licenseDays === d ? 'rgba(6, 182, 212, 0.2)' : 'rgba(255, 255, 255, 0.03)',
                        color: licenseDays === d ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        fontWeight: licenseDays === d ? 600 : 400
                      }}
                    >
                      {d} Days {d === 365 && '★ (1 Year)'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Seat Capacity Presets */}
              <div>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                  Endpoint Seat Capacity: <strong style={{ color: 'var(--text-primary)' }}>{licenseSeats.toLocaleString()} Endpoints</strong>
                </label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {[10, 25, 50, 100, 250, 500, 1000, 5000, 50000].map(s => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => setLicenseSeats(s)}
                      style={{
                        padding: '0.4rem 0.8rem',
                        borderRadius: '6px',
                        fontSize: '0.82rem',
                        cursor: 'pointer',
                        border: licenseSeats === s ? '1px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                        background: licenseSeats === s ? 'rgba(6, 182, 212, 0.2)' : 'rgba(255, 255, 255, 0.03)',
                        color: licenseSeats === s ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        fontWeight: licenseSeats === s ? 600 : 400
                      }}
                    >
                      {s >= 50000 ? 'Unlimited (50k)' : `${s} Seats`}
                    </button>
                  ))}
                </div>
              </div>

              {/* Submit Button */}
              <div>
                <button
                  type="submit"
                  disabled={isGeneratingLicense || !licenseOrg.trim()}
                  className="btn-primary"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.65rem 1.4rem',
                    fontSize: '0.92rem',
                    fontWeight: 600
                  }}
                >
                  <Key size={16} />
                  {isGeneratingLicense ? 'Signing Cryptographic Token...' : 'Generate Cryptographic License Key'}
                </button>
              </div>
            </form>
          </div>

          {/* Newly Generated License Modal / Card */}
          {generatedLicense && (
            <div className="glass-panel" style={{
              padding: '1.5rem',
              background: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.4)',
              borderRadius: '12px',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <CheckCircle2 size={20} style={{ color: 'var(--status-secure)' }} />
                  <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    License Key Successfully Created for {generatedLicense.tenantName}
                  </h4>
                </div>
                <button
                  onClick={() => setGeneratedLicense(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.85rem' }}
                >
                  Dismiss
                </button>
              </div>

              <div style={{
                background: 'rgba(0, 0, 0, 0.5)',
                padding: '0.8rem 1rem',
                borderRadius: '8px',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: '1rem'
              }}>
                <code style={{ fontSize: '1.05rem', color: 'var(--accent-cyan)', fontWeight: 700, letterSpacing: '0.5px' }}>
                  {generatedLicense.licenseKey}
                </code>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <button
                    onClick={() => handleCopyKey(generatedLicense.licenseKey)}
                    className="btn-secondary"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', padding: '0.4rem 0.8rem', fontSize: '0.82rem' }}
                  >
                    {copiedKey === generatedLicense.licenseKey ? <Check size={14} style={{ color: 'var(--status-secure)' }} /> : <Copy size={14} />}
                    {copiedKey === generatedLicense.licenseKey ? 'Copied!' : 'Copy Key'}
                  </button>
                  <button
                    onClick={() => handleSendLicenseEmail(generatedLicense)}
                    disabled={emailSendingKey === generatedLicense.licenseKey}
                    className="btn-primary"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.45rem',
                      padding: '0.4rem 0.85rem',
                      fontSize: '0.82rem',
                      background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                      border: '1px solid #38bdf8'
                    }}
                    title={generatedLicense.contactEmail ? `Dispatch license key to ${generatedLicense.contactEmail}` : "Send official license key to client contact from License@Quarkshield.ai"}
                  >
                    <Mail size={14} />
                    {emailSendingKey === generatedLicense.licenseKey 
                      ? 'Sending...' 
                      : (generatedLicense.contactEmail 
                          ? `✉️ Send Key to ${generatedLicense.contactEmail}` 
                          : '✉️ Send Key via Email (License@Quarkshield.ai)')}
                  </button>
                </div>
              </div>

              {emailSuccessMsg && (
                <div style={{
                  padding: '0.6rem 0.85rem',
                  borderRadius: '6px',
                  background: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid rgba(34, 197, 94, 0.4)',
                  color: '#4ade80',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}>
                  <CheckCircle2 size={16} />
                  <span>{emailSuccessMsg}</span>
                </div>
              )}

              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                <span>Customer ID: <strong style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{generatedLicense.customerId || (generatedLicense.tier === 'partner' ? 'PART-9148' : 'CORP-4821')}</strong></span>
                <span>Tier: <strong style={{ color: 'var(--text-primary)' }}>{generatedLicense.tier.toUpperCase()}</strong></span>
                <span>Seats: <strong style={{ color: 'var(--text-primary)' }}>{generatedLicense.seats} Endpoints</strong></span>
                <span>Validity: <strong style={{ color: 'var(--text-primary)' }}>{generatedLicense.durationDays} Days</strong> (Expires: {generatedLicense.expiresAt})</span>
                {generatedLicense.contactEmail && (
                  <span>Recipient: <strong style={{ color: '#4ade80' }}>{generatedLicense.contactName ? `${generatedLicense.contactName} (${generatedLicense.contactEmail})` : generatedLicense.contactEmail}</strong></span>
                )}
              </div>

              {/* Silent IT Deployment Snippets */}
              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.82rem' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.3rem' }}>
                  Enterprise Silent Deployment Command (GPO / Intune / MDM / systemd):
                </div>
                <code style={{ color: '#38bdf8', display: 'block', wordBreak: 'break-all' }}>
                  {generatedLicense.intuneGuidance}
                </code>
              </div>
            </div>
          )}

          {/* Active Licenses Directory Table (Collapsible Organization Groups) */}
          <div className="glass-panel" style={{ padding: '1.5rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)', borderRadius: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 600, margin: 0 }}>
                  Active & Registered Licenses ({licenses.length})
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: '0.25rem 0 0 0' }}>
                  {groupedLicenses.length} Client Organizations ({groupedLicenses.filter(g => g.tier === 'corporate' || g.tier === 'corp').length} Corporate • {groupedLicenses.filter(g => g.tier === 'partner').length} Partners) • Click any organization row or use Expand All to view its sub-license keys and enrolled workstations (Mac, Windows, Linux) consuming seats.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                <button
                  onClick={() => {
                    const allExp = groupedLicenses.length > 0 && groupedLicenses.every(g => !!expandedLicenseOrgs[g.orgKey]);
                    toggleAllLicenseOrgs(!allExp);
                  }}
                  className="btn-secondary"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.8rem',
                    borderRadius: '6px',
                    background: 'rgba(56, 189, 248, 0.08)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                    color: '#38bdf8',
                    cursor: 'pointer',
                    fontWeight: 500
                  }}
                >
                  {groupedLicenses.length > 0 && groupedLicenses.every(g => !!expandedLicenseOrgs[g.orgKey]) ? (
                    <>
                      <ChevronUp size={14} />
                      <span>Collapse All</span>
                    </>
                  ) : (
                    <>
                      <ChevronDown size={14} />
                      <span>Expand All</span>
                    </>
                  )}
                </button>
                <div style={{ position: 'relative', width: '260px' }}>
                  <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search org, key, or contact..."
                    value={licenseFilter}
                    onChange={(e) => setLicenseFilter(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem 0.8rem 0.5rem 2rem',
                      background: 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-normal)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  />
                </div>
              </div>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-normal)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.75rem', width: '36px' }}></th>
                    <th style={{ padding: '0.75rem' }}>Customer ID</th>
                    <th style={{ padding: '0.75rem' }}>Organization / Partner</th>
                    <th style={{ padding: '0.75rem' }}>Primary Contact</th>
                    <th style={{ padding: '0.75rem' }}>Tier</th>
                    <th style={{ padding: '0.75rem' }}>Sub-Licenses</th>
                    <th style={{ padding: '0.75rem' }}>Total Seats</th>
                    <th style={{ padding: '0.75rem' }}>Status</th>
                    <th style={{ padding: '0.75rem', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLicenseGroups.map(group => {
                    const isExpanded = (licenseFilter && licenseFilter.trim().length > 1) || !!expandedLicenseOrgs[group.orgKey];
                    const isCorp = group.tier === 'corporate' || group.tier === 'corp';

                    return (
                      <React.Fragment key={group.orgKey}>
                        {/* Collapsible Organization Parent Row */}
                        <tr
                          onClick={() => toggleLicenseOrg(group.orgKey)}
                          style={{
                            borderBottom: isExpanded ? 'none' : '1px solid rgba(255, 255, 255, 0.06)',
                            background: isExpanded ? 'rgba(56, 189, 248, 0.05)' : 'transparent',
                            cursor: 'pointer',
                            transition: 'background 0.15s ease'
                          }}
                          className="hover-highlight"
                        >
                          <td style={{ padding: '0.75rem 0.5rem 0.75rem 0.75rem', textAlign: 'center' }}>
                            <div style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: '24px',
                              height: '24px',
                              borderRadius: '4px',
                              background: isExpanded ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                              color: isExpanded ? '#38bdf8' : 'var(--text-muted)',
                              transition: 'all 0.2s ease'
                            }}>
                              <ChevronRight
                                size={15}
                                style={{
                                  transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
                                  transition: 'transform 0.2s ease'
                                }}
                              />
                            </div>
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            <span style={{
                              fontSize: '0.78rem',
                              fontFamily: 'monospace',
                              fontWeight: 700,
                              color: '#38bdf8',
                              background: 'rgba(56, 189, 248, 0.1)',
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              border: '1px solid rgba(56, 189, 248, 0.25)',
                              whiteSpace: 'nowrap'
                            }}>
                              {group.customerId}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                              <span>{group.tenantName}</span>
                              {group.subLicenses.length > 1 && (
                                <span style={{
                                  fontSize: '0.7rem',
                                  padding: '0.1rem 0.35rem',
                                  borderRadius: '3px',
                                  background: 'rgba(56, 189, 248, 0.15)',
                                  color: '#38bdf8',
                                  fontWeight: 500
                                }}>
                                  MSP Multi-Key
                                </span>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '0.75rem', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                            {group.contactEmail ? (
                              <div>
                                <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{group.contactName || 'Primary Admin'}</div>
                                <div style={{ color: '#38bdf8', fontSize: '0.75rem' }}>{group.contactEmail}</div>
                              </div>
                            ) : (
                              <span style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>Shared tenant admin</span>
                            )}
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            <span style={{
                              fontSize: '0.75rem',
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              fontWeight: 600,
                              textTransform: 'uppercase',
                              background: isCorp ? 'rgba(168, 85, 247, 0.15)' : 'rgba(6, 182, 212, 0.15)',
                              color: isCorp ? '#c084fc' : '#38bdf8',
                              border: isCorp ? '1px solid rgba(168, 85, 247, 0.3)' : '1px solid rgba(6, 182, 212, 0.3)'
                            }}>
                              {isCorp ? 'CORPORATE' : 'PARTNER'}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            <span style={{
                              fontSize: '0.78rem',
                              fontWeight: 600,
                              padding: '0.2rem 0.55rem',
                              borderRadius: '12px',
                              background: group.subLicenses.length > 1 ? 'rgba(56, 189, 248, 0.18)' : 'rgba(255, 255, 255, 0.06)',
                              color: group.subLicenses.length > 1 ? '#38bdf8' : 'var(--text-secondary)',
                              border: group.subLicenses.length > 1 ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid rgba(255, 255, 255, 0.1)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.35rem'
                            }}>
                              <Key size={11} />
                              {group.subLicenses.length} Sub-License{group.subLicenses.length !== 1 ? 's' : ''}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.35rem' }}>
                                <span style={{
                                  fontWeight: 700,
                                  color: group.usedSeats > 0 ? '#38bdf8' : 'var(--text-primary)',
                                  fontSize: '0.88rem'
                                }}>
                                  {group.usedSeats} / {group.totalSeats.toLocaleString()}
                                </span>
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                                  Seats Used ({Math.round((group.usedSeats / Math.max(1, group.totalSeats)) * 100)}%)
                                </span>
                              </div>
                              {group.usedSeats > 0 ? (
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', flexWrap: 'wrap' }}>
                                  {group.macCount > 0 && (
                                    <span style={{
                                      fontSize: '0.69rem',
                                      padding: '0.1rem 0.35rem',
                                      borderRadius: '3px',
                                      background: 'rgba(56, 189, 248, 0.12)',
                                      color: '#38bdf8',
                                      border: '1px solid rgba(56, 189, 248, 0.25)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.2rem'
                                    }}>
                                      <Laptop size={10} /> {group.macCount} Mac
                                    </span>
                                  )}
                                  {group.winCount > 0 && (
                                    <span style={{
                                      fontSize: '0.69rem',
                                      padding: '0.1rem 0.35rem',
                                      borderRadius: '3px',
                                      background: 'rgba(168, 85, 247, 0.12)',
                                      color: '#c084fc',
                                      border: '1px solid rgba(168, 85, 247, 0.25)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.2rem'
                                    }}>
                                      <Monitor size={10} /> {group.winCount} Windows
                                    </span>
                                  )}
                                  {group.linuxCount > 0 && (
                                    <span style={{
                                      fontSize: '0.69rem',
                                      padding: '0.1rem 0.35rem',
                                      borderRadius: '3px',
                                      background: 'rgba(34, 197, 94, 0.12)',
                                      color: '#4ade80',
                                      border: '1px solid rgba(34, 197, 94, 0.25)',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '0.2rem'
                                    }}>
                                      <Server size={10} /> {group.linuxCount} Linux
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                                  0 enrolled endpoints
                                </span>
                              )}
                            </div>
                          </td>
                          <td style={{ padding: '0.75rem' }}>
                            {group.overallStatus === 'active' ? (
                              <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', borderRadius: '4px', background: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.3)', fontWeight: 500 }}>
                                Active
                              </span>
                            ) : group.overallStatus === 'expired' ? (
                              <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)', fontWeight: 500 }}>
                                Expired
                              </span>
                            ) : (
                              <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 500 }}>
                                Revoked
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleLicenseOrg(group.orgKey);
                              }}
                              style={{
                                background: isExpanded ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                                border: isExpanded ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid var(--border-normal)',
                                color: isExpanded ? '#38bdf8' : 'var(--text-secondary)',
                                borderRadius: '4px',
                                padding: '0.3rem 0.65rem',
                                fontSize: '0.75rem',
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.35rem',
                                fontWeight: 500
                              }}
                            >
                              {isExpanded ? (
                                <>
                                  <ChevronUp size={12} />
                                  <span>Collapse</span>
                                </>
                              ) : (
                                <>
                                  <ChevronDown size={12} />
                                  <span>Expand ({group.subLicenses.length})</span>
                                </>
                              )}
                            </button>
                          </td>
                        </tr>

                        {/* Collapsible Sub-Licenses Child View */}
                        {isExpanded && (
                          <tr style={{ background: 'rgba(0, 0, 0, 0.3)', borderBottom: '1px solid var(--border-normal)' }}>
                            <td colSpan={9} style={{ padding: '0.5rem 1.25rem 1.25rem 2.5rem' }}>
                              <div style={{
                                background: 'rgba(255, 255, 255, 0.02)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '8px',
                                padding: '1rem',
                                boxShadow: 'inset 0 2px 6px rgba(0, 0, 0, 0.3)'
                              }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#38bdf8', display: 'flex', gap: '0.45rem', alignItems: 'center', letterSpacing: '0.3px' }}>
                                    <Key size={13} />
                                    <span>SUB-LICENSES & FLEET ENDPOINT KEYS ({group.subLicenses.length})</span>
                                  </div>
                                  <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                                    Individual keys dispatched to client workstations, servers, or tenant departments.
                                  </span>
                                </div>

                                <div style={{ overflowX: 'auto' }}>
                                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                                    <thead>
                                      <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                                        <th style={{ padding: '0.5rem' }}>#</th>
                                        <th style={{ padding: '0.5rem' }}>License Key</th>
                                        <th style={{ padding: '0.5rem' }}>Assigned Contact</th>
                                        <th style={{ padding: '0.5rem' }}>Seat Allocation</th>
                                        <th style={{ padding: '0.5rem' }}>Expiration</th>
                                        <th style={{ padding: '0.5rem' }}>Status</th>
                                        <th style={{ padding: '0.5rem', textAlign: 'right' }}>Actions</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {group.subLicenses.map((lic, idx) => {
                                        const isExpired = new Date(lic.expiresAt).getTime() < Date.now();
                                        const isRevoked = lic.status === 'revoked';
                                        const daysLeft = Math.max(0, Math.ceil((new Date(lic.expiresAt).getTime() - Date.now()) / 86400000));

                                        return (
                                          <tr key={lic.id || lic.licenseKey} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)', opacity: (isExpired || isRevoked) ? 0.6 : 1 }}>
                                            <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.76rem' }}>
                                              #{idx + 1}
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem' }}>
                                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem' }}>
                                                <code style={{
                                                  fontSize: '0.78rem',
                                                  background: 'rgba(0, 0, 0, 0.45)',
                                                  padding: '0.2rem 0.45rem',
                                                  borderRadius: '4px',
                                                  color: 'var(--accent-cyan)',
                                                  fontFamily: 'monospace'
                                                }}>
                                                  {lic.licenseKey}
                                                </code>
                                                <button
                                                  onClick={(e) => {
                                                    e.stopPropagation();
                                                    handleCopyKey(lic.licenseKey);
                                                  }}
                                                  title="Copy license key"
                                                  style={{
                                                    background: 'none',
                                                    border: 'none',
                                                    cursor: 'pointer',
                                                    color: copiedKey === lic.licenseKey ? 'var(--status-secure)' : 'var(--text-muted)',
                                                    padding: '2px'
                                                  }}
                                                >
                                                  {copiedKey === lic.licenseKey ? <Check size={13} /> : <Copy size={13} />}
                                                </button>
                                              </div>
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-secondary)' }}>
                                              {lic.contactEmail ? (
                                                <div>
                                                  <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{lic.contactName || 'Primary Admin'}</div>
                                                  <div style={{ color: '#38bdf8', fontSize: '0.72rem' }}>{lic.contactEmail}</div>
                                                </div>
                                              ) : (
                                                <span style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>Shared tenant admin</span>
                                              )}
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-primary)', fontWeight: 500 }}>
                                              {(() => {
                                                const licMachines = group.machines.filter(m => (m.licenseKey || '').trim().toUpperCase() === (lic.licenseKey || '').trim().toUpperCase());
                                                return (
                                                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                                    <span style={{ fontWeight: 600, color: licMachines.length > 0 ? '#38bdf8' : 'var(--text-primary)' }}>
                                                      {licMachines.length} / {lic.seats ? `${lic.seats.toLocaleString()} Seats` : 'N/A'}
                                                    </span>
                                                    {licMachines.length > 0 ? (
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
                                                    ) : (
                                                      <span style={{
                                                        fontSize: '0.7rem',
                                                        color: 'var(--text-muted)',
                                                        background: 'rgba(255, 255, 255, 0.04)',
                                                        padding: '0.1rem 0.35rem',
                                                        borderRadius: '3px'
                                                      }}>
                                                        Available
                                                      </span>
                                                    )}
                                                  </div>
                                                );
                                              })()}
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-secondary)' }}>
                                              <div>{lic.expiresAt ? new Date(lic.expiresAt).toLocaleDateString() : 'N/A'}</div>
                                              {!isExpired && !isRevoked && (
                                                <div style={{ fontSize: '0.72rem', color: daysLeft < 7 ? 'var(--status-warning)' : 'var(--text-muted)' }}>
                                                  {daysLeft} days remaining
                                                </div>
                                              )}
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem' }}>
                                              {isRevoked ? (
                                                <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                                                  Revoked
                                                </span>
                                              ) : isExpired ? (
                                                <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
                                                  Expired
                                                </span>
                                              ) : (
                                                <span style={{ fontSize: '0.72rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.3)' }}>
                                                  Active
                                                </span>
                                              )}
                                            </td>
                                            <td style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }}>
                                              <div style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center', justifyContent: 'flex-end' }}>
                                                {!isRevoked && (
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      handleSendLicenseEmail(lic);
                                                    }}
                                                    disabled={emailSendingKey === lic.licenseKey}
                                                    title={`Send key to ${lic.contactEmail || 'contact'} from License@Quarkshield.ai`}
                                                    style={{
                                                      background: 'rgba(56, 189, 248, 0.1)',
                                                      border: '1px solid rgba(56, 189, 248, 0.35)',
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
                                                    <Mail size={11} />
                                                    {emailSendingKey === lic.licenseKey ? 'Sending...' : 'Email Key'}
                                                  </button>
                                                )}
                                                {!isRevoked && (
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      handleRevokeLicense(lic.id, lic.licenseKey);
                                                    }}
                                                    disabled={revokingId === lic.id}
                                                    title="Revoke License"
                                                    style={{
                                                      background: 'none',
                                                      border: '1px solid rgba(239, 68, 68, 0.3)',
                                                      color: '#f87171',
                                                      borderRadius: '4px',
                                                      padding: '0.25rem 0.55rem',
                                                      fontSize: '0.72rem',
                                                      cursor: 'pointer'
                                                    }}
                                                  >
                                                    {revokingId === lic.id ? 'Revoking...' : 'Revoke'}
                                                  </button>
                                                )}
                                              </div>
                                            </td>
                                          </tr>
                                        );
                                      })}
                                    </tbody>
                                  </table>
                                </div>
                              </div>

                              {/* Enrolled Workstations Consuming Seats Card */}
                              <div style={{
                                marginTop: '1rem',
                                background: 'rgba(255, 255, 255, 0.02)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                borderRadius: '8px',
                                padding: '1rem',
                                boxShadow: 'inset 0 2px 6px rgba(0, 0, 0, 0.3)'
                              }}>
                                {(() => {
                                  const isWorkstationsCollapsed = !!collapsedWorkstations[group.orgKey];
                                  return (
                                    <>
                                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: isWorkstationsCollapsed ? 0 : '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                                        <div 
                                          onClick={() => toggleWorkstationsCollapse(group.orgKey)}
                                          style={{ fontSize: '0.8rem', fontWeight: 600, color: '#38bdf8', display: 'flex', gap: '0.45rem', alignItems: 'center', letterSpacing: '0.3px', cursor: 'pointer' }}
                                        >
                                          <ChevronRight
                                            size={14}
                                            style={{
                                              transform: isWorkstationsCollapsed ? 'rotate(0deg)' : 'rotate(90deg)',
                                              transition: 'transform 0.2s ease',
                                              color: '#38bdf8'
                                            }}
                                          />
                                          <Laptop size={14} />
                                          <span>ENROLLED WORKSTATIONS CONSUMING SEATS ({group.machines.length} Active Device{group.machines.length !== 1 ? 's' : ''})</span>
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                                          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                                            <span>Seat Utilization: <strong style={{ color: group.usedSeats > 0 ? '#38bdf8' : 'var(--text-secondary)' }}>{group.usedSeats} / {group.totalSeats} ({Math.round((group.usedSeats / Math.max(1, group.totalSeats)) * 100)}%)</strong></span>
                                            {group.macCount > 0 && <span style={{ color: '#38bdf8' }}>• {group.macCount} macOS</span>}
                                            {group.winCount > 0 && <span style={{ color: '#c084fc' }}>• {group.winCount} Windows</span>}
                                            {group.linuxCount > 0 && <span style={{ color: '#4ade80' }}>• {group.linuxCount} Linux</span>}
                                          </div>
                                          <button
                                            onClick={() => toggleWorkstationsCollapse(group.orgKey)}
                                            style={{
                                              background: 'rgba(255, 255, 255, 0.04)',
                                              border: '1px solid rgba(255, 255, 255, 0.1)',
                                              borderRadius: '4px',
                                              color: 'var(--text-secondary)',
                                              padding: '0.2rem 0.5rem',
                                              fontSize: '0.72rem',
                                              cursor: 'pointer',
                                              display: 'inline-flex',
                                              alignItems: 'center',
                                              gap: '0.25rem'
                                            }}
                                          >
                                            {isWorkstationsCollapsed ? <ChevronDown size={12} /> : <ChevronUp size={12} />}
                                            {isWorkstationsCollapsed ? 'Expand Devices' : 'Collapse Devices'}
                                          </button>
                                        </div>
                                      </div>

                                      {!isWorkstationsCollapsed && (
                                        group.machines.length > 0 ? (
                                          <div style={{ overflowX: 'auto' }}>
                                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                                              <thead>
                                                <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', textAlign: 'left', color: 'var(--text-muted)', fontSize: '0.74rem', textTransform: 'uppercase' }}>
                                                  <th style={{ padding: '0.5rem' }}>Device Hostname</th>
                                                  <th style={{ padding: '0.5rem' }}>Platform / OS</th>
                                                  <th style={{ padding: '0.5rem' }}>IP Address</th>
                                                  <th style={{ padding: '0.5rem' }}>Active License Key</th>
                                                  <th style={{ padding: '0.5rem' }}>PQC Risk Score</th>
                                                  <th style={{ padding: '0.5rem' }}>Agent Status</th>
                                                  <th style={{ padding: '0.5rem', textAlign: 'right' }}>Last Seen</th>
                                                </tr>
                                              </thead>
                                              <tbody>
                                                {group.machines.map(m => {
                                                  const isMac = (m.os || '').toLowerCase().includes('darwin') || (m.os || '').toLowerCase().includes('mac');
                                                  const isWin = (m.os || '').toLowerCase().includes('win');

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
                                                          <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                                                            {m.hostname}
                                                          </span>
                                                        </div>
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
                                                      <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '0.78rem' }}>
                                                        {m.ip || '127.0.0.1'}
                                                      </td>
                                                      <td style={{ padding: '0.6rem 0.5rem' }}>
                                                        <code style={{
                                                          fontSize: '0.74rem',
                                                          background: 'rgba(0, 0, 0, 0.4)',
                                                          padding: '0.15rem 0.4rem',
                                                          borderRadius: '3px',
                                                          color: 'var(--accent-cyan)',
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
                                                          background: (m.quantumRiskScore || 0) >= 80 ? 'rgba(239, 68, 68, 0.2)' : (m.quantumRiskScore || 0) >= 50 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                                                          color: (m.quantumRiskScore || 0) >= 80 ? '#f87171' : (m.quantumRiskScore || 0) >= 50 ? '#fbbf24' : '#4ade80',
                                                          border: (m.quantumRiskScore || 0) >= 80 ? '1px solid rgba(239, 68, 68, 0.35)' : (m.quantumRiskScore || 0) >= 50 ? '1px solid rgba(245, 158, 11, 0.35)' : '1px solid rgba(34, 197, 94, 0.35)'
                                                        }}>
                                                          {m.quantumRiskScore || 0}/100 ({m.riskLevel ? m.riskLevel.toUpperCase() : 'SECURE'})
                                                        </span>
                                                      </td>
                                                      <td style={{ padding: '0.6rem 0.5rem' }}>
                                                        <span style={{
                                                          fontSize: '0.72rem',
                                                          padding: '0.15rem 0.4rem',
                                                          borderRadius: '4px',
                                                          background: m.status === 'online' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(255, 255, 255, 0.06)',
                                                          color: m.status === 'online' ? '#4ade80' : 'var(--text-muted)',
                                                          border: m.status === 'online' ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)',
                                                          display: 'inline-flex',
                                                          alignItems: 'center',
                                                          gap: '0.3rem'
                                                        }}>
                                                          <span style={{
                                                            width: '6px',
                                                            height: '6px',
                                                            borderRadius: '50%',
                                                            background: m.status === 'online' ? '#4ade80' : 'var(--text-muted)',
                                                            boxShadow: m.status === 'online' ? '0 0 6px #4ade80' : 'none'
                                                          }} />
                                                          {m.status === 'online' ? 'Online' : 'Offline'}
                                                        </span>
                                                      </td>
                                                      <td style={{ padding: '0.6rem 0.5rem', textAlign: 'right', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                                                        {m.lastSeen ? new Date(m.lastSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Recently'}
                                                      </td>
                                                    </tr>
                                                  );
                                                })}
                                              </tbody>
                                            </table>
                                          </div>
                                        ) : (
                                          <div style={{
                                            padding: '1.25rem',
                                            textAlign: 'center',
                                            color: 'var(--text-muted)',
                                            background: 'rgba(255, 255, 255, 0.01)',
                                            borderRadius: '6px',
                                            border: '1px dashed rgba(255, 255, 255, 0.08)',
                                            fontSize: '0.8rem'
                                          }}>
                                            No endpoint machines currently enrolled for {group.tenantName}. Launch QuarkShield Desktop Scanner on Mac, Windows, or Linux and scan with the license key above to automatically register endpoints.
                                          </div>
                                        )
                                      )}
                                    </>
                                  );
                                })()}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}

                  {filteredLicenseGroups.length === 0 && (
                    <tr>
                      <td colSpan={9} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                        {licenseFilter ? 'No organizations or sub-licenses matching your search.' : 'No partner or corporate licenses issued yet. Use the form above to issue a new license key.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Super Admin Platform Operators & Control Plane User Registry */}
      {activeSubTab === 'users' && (
        <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Toast Notification */}
          {opToast && (
            <div style={{
              position: 'fixed',
              top: '24px',
              right: '24px',
              background: 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
              color: '#ffffff',
              padding: '0.75rem 1.25rem',
              borderRadius: '8px',
              boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              zIndex: 10000,
              fontSize: '0.85rem',
              fontWeight: 600
            }}>
              <CheckCircle2 size={16} />
              <span>{opToast}</span>
            </div>
          )}

          {/* Architectural Privilege Notice */}
          <div className="glass-panel" style={{
            padding: '1.15rem 1.5rem',
            background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.08) 0%, rgba(15, 23, 42, 0.6) 100%)',
            border: '1px solid rgba(14, 165, 233, 0.25)',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: '10px',
                background: 'rgba(14, 165, 233, 0.15)',
                border: '1px solid rgba(14, 165, 233, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <ShieldCheck size={22} color="#38bdf8" />
              </div>
              <div>
                <h4 style={{ margin: 0, fontSize: '0.98rem', color: '#e0f2fe', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  Platform Operators & Central Control Plane Directory
                  <span style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', fontWeight: 700, border: '1px solid rgba(56, 189, 248, 0.35)' }}>
                    SUPER ADMIN ACCESS ONLY
                  </span>
                </h4>
                <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  This registry strictly governs internal QuarkShield platform operators, SecOps leads, and Tier-3 support engineers with root control plane privileges. 
                  <strong style={{ color: '#ffffff' }}> Tenant end-users are self-managed</strong> by customers independently inside their private tenant workspaces under the <em>Team & 2FA Policies</em> tab.
                </p>
              </div>
            </div>

            {onMirrorTenant && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setActiveSubTab('registry')}
                  style={{
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.8rem',
                    background: 'rgba(234, 179, 8, 0.12)',
                    color: '#facc15',
                    border: '1px solid rgba(234, 179, 8, 0.35)',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontWeight: 600
                  }}
                >
                  <Eye size={13} /> Open Tenant Support Mirror
                </button>
              </div>
            )}
          </div>

          {/* Security Metrics Grid */}
          <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>ACTIVE PLATFORM OPERATORS</h3>
                <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>{operators.length}</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  {operators.filter(o => o.role === 'root_admin').length} Root • {operators.filter(o => o.role === 'secops_lead').length} SecOps • {operators.filter(o => o.role === 'support_engineer').length} Support
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--accent-cyan)' }}>
                <Users size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>2FA / MFA ENFORCEMENT</h3>
                <div className="metric-value" style={{ color: '#4ade80' }}>100%</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Hardware FIDO2 & TOTP Enforced
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#4ade80' }}>
                <Lock size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>PQC HANDSHAKE AUDIT</h3>
                <div className="metric-value" style={{ color: '#38bdf8' }}>FIPS 203</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  ML-KEM-768 Hybrid Protocol Active
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#38bdf8' }}>
                <Activity size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>SUPPORT MIRROR AUTHORITY</h3>
                <div className="metric-value" style={{ color: '#facc15' }}>TIER-3+</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Live Diagnostics Impersonation
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#facc15' }}>
                <Eye size={24} />
              </div>
            </div>
          </div>

          {/* Search, Filters, and Add Operator Bar */}
          <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: '300px' }}>
                <div style={{ position: 'relative', flex: 1, maxWidth: '380px' }}>
                  <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search operators by name, email, or role..."
                    value={operatorSearch}
                    onChange={(e) => setOperatorSearch(e.target.value)}
                    style={{
                      width: '100%',
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid var(--border-normal)',
                      borderRadius: '6px',
                      padding: '0.5rem 0.75rem 0.5rem 2.2rem',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  />
                </div>

                <select
                  value={operatorRoleFilter}
                  onChange={(e) => setOperatorRoleFilter(e.target.value as any)}
                  style={{
                    background: 'rgba(255, 255, 255, 0.04)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-normal)',
                    borderRadius: '6px',
                    padding: '0.5rem 0.75rem',
                    fontSize: '0.85rem',
                    outline: 'none'
                  }}
                >
                  <option value="all">All Roles ({operators.length})</option>
                  <option value="root_admin">Root Master Admins</option>
                  <option value="secops_lead">Platform SecOps Leads</option>
                  <option value="support_engineer">Tier-3 Support Engineers</option>
                  <option value="compliance_auditor">SOC2 / FedRAMP Auditors</option>
                </select>
              </div>

              <button
                type="button"
                onClick={() => setShowAddOperatorModal(true)}
                style={{
                  background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.5rem 1.15rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  boxShadow: '0 4px 12px rgba(2, 132, 199, 0.35)',
                  transition: 'all 0.15s'
                }}
              >
                <Plus size={15} /> Invite Platform Operator
              </button>
            </div>

            {/* Operators Table */}
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-normal)', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ background: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--border-normal)', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>OPERATOR / IDENTITY</th>
                    <th style={{ padding: '0.75rem 1rem' }}>CONTROL PLANE ROLE & SCOPE</th>
                    <th style={{ padding: '0.75rem 1rem' }}>2FA / MFA SECURITY</th>
                    <th style={{ padding: '0.75rem 1rem' }}>LAST CONSOLE ACTIVITY</th>
                    <th style={{ padding: '0.75rem 1rem' }}>STATUS</th>
                    <th style={{ padding: '0.75rem 1rem', textAlign: 'center' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredOperators.map(op => {
                    const initials = op.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) || 'OP';
                    const isRoot = op.role === 'root_admin';
                    const isSecOps = op.role === 'secops_lead';
                    const isSupport = op.role === 'support_engineer';

                    const roleBadgeStyle = isRoot ? {
                      background: 'rgba(239, 68, 68, 0.15)',
                      color: '#f87171',
                      border: '1px solid rgba(239, 68, 68, 0.4)'
                    } : isSecOps ? {
                      background: 'rgba(6, 182, 212, 0.15)',
                      color: '#22d3ee',
                      border: '1px solid rgba(6, 182, 212, 0.4)'
                    } : isSupport ? {
                      background: 'rgba(245, 158, 11, 0.15)',
                      color: '#fbbf24',
                      border: '1px solid rgba(245, 158, 11, 0.4)'
                    } : {
                      background: 'rgba(16, 185, 129, 0.15)',
                      color: '#34d399',
                      border: '1px solid rgba(16, 185, 129, 0.4)'
                    };

                    return (
                      <tr key={op.id} style={{ borderBottom: '1px solid var(--border-normal)', transition: 'background-color 0.15s' }}>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            <div style={{
                              width: '36px',
                              height: '36px',
                              borderRadius: '50%',
                              background: isRoot ? 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                              color: '#ffffff',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 700,
                              fontSize: '0.75rem',
                              flexShrink: 0
                            }}>
                              {initials}
                            </div>
                            <div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                <strong style={{ color: 'var(--text-primary)', fontSize: '0.88rem' }}>{op.name}</strong>
                                {op.isRootOwner && (
                                  <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.35rem', borderRadius: '3px', background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5', fontWeight: 700, border: '1px solid rgba(239, 68, 68, 0.4)' }}>
                                    PRIMARY ROOT
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                                {op.email}
                              </div>
                            </div>
                          </div>
                        </td>

                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                            <span style={{
                              padding: '0.15rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.74rem',
                              fontWeight: 700,
                              display: 'inline-block',
                              width: 'fit-content',
                              ...roleBadgeStyle
                            }}>
                              {op.roleDisplayName}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                              {op.accessScope}
                            </span>
                          </div>
                        </td>

                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                              <span style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                fontSize: '0.72rem',
                                color: '#4ade80',
                                background: 'rgba(34, 197, 94, 0.15)',
                                padding: '0.1rem 0.4rem',
                                borderRadius: '4px',
                                fontWeight: 700
                              }}>
                                <Lock size={10} /> MFA ENFORCED
                              </span>
                            </div>
                            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                              {op.mfaType}
                            </span>
                          </div>
                        </td>

                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                            {op.lastLogin.includes('T') ? new Date(op.lastLogin).toLocaleString() : op.lastLogin}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            IP: {op.lastIp}
                          </div>
                        </td>

                        <td style={{ padding: '0.75rem 1rem' }}>
                          {op.status === 'active' ? (
                            <span style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                              color: '#4ade80',
                              fontWeight: 700,
                              fontSize: '0.76rem',
                              background: 'rgba(34, 197, 94, 0.12)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px'
                            }}>
                              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#4ade80' }} />
                              ACTIVE
                            </span>
                          ) : (
                            <span style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                              color: '#fbbf24',
                              fontWeight: 700,
                              fontSize: '0.76rem',
                              background: 'rgba(245, 158, 11, 0.12)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px'
                            }}>
                              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#fbbf24' }} />
                              SUSPENDED
                            </span>
                          )}
                        </td>

                        <td style={{ padding: '0.75rem 1rem', textAlign: 'center' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.35rem', flexWrap: 'wrap' }}>
                            <select
                              value={op.role}
                              disabled={op.isRootOwner}
                              onChange={(e) => handleChangeOperatorRole(op.id, e.target.value as any)}
                              title={op.isRootOwner ? 'Primary Root role cannot be altered' : 'Modify Control Plane Role'}
                              style={{
                                background: 'rgba(0,0,0,0.35)',
                                color: op.isRootOwner ? 'var(--text-muted)' : 'var(--text-primary)',
                                border: '1px solid var(--border-normal)',
                                borderRadius: '4px',
                                padding: '0.3rem 0.5rem',
                                fontSize: '0.75rem',
                                outline: 'none',
                                cursor: op.isRootOwner ? 'not-allowed' : 'pointer'
                              }}
                            >
                              <option value="root_admin">Root Master Admin</option>
                              <option value="secops_lead">SecOps Lead</option>
                              <option value="support_engineer">Tier-3 Support</option>
                              <option value="compliance_auditor">Compliance Auditor</option>
                            </select>

                            <button
                              type="button"
                              onClick={() => setOperatorToReset2FA(op)}
                              title={`Generate emergency 2FA reset token for ${op.email}`}
                              style={{
                                background: 'rgba(255,255,255,0.05)',
                                color: 'var(--text-secondary)',
                                border: '1px solid var(--border-normal)',
                                borderRadius: '4px',
                                padding: '0.3rem 0.55rem',
                                fontSize: '0.75rem',
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.3rem'
                              }}
                            >
                              <Key size={12} /> Reset 2FA
                            </button>

                            <button
                              type="button"
                              disabled={op.isRootOwner}
                              onClick={() => handleToggleOperatorStatus(op.id)}
                              title={op.isRootOwner ? 'Primary Root cannot be suspended' : op.status === 'active' ? 'Suspend operator access' : 'Reactivate operator'}
                              style={{
                                background: op.status === 'active' ? 'rgba(245, 158, 11, 0.12)' : 'rgba(34, 197, 94, 0.12)',
                                color: op.status === 'active' ? '#fbbf24' : '#4ade80',
                                border: `1px solid ${op.status === 'active' ? 'rgba(245, 158, 11, 0.35)' : 'rgba(34, 197, 94, 0.35)'}`,
                                borderRadius: '4px',
                                padding: '0.3rem 0.55rem',
                                fontSize: '0.75rem',
                                cursor: op.isRootOwner ? 'not-allowed' : 'pointer',
                                opacity: op.isRootOwner ? 0.4 : 1,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '0.25rem'
                              }}
                            >
                              {op.status === 'active' ? <Lock size={12} /> : <Unlock size={12} />}
                              {op.status === 'active' ? 'Suspend' : 'Activate'}
                            </button>

                            <button
                              type="button"
                              disabled={op.isRootOwner}
                              onClick={() => setOperatorToDelete(op)}
                              title={op.isRootOwner ? 'Primary Root cannot be removed' : `Revoke & Remove ${op.email}`}
                              style={{
                                background: 'rgba(239, 68, 68, 0.12)',
                                color: '#f87171',
                                border: '1px solid rgba(239, 68, 68, 0.35)',
                                borderRadius: '4px',
                                padding: '0.3rem 0.5rem',
                                fontSize: '0.75rem',
                                cursor: op.isRootOwner ? 'not-allowed' : 'pointer',
                                opacity: op.isRootOwner ? 0.4 : 1
                              }}
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}

                  {filteredOperators.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                        No platform operators found matching "{operatorSearch}".
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Super Admin Exclusive: Platform Stack SBOM (quarkshield.ai) */}
      {activeSubTab === 'platform_sbom' && (
        <div style={{ marginTop: '1.5rem' }}>
          <SbomInventory tenant="quarkshield.ai" isSuperAdmin={true} apiUrl="" />
        </div>
      )}

      {/* MODAL: Invite Platform Operator */}
      {showAddOperatorModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '520px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid rgba(14, 165, 233, 0.4)',
            borderRadius: '12px',
            boxShadow: '0 20px 40px rgba(0,0,0,0.6)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Users size={18} color="var(--accent-cyan)" /> Invite Platform Operator
              </h3>
              <button
                type="button"
                onClick={() => setShowAddOperatorModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleAddOperator} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 600 }}>
                  Operator Full Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Sridhar GS or Sarah Jenkins"
                  value={newOpName}
                  onChange={(e) => setNewOpName(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid var(--border-normal)',
                    borderRadius: '6px',
                    padding: '0.55rem 0.85rem',
                    color: 'var(--text-primary)',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 600 }}>
                  Corporate / Super Admin Email *
                </label>
                <input
                  type="email"
                  required
                  placeholder="e.g. admin@quarkshield.ai or designated root email"
                  value={newOpEmail}
                  onChange={(e) => setNewOpEmail(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid var(--border-normal)',
                    borderRadius: '6px',
                    padding: '0.55rem 0.85rem',
                    color: 'var(--text-primary)',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Control Plane Role *
                  </label>
                  <select
                    value={newOpRole}
                    onChange={(e) => setNewOpRole(e.target.value as any)}
                    style={{
                      width: '100%',
                      background: '#0f172a',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-normal)',
                      borderRadius: '6px',
                      padding: '0.55rem 0.75rem',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  >
                    <option value="root_admin">Root Master Admin</option>
                    <option value="secops_lead">Platform SecOps Lead</option>
                    <option value="support_engineer">Tier-3 Support Escalations</option>
                    <option value="compliance_auditor">SOC2 / FedRAMP Auditor</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Required 2FA Method *
                  </label>
                  <select
                    value={newOpMfaType}
                    onChange={(e) => setNewOpMfaType(e.target.value as any)}
                    style={{
                      width: '100%',
                      background: '#0f172a',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-normal)',
                      borderRadius: '6px',
                      padding: '0.55rem 0.75rem',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  >
                    <option value="Hardware Security Key (YubiKey)">Hardware Key (YubiKey)</option>
                    <option value="FIDO2 / WebAuthn">FIDO2 / Touch ID / WebAuthn</option>
                    <option value="TOTP Authenticator">TOTP (Google/Microsoft Auth)</option>
                  </select>
                </div>
              </div>

              {/* Role Scope Preview */}
              <div style={{
                background: 'rgba(255, 255, 255, 0.03)',
                borderRadius: '8px',
                padding: '0.85rem',
                border: '1px solid var(--border-normal)',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)'
              }}>
                <strong style={{ color: '#ffffff', display: 'block', marginBottom: '0.25rem' }}>
                  Role Privileges Summary:
                </strong>
                {newOpRole === 'root_admin' && (
                  <span>Full control plane authority: physical tenant provisioning, server port allocation, master license key generation, and operator management.</span>
                )}
                {newOpRole === 'secops_lead' && (
                  <span>Governance of PQC algorithms (ML-KEM, ML-DSA, SLH-DSA), hybrid TLS handshakes, and cryptographic risk scoring policies.</span>
                )}
                {newOpRole === 'support_engineer' && (
                  <span>Full Support Mirror access into customer portals, machine synchronization inspection, and diagnostic troubleshooting.</span>
                )}
                {newOpRole === 'compliance_auditor' && (
                  <span>Read-only attestation reporting, SOC2 / FedRAMP evidence generation, and cryptographic certificate chain auditing.</span>
                )}
              </div>

              {/* Enforce 2FA Disclaimer */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                fontSize: '0.8rem',
                color: '#4ade80',
                background: 'rgba(34, 197, 94, 0.1)',
                padding: '0.5rem 0.75rem',
                borderRadius: '6px',
                border: '1px solid rgba(34, 197, 94, 0.25)'
              }}>
                <Lock size={14} />
                <span>Mandatory 2FA Enrollment enforced on initial console activation.</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowAddOperatorModal(false)}
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid var(--border-normal)',
                    color: 'var(--text-secondary)',
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
                  style={{
                    background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
                    border: 'none',
                    color: '#ffffff',
                    borderRadius: '6px',
                    padding: '0.5rem 1.25rem',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    boxShadow: '0 4px 12px rgba(2, 132, 199, 0.35)'
                  }}
                >
                  Issue Operator Invitation
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Reset 2FA Confirmation */}
      {operatorToReset2FA && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '460px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid rgba(245, 158, 11, 0.4)',
            borderRadius: '12px'
          }}>
            <h3 style={{ margin: '0 0 0.75rem 0', color: '#fef08a', fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Key size={18} color="#facc15" /> Reset Operator 2FA Security Token
            </h3>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Are you sure you want to invalidate the active 2FA authenticator for <strong style={{ color: '#ffffff' }}>{operatorToReset2FA.email}</strong>? 
              Upon confirmation, the operator will be required to scan a fresh QR code and re-bind their authenticator app on their next login.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setOperatorToReset2FA(null)}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid var(--border-normal)',
                  color: 'var(--text-secondary)',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.85rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmReset2FA}
                style={{
                  background: 'linear-gradient(135deg, #d97706 0%, #b45309 100%)',
                  border: 'none',
                  color: '#ffffff',
                  borderRadius: '6px',
                  padding: '0.5rem 1.15rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Confirm 2FA Invalidation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: Delete Operator Confirmation */}
      {operatorToDelete && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '460px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '12px'
          }}>
            <h3 style={{ margin: '0 0 0.75rem 0', color: '#fca5a5', fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Trash2 size={18} color="#f87171" /> Revoke Platform Operator Access
            </h3>
            <p style={{ margin: '0 0 1rem 0', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Are you sure you want to permanently revoke control plane access for <strong style={{ color: '#ffffff' }}>{operatorToDelete.name} ({operatorToDelete.email})</strong>? 
              All active sessions will be terminated immediately.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setOperatorToDelete(null)}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid var(--border-normal)',
                  color: 'var(--text-secondary)',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.85rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDeleteOperator}
                style={{
                  background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
                  border: 'none',
                  color: '#ffffff',
                  borderRadius: '6px',
                  padding: '0.5rem 1.15rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Revoke Operator
              </button>
            </div>
          </div>
        </div>
      )}

      {/* User Deletion Confirmation Modal */}
      {userToDelete && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '520px',
            width: '100%',
            padding: '1.75rem',
            background: 'var(--bg-card)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem',
            boxShadow: '0 12px 40px rgba(239, 68, 68, 0.2)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{ background: 'rgba(239, 68, 68, 0.15)', padding: '0.6rem', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <AlertTriangle size={24} color="var(--accent-red)" />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.2rem', color: '#ffffff', fontWeight: 700 }}>
                  Confirm Permanent User Deletion
                </h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  This action cannot be undone.
                </span>
              </div>
            </div>

            <div style={{ background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <p style={{ margin: 0, fontSize: '0.9rem', color: '#ffffff', lineHeight: '1.5' }}>
                Are you sure you want to delete user <strong>{userToDelete.email}</strong> {userToDelete.company ? `(${userToDelete.company})` : ''}?
              </p>
              <ul style={{ margin: '0.5rem 0 0 1.25rem', padding: 0, fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                <li>Permanently deletes the user account record and session auth keys.</li>
                <li>Wipes all registered assets, compliance reports, and CMDB inventory data.</li>
                <li><strong>Stops and destroys isolated Docker containers:</strong> <code>quarkshield-app-{getSanitizedPrefix(userToDelete.email)}</code> & <code>quarkshield-db-{getSanitizedPrefix(userToDelete.email)}</code>.</li>
                <li>Permanently deletes the tenant client directory on the host server.</li>
              </ul>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
              <button
                onClick={() => setUserToDelete(null)}
                disabled={isDeletingUser}
                className="btn-secondary"
                style={{ padding: '0.5rem 1.2rem', fontSize: '0.88rem' }}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDeleteUser}
                disabled={isDeletingUser}
                className="btn-primary"
                style={{
                  padding: '0.5rem 1.2rem',
                  fontSize: '0.88rem',
                  background: 'linear-gradient(to right, #ef4444, #dc2626)',
                  color: '#ffffff',
                  fontWeight: 600
                }}
              >
                {isDeletingUser ? 'Tearing Down Environment...' : 'Confirm Permanent Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL: CORPORATE & PARTNER ONBOARDING (Inside Admin Panel) */}
      {/* ========================================================================= */}
      {showOnboardModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.5rem'
        }}>
          <div className="glass-panel" style={{
            background: 'var(--bg-sidebar)',
            maxWidth: '620px',
            width: '100%',
            borderRadius: '12px',
            border: '1px solid rgba(0, 242, 254, 0.35)',
            boxShadow: '0 16px 48px rgba(0, 0, 0, 0.8)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Building size={20} color="var(--accent-cyan)" />
                <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: '#ffffff' }}>
                  Onboard Corporate / Partner Fleet
                </h3>
              </div>
              <button
                onClick={() => {
                  setShowOnboardModal(false);
                  setOnboardSuccessData(null);
                  setOnboardError(null);
                }}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '1.5rem', overflowY: 'auto', maxHeight: '75vh' }}>
              {onboardSuccessData ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                  <div style={{
                    padding: '1rem',
                    borderRadius: '8px',
                    background: 'rgba(0, 255, 136, 0.1)',
                    border: '1px solid var(--status-secure)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem'
                  }}>
                    <CheckCircle2 size={24} color="var(--status-secure)" />
                    <div>
                      <h4 style={{ margin: '0 0 0.2rem 0', color: 'var(--status-secure)', fontSize: '1.05rem' }}>
                        Tenant Workspace Provisioned!
                      </h4>
                      <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        Isolated container workspace created for <strong>{onboardSuccessData.displayName}</strong>.
                      </p>
                    </div>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.4)', padding: '1.2rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.8rem', fontSize: '0.9rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Tenant Subdomain: </span>
                      <a href={onboardSuccessData.subdomain} target="_blank" rel="noreferrer" style={{ color: 'var(--accent-cyan)', fontWeight: 600, textDecoration: 'none' }}>
                        {onboardSuccessData.subdomain} <ExternalLink size={14} style={{ display: 'inline' }} />
                      </a>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Cryptographic Master License Key: </span>
                      <code style={{ color: '#ffffff', wordBreak: 'break-all', display: 'block', marginTop: '0.3rem', padding: '0.4rem 0.6rem', background: 'rgba(255,255,255,0.05)', borderRadius: '4px' }}>{onboardSuccessData.licenseKey}</code>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Subscription Tier: </span>
                      <span style={{ textTransform: 'uppercase', color: '#c084fc', fontWeight: 600 }}>{onboardSuccessData.tier}</span> ({onboardSuccessData.seats} authorized seats)
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>2FA Security Policy: </span>
                      <span style={{ color: 'var(--status-secure)', fontWeight: 600 }}>{onboardSuccessData.twoFactorPolicy}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Initial Admin: </span>
                      <span style={{ color: '#ffffff' }}>{onboardSuccessData.adminUser?.email}</span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                    <button
                      onClick={() => {
                        setShowOnboardModal(false);
                        setOnboardSuccessData(null);
                      }}
                      className="btn-primary"
                      style={{ padding: '0.6rem 1.4rem', borderRadius: '7px', fontWeight: 700, cursor: 'pointer' }}
                    >
                      Done & Return to Registry
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleOnboardSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
                  <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
                    Provision an enterprise client organization, create dedicated database routing, and generate signed fleet activation tokens.
                  </p>

                  {onboardError && (
                    <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--status-vulnerable)', color: '#f87171', fontSize: '0.85rem' }}>
                      {onboardError}
                    </div>
                  )}

                  {/* Org Name */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                      Organization or Company Name *
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Acme Defense Labs"
                      value={onboardOrg}
                      onChange={(e) => setOnboardOrg(e.target.value)}
                      required
                      style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff' }}
                    />
                  </div>

                  {/* Subdomain */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                      Subdomain Prefix (https://&lt;prefix&gt;.quarkshield.ai)
                    </label>
                    <input
                      type="text"
                      placeholder="acme"
                      value={onboardSubdomain}
                      onChange={(e) => setOnboardSubdomain(e.target.value)}
                      style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}
                    />
                  </div>

                  {/* Admin Work Email */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                      Administrator Work Email *
                    </label>
                    <input
                      type="email"
                      placeholder="admin@acme.com"
                      value={onboardAdminEmail}
                      onChange={(e) => setOnboardAdminEmail(e.target.value)}
                      required
                      style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff' }}
                    />
                  </div>

                  {/* Tier & Seats */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                        Subscription Tier
                      </label>
                      <select
                        value={onboardTier}
                        onChange={(e) => setOnboardTier(e.target.value as any)}
                        style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff' }}
                      >
                        <option value="corporate">Corporate Fleet</option>
                        <option value="partner">Managed Security Partner (MSSP)</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                        Endpoint Seat Quota
                      </label>
                      <input
                        type="number"
                        min="5"
                        max="50000"
                        value={onboardSeats}
                        onChange={(e) => setOnboardSeats(parseInt(e.target.value, 10) || 50)}
                        style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff' }}
                      />
                    </div>
                  </div>

                  {/* 2FA Security Policy */}
                  <div>
                    <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-secondary)' }}>
                      MFA / 2FA Enforcement Policy
                    </label>
                    <select
                      value={onboard2FAPolicy}
                      onChange={(e) => setOnboard2FAPolicy(e.target.value as any)}
                      style={{ width: '100%', padding: '0.65rem 0.85rem', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px', color: '#ffffff' }}
                    >
                      <option value="admins_only">Mandatory for Administrators Only (Recommended)</option>
                      <option value="mandatory">Mandatory for All Tenant Users</option>
                      <option value="optional">Optional / Self-Enrolled</option>
                    </select>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={() => setShowOnboardModal(false)}
                      className="btn-secondary"
                      style={{ padding: '0.65rem 1.25rem', borderRadius: '6px' }}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={onboardingLoading}
                      className="btn-primary"
                      style={{ padding: '0.65rem 1.5rem', borderRadius: '6px', fontWeight: 700 }}
                    >
                      {onboardingLoading ? 'Provisioning Workspace...' : 'Instantiate Tenant & Issue Key'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
};

