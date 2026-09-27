import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  Terminal,
  Download,
  ExternalLink,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Server,
  Laptop,
  Building,
  RefreshCw,
  Copy,
  Check,
  Shield,
  X,
  FileCode,
  Zap,
  Activity,
  Key,
  Lock,
  Eye,
  EyeOff,
  ShieldCheck,
  Calendar,
  Radio,
  Globe,
  Menu,
  ChevronDown,
  FileText,
  BookOpen,
  Briefcase,
  Users,
  LifeBuoy,
  Mail,
  MessageSquare,
  HelpCircle,
  Compass,
  Send,
  Sparkles,
  MapPin,
  Clock,
  ArrowUpRight,
  Layers,
  Code,
  Award,
  GitBranch,
  Presentation,
  LogOut,
  User,
  CreditCard,
  Star,
  ChevronUp,
  Cpu,
  Search,
  FileCheck
} from 'lucide-react';
import HelpFeedbackWidget from './HelpFeedbackWidget';
import { CryptographicPostureCard, calculatePostureMetrics, PostureMetrics } from './CryptographicPostureCard';

interface LandingPageProps {
  onLaunchConsole: (initialTab?: 'dashboard' | 'cbom' | 'tokens' | 'git' | 'admin' | 'planner', userEmail?: string) => void;
}

interface ProbeResultPreset {
  pqc: boolean;
  kx: string;
  tls: string;
  cipher: string;
  cert: string;
}

const FREE_EMAIL_PROVIDERS = [
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
  'icloud.com', 'aol.com', 'proton.me', 'protonmail.com',
  'gmx.com', 'live.com', 'msn.com'
];

const PROBE_PRESETS: Record<string, ProbeResultPreset> = {
  'cloudflare.com': { pqc: true, kx: 'X25519MLKEM768 (hybrid)', tls: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert: 'ECDSA P-256' },
  'google.com':     { pqc: true, kx: 'X25519MLKEM768 (hybrid)', tls: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert: 'ECDSA P-256' },
  'microsoft.com':  { pqc: false, kx: 'ECDHE secp384r1', tls: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert: 'RSA-2048' },
  'github.com':     { pqc: false, kx: 'ECDHE X25519', tls: 'TLS 1.3', cipher: 'TLS_AES_128_GCM_SHA256', cert: 'ECDSA P-256' },
  'apple.com':      { pqc: false, kx: 'ECDHE secp256r1', tls: 'TLS 1.3', cipher: 'TLS_CHACHA20_POLY1305_SHA256', cert: 'ECDSA P-256' },
  'amazon.com':     { pqc: false, kx: 'ECDHE secp256r1', tls: 'TLS 1.3', cipher: 'TLS_AES_128_GCM_SHA256', cert: 'RSA-2048' },
  'meta.com':       { pqc: false, kx: 'ECDHE X25519', tls: 'TLS 1.3', cipher: 'TLS_AES_128_GCM_SHA256', cert: 'ECDSA P-256' },
  'linkedin.com':   { pqc: false, kx: 'ECDHE secp384r1', tls: 'TLS 1.2', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', cert: 'RSA-2048' }
};

const SECTOR_BENCHMARKS = [
  { name: 'Healthcare & Life Sciences', short: 'Healthcare', meta: 'HIPAA · X25 Y5 Z7', x: 25, y: 5, z: 7 },
  { name: 'Defense & Aerospace', short: 'Defense & Aerospace', meta: 'CNSA 2.0 · X30 Y7 Z5', x: 30, y: 7, z: 5 },
  { name: 'Financial Services', short: 'Financial Services', meta: 'PCI · X10 Y4 Z7', x: 10, y: 4, z: 7 },
  { name: 'Corporate IP & Technology', short: 'Corporate IP / Tech', meta: 'SaaS · X15 Y3 Z7', x: 15, y: 3, z: 7 }
];

export const LandingPage: React.FC<LandingPageProps> = ({ onLaunchConsole }) => {
  // ---------------------------------------------------------
  // Public hero: anonymized "Sample Enterprise Fleet" posture (no real tenant data)
  // ---------------------------------------------------------
  // Anonymized "sample enterprise" posture for the public hero panel. The public
  // /api/cbom/fleet endpoint returns representative (not real-tenant) data.
  const [spinovationPosture, setSpinovationPosture] = useState<PostureMetrics>(() =>
    calculatePostureMetrics([], [], {
      totalAssets: 1284,
      quantumVuln: 517,
      hndlExposed: 143,
      configFindings: 38,
      pqcReady: 226,
      riskScore: 57
    })
  );

  useEffect(() => {
    fetch('/api/cbom/fleet')
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data && data.summary) {
          // Authoritative aggregate counts come from the endpoint's summary.
          setSpinovationPosture(calculatePostureMetrics([], data.machines || [], data.summary));
        } else if (data && data.assets && data.assets.length > 0) {
          setSpinovationPosture(calculatePostureMetrics(data.assets, data.machines || []));
        }
      })
      .catch(() => {});
  }, []);

  // ---------------------------------------------------------
  // Navigation & Resources Mega-Menu
  // ---------------------------------------------------------
  const [resDropdownOpen, setResDropdownOpen] = useState(false);
  const resDropdownRef = useRef<HTMLDivElement>(null);
  const resTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (resDropdownRef.current && !resDropdownRef.current.contains(e.target as Node)) {
        setResDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // ---------------------------------------------------------
  // Mosca Planner State
  // ---------------------------------------------------------
  const [plannerSector, setPlannerSector] = useState(SECTOR_BENCHMARKS[0]);
  const [sx, setSx] = useState(25);
  const [sy, setSy] = useState(5);
  const [sz, setSz] = useState(7);

  const selectSector = (s: typeof SECTOR_BENCHMARKS[0]) => {
    setPlannerSector(s);
    setSx(s.x);
    setSy(s.y);
    setSz(s.z);
  };

  const plannerDeficit = (sx + sy) - sz;
  const plannerIsBad = plannerDeficit > 0;
  const plannerOp = plannerDeficit > 0 ? '>' : (plannerDeficit === 0 ? '=' : '<');

  // ---------------------------------------------------------
  // Live Outbound TLS Probe State
  // ---------------------------------------------------------
  const [probeHostInput, setProbeHostInput] = useState('cloudflare.com');
  const [probing, setProbing] = useState(false);
  const [probeLogs, setProbeLogs] = useState<Array<{ cls: string; text: string }>>([
    { cls: 'muted', text: '$ quarkshield probe --host cloudflare.com --tls1.3' },
    { cls: 'muted', text: 'Ready. Enter a host and run a probe, or pick a preset above.' }
  ]);
  const [probeVerdict, setProbeVerdict] = useState<{ pqc: boolean; kx: string; cert: string; tls: string } | null>(null);
  const termBodyRef = useRef<HTMLDivElement>(null);

  const cleanHost = (raw: string) => {
    return (raw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  };

  const runProbe = (rawHost: string) => {
    if (probing) return;
    const host = cleanHost(rawHost);
    if (!host || host.indexOf('.') === -1) {
      setProbeLogs([
        { cls: 'muted', text: '$ quarkshield probe' },
        { cls: 'red', text: '! Enter a valid hostname, e.g. yourcompany.com' }
      ]);
      setProbeVerdict(null);
      return;
    }

    setProbing(true);
    setProbeHostInput(host);
    setProbeVerdict(null);

    const d = PROBE_PRESETS[host] || {
      pqc: false,
      kx: 'ECDHE X25519',
      tls: 'TLS 1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      cert: 'RSA-2048'
    };

    const tlsOld = d.tls === 'TLS 1.2';
    const seq = [
      { t: 0,    item: { cls: 'muted', text: `$ quarkshield probe --host ${host} --tls1.3 --pq` } },
      { t: 320,  item: { cls: 'muted', text: `→ resolving ${host} … 104.18.x.x` } },
      { t: 680,  item: { cls: 'muted', text: '→ TCP 443 connected · TLS handshake' } },
      { t: 1040, item: { cls: 'cyan',  text: '→ ClientHello  key_share = [X25519MLKEM768, X25519, secp256r1]' } },
      { t: 1480, item: { cls: tlsOld ? 'amber' : 'muted', text: `← ServerHello  ${d.tls}${tlsOld ? '  ⚠ no TLS 1.3' : ''} · ${d.cipher}` } },
      { t: 1860, item: { cls: d.pqc ? 'green' : 'red',   text: `← key_exchange  ${d.kx}${d.pqc ? '  ✓ quantum-safe' : '  ✕ classical'}` } },
      { t: 2180, item: { cls: 'muted', text: `← certificate   ${d.cert}${d.cert.indexOf('RSA') === 0 ? '  ⚠ Shor-vulnerable signature' : ''}` } },
      { t: 2460, item: { cls: 'muted', text: `→ analysis complete (${d.pqc ? '0' : (tlsOld ? '3' : '2')} findings)` } }
    ];

    setProbeLogs([]);
    seq.forEach((step) => {
      setTimeout(() => {
        setProbeLogs(prev => [...prev, step.item]);
        if (termBodyRef.current) {
          termBodyRef.current.scrollTop = termBodyRef.current.scrollHeight;
        }
      }, step.t);
    });

    setTimeout(() => {
      setProbeVerdict({ pqc: d.pqc, kx: d.kx, cert: d.cert, tls: d.tls });
      setProbing(false);
      if (termBodyRef.current) {
        termBodyRef.current.scrollTop = termBodyRef.current.scrollHeight;
      }
    }, 2900);
  };

  // ---------------------------------------------------------
  // Pricing Billing Switch
  // ---------------------------------------------------------
  const [isAnnualBilling, setIsAnnualBilling] = useState(false);

  // ---------------------------------------------------------
  // Copy Quick Install Command
  // ---------------------------------------------------------
  const [isCopiedInstall, setIsCopiedInstall] = useState(false);
  const copyInstallCmd = () => {
    const cmd = `# 1. Download the universal scanner\ncurl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner -o quarkshield-scanner\n# 2. Make it executable\nchmod +x quarkshield-scanner\n# 3. Launch the interactive dashboard (local-first, no data leaves the host)\n./quarkshield-scanner --server https://quarkshield.ai`;
    navigator.clipboard?.writeText(cmd).then(() => {
      setIsCopiedInstall(true);
      setTimeout(() => setIsCopiedInstall(false), 2000);
    }).catch(() => {
      setIsCopiedInstall(true);
      setTimeout(() => setIsCopiedInstall(false), 2000);
    });
  };

  // ---------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const toastTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showToast = (msg: string) => {
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    setToastMessage(msg);
    toastTimeoutRef.current = setTimeout(() => {
      setToastMessage(null);
    }, 2800);
  };

  // ---------------------------------------------------------
  // 3-Step Assessment Request Modal
  // ---------------------------------------------------------
  const [showAssessmentModal, setShowAssessmentModal] = useState(false);
  const [assessmentStep, setAssessmentStep] = useState<1 | 2 | 3>(1);
  const [selectedInterests, setSelectedInterests] = useState<string[]>(['PQC / Quantum Readiness']);
  const [assessmentForm, setAssessmentForm] = useState({
    name: '',
    email: '',
    company: '',
    role: '',
    size: ''
  });
  const [assessmentErrors, setAssessmentErrors] = useState<Record<string, string>>({});
  const [isSubmittingAssessment, setIsSubmittingAssessment] = useState(false);

  const openAssessmentModal = (initialInterest?: string) => {
    if (initialInterest && !selectedInterests.includes(initialInterest)) {
      setSelectedInterests(prev => [...prev, initialInterest]);
    }
    setAssessmentStep(1);
    setAssessmentErrors({});
    setShowAssessmentModal(true);
  };

  const toggleInterest = (interest: string) => {
    setSelectedInterests(prev =>
      prev.includes(interest) ? prev.filter(i => i !== interest) : [...prev, interest]
    );
  };

  const validateAssessmentStep2 = () => {
    const errs: Record<string, string> = {};
    if (!assessmentForm.name.trim()) errs.name = 'Please enter your name.';
    const email = assessmentForm.email.trim();
    if (!email) {
      errs.email = 'Please enter your work email.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errs.email = "That doesn't look like a valid email.";
    } else {
      const domain = email.split('@')[1]?.toLowerCase();
      if (domain && FREE_EMAIL_PROVIDERS.includes(domain)) {
        errs.email = 'Please use your work email, not a personal one.';
      }
    }
    if (!assessmentForm.company.trim()) errs.company = 'Please enter your company.';
    setAssessmentErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const submitAssessment = async () => {
    if (!validateAssessmentStep2()) return;
    setIsSubmittingAssessment(true);
    try {
      await fetch('/api/assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: assessmentForm.name.trim(),
          email: assessmentForm.email.trim(),
          company: assessmentForm.company.trim(),
          role: assessmentForm.role || 'Unspecified',
          environmentSize: assessmentForm.size || 'Unspecified',
          interests: selectedInterests,
          benchmarkSector: plannerSector.name,
          source: 'assessment_modal'
        })
      });
    } catch (e) {
      // Graceful fallback to offline success screen
    } finally {
      setIsSubmittingAssessment(false);
      setAssessmentStep(3);
    }
  };

  // ---------------------------------------------------------
  // Support Form Modal
  // ---------------------------------------------------------
  const [showSupportModalState, setShowSupportModalState] = useState(false);
  const [supportForm, setSupportForm] = useState({
    name: '',
    email: '',
    company: '',
    category: 'Technical issue',
    subject: '',
    message: ''
  });
  const [supportErrors, setSupportErrors] = useState<Record<string, string>>({});
  const [supportSubmitted, setSupportSubmitted] = useState(false);
  const [isSubmittingSupport, setIsSubmittingSupport] = useState(false);

  const validateSupport = () => {
    const errs: Record<string, string> = {};
    if (!supportForm.name.trim()) errs.name = 'Please enter your name.';
    const email = supportForm.email.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errs.email = 'Please enter a valid work email.';
    }
    if (!supportForm.subject.trim()) errs.subject = 'Please add a subject.';
    if (!supportForm.message.trim()) errs.message = 'Please describe how we can help.';
    setSupportErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const submitSupport = async () => {
    if (!validateSupport()) return;
    setIsSubmittingSupport(true);
    try {
      await fetch('/api/support', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(supportForm)
      });
    } catch (e) {
      // Fallback
    } finally {
      setIsSubmittingSupport(false);
      setSupportSubmitted(true);
    }
  };

  // ---------------------------------------------------------
  // Legal Reader Modal
  // ---------------------------------------------------------
  const [legalDoc, setLegalDoc] = useState<'privacy' | 'terms' | 'disclosure' | null>(null);

  // ---------------------------------------------------------
  // Unified Console Authentication & Modals
  // ---------------------------------------------------------
  const [showSignInModal, setShowSignInModal] = useState(false);
  const [loginIdentifier, setLoginIdentifier] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginWorkspace, setLoginWorkspace] = useState('');
  const [login2FACode, setLogin2FACode] = useState('');
  const [showCareerModal, setShowCareerModal] = useState(false);
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);
  const [signInSuccessMsg, setSignInSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setShowSignInModal(false);
        setShowCareerModal(false);
        setShowForgotPasswordModal(false);
        setShowForceChangeModal(false);
        setShowAssessmentModal(false);
        setShowSupportModalState(false);
        setLegalDoc(null);
        setShowStripeModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    const hash = window.location.hash;
    const params = new URLSearchParams(window.location.search);
    if (hash === '#signin' || params.get('modal') === 'signin') {
      setShowSignInModal(true);
    } else if (hash === '#career-modal' || params.get('modal') === 'careers') {
      setShowCareerModal(true);
    }

    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const [showForgotPasswordModal, setShowForgotPasswordModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSubmitted, setForgotSubmitted] = useState(false);
  const [forgotError, setForgotError] = useState<string | null>(null);

  const [showForceChangeModal, setShowForceChangeModal] = useState(false);
  const [forceChangeEmail, setForceChangeEmail] = useState('');
  const [forceCurrentPassword, setForceCurrentPassword] = useState('');
  const [forceNewPassword, setForceNewPassword] = useState('');
  const [forceConfirmPassword, setForceConfirmPassword] = useState('');
  const [forceChangeError, setForceChangeError] = useState<string | null>(null);
  const [forceChangeSuccess, setForceChangeSuccess] = useState<string | null>(null);
  const [showForceCurrent, setShowForceCurrent] = useState(false);
  const [showForceNew, setShowForceNew] = useState(false);
  const [showForceConfirm, setShowForceConfirm] = useState(false);

  const [showStripeModal, setShowStripeModal] = useState(false);
  const [stripeTier, setStripeTier] = useState<'entry' | 'scale' | 'enterprise'>('scale');
  const [stripeBillingCycle, setStripeBillingCycle] = useState<'monthly' | 'annual'>('annual');
  const [checkoutForm, setCheckoutForm] = useState({ companyName: '', contactName: '', email: '' });
  const [stripeLoading, setStripeLoading] = useState(false);
  const [stripeError, setStripeError] = useState<string | null>(null);

  const processSignInSuccess = (data: any, email: string) => {
    const cleanEmail = email.toLowerCase().trim();
    const isInternal =
      cleanEmail.endsWith('@quarkshield.ai') ||
      cleanEmail.endsWith('@spinovation.com') ||
      cleanEmail.includes('superadmin') ||
      cleanEmail === 'sridhargs@gmail.com';

    if (data.accountType === 'superadmin' || isInternal) {
      localStorage.setItem('quarkshield_user', email);
      sessionStorage.setItem('quarkshield_user', email);
      localStorage.setItem('quarkshield_role', data.role || 'Super Admin');
      sessionStorage.setItem('quarkshield_role', data.role || 'Super Admin');
      localStorage.setItem('quarkshield_account_type', 'superadmin');
      sessionStorage.setItem('quarkshield_account_type', 'superadmin');
      localStorage.setItem('quarkshield_customer_id', data.customerId || 'QS-ADMIN-001');
      sessionStorage.setItem('quarkshield_customer_id', data.customerId || 'QS-ADMIN-001');
      localStorage.setItem('quarkshield_customer_name', data.customerName || 'INTERNAL USER');
      sessionStorage.setItem('quarkshield_customer_name', data.customerName || 'INTERNAL USER');
      localStorage.setItem('quarkshield_license_tier', 'INTERNAL ROOT');
      sessionStorage.setItem('quarkshield_license_tier', 'INTERNAL ROOT');
      if (data.token) {
        localStorage.setItem('quarkshield_token', data.token);
        sessionStorage.setItem('quarkshield_token', data.token);
      }
      setSignInSuccessMsg('Verified Internal Super Admin. Launching Management Console...');
      setTimeout(() => {
        setShowSignInModal(false);
        setShowForceChangeModal(false);
        onLaunchConsole('admin', email);
      }, 400);
    } else {
      localStorage.setItem('quarkshield_user', email);
      sessionStorage.setItem('quarkshield_user', email);
      localStorage.setItem('quarkshield_role', data.role || (data.accountType === 'partner' ? 'Partner Admin' : 'Corporate Admin'));
      sessionStorage.setItem('quarkshield_role', data.role || (data.accountType === 'partner' ? 'Partner Admin' : 'Corporate Admin'));
      localStorage.setItem('quarkshield_account_type', data.accountType || 'tenant');
      sessionStorage.setItem('quarkshield_account_type', data.accountType || 'tenant');
      localStorage.setItem('quarkshield_customer_id', data.customerId || '');
      sessionStorage.setItem('quarkshield_customer_id', data.customerId || '');
      localStorage.setItem('quarkshield_customer_name', data.customerName || '');
      sessionStorage.setItem('quarkshield_customer_name', data.customerName || '');
      localStorage.setItem('quarkshield_license_tier', data.licenseTier || 'CORPORATE ENTERPRISE');
      sessionStorage.setItem('quarkshield_license_tier', data.licenseTier || 'CORPORATE ENTERPRISE');
      const ws = data.workspace || (cleanEmail.includes('algomeld') ? 'algomeld' : (cleanEmail.includes('spinovation') ? 'spinovationcorp' : ''));
      if (ws) {
        localStorage.setItem('quarkshield_workspace', ws);
        sessionStorage.setItem('quarkshield_workspace', ws);
        localStorage.setItem('quarkshield_tenant_slug', ws);
        sessionStorage.setItem('quarkshield_tenant_slug', ws);
      }
      if (data.token) {
        localStorage.setItem('quarkshield_token', data.token);
        sessionStorage.setItem('quarkshield_token', data.token);
      }
      setSignInSuccessMsg(`Verified ${data.role || 'User'} (${data.customerName || data.workspace || 'Workspace'}). Connecting...`);
      setTimeout(() => {
        if (data.redirectUrl && window.location.hostname !== 'localhost' && !window.location.hostname.includes('127.0.0.1')) {
          window.location.href = data.redirectUrl;
        } else {
          setShowSignInModal(false);
          setShowForceChangeModal(false);
          onLaunchConsole('dashboard', email);
        }
      }, 500);
    }
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setSignInError(null);
    setSignInSuccessMsg(null);

    if (!loginIdentifier || !loginIdentifier.trim()) {
      setSignInError('Please enter your work email or workspace identifier.');
      return;
    }

    setIsAuthenticating(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: loginIdentifier.trim(),
          email: loginIdentifier.trim(),
          password: loginPassword,
          totpCode: login2FACode ? login2FACode.trim() : undefined,
          workspace: loginWorkspace.trim() || undefined
        })
      });

      const data = await res.json();

      if (!res.ok) {
        if (res.status === 403 && data.forcePasswordChange) {
          setForceChangeEmail(loginIdentifier.trim());
          setShowForceChangeModal(true);
          setShowSignInModal(false);
          setIsAuthenticating(false);
          return;
        }
        throw new Error(data.error || 'Authentication failed. Please check your credentials.');
      }

      processSignInSuccess(data, loginIdentifier.trim());
    } catch (err: any) {
      setSignInError(err.message || 'Unable to connect to authentication authority.');
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForgotError(null);
    if (!forgotEmail || !forgotEmail.trim()) {
      setForgotError('Please enter your registered email address.');
      return;
    }
    try {
      await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail.trim() })
      });
      setForgotSubmitted(true);
    } catch (err: any) {
      setForgotSubmitted(true);
    }
  };

  const handleForceChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setForceChangeError(null);
    setForceChangeSuccess(null);

    if (forceNewPassword !== forceConfirmPassword) {
      setForceChangeError('New passwords do not match.');
      return;
    }
    if (forceNewPassword.length < 8) {
      setForceChangeError('Password must be at least 8 characters long.');
      return;
    }

    try {
      const res = await fetch('/api/auth/force-change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: forceChangeEmail,
          currentPassword: forceCurrentPassword,
          newPassword: forceNewPassword
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update temporary password.');
      }

      setForceChangeSuccess('Password successfully established! Signing you in...');
      setTimeout(() => {
        processSignInSuccess(data, forceChangeEmail);
      }, 1000);
    } catch (err: any) {
      setForceChangeError(err.message || 'Error changing password.');
    }
  };

  const handleStripeCheckout = async (e: React.FormEvent) => {
    e.preventDefault();
    setStripeError(null);
    if (!checkoutForm.companyName.trim() || !checkoutForm.email.trim()) {
      setStripeError('Please provide both your company name and corporate email address.');
      return;
    }
    setStripeLoading(true);
    try {
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tier: stripeTier,
          billingInterval: stripeBillingCycle,
          companyName: checkoutForm.companyName.trim(),
          contactName: checkoutForm.contactName.trim(),
          email: checkoutForm.email.trim()
        })
      });
      const data = await res.json();
      if (!res.ok || !data.checkoutUrl) {
        throw new Error(data.error || 'Failed to initialize Stripe checkout session.');
      }
      window.location.href = data.checkoutUrl;
    } catch (err: any) {
      setStripeError(err.message || 'Payment system error. Please try again.');
      setStripeLoading(false);
    }
  };

  return (
    <div style={{ background: 'var(--bg)', minHeight: '100vh', color: 'var(--text)' }}>

      {/* ===================== NAV ===================== */}
      <nav className="nav">
        <div className="wrap nav-inner">
          <div className="brand">
            <span className="mark" aria-hidden="true">
              <svg viewBox="0 0 32 32" fill="none">
                <path d="M16 2 4 7v8c0 7.2 5.1 12.9 12 15 6.9-2.1 12-7.8 12-15V7L16 2Z" fill="url(#g-logo)" stroke="#c084fc" strokeWidth="1.2"/>
                <path d="M11 16.5 14.5 20 21 12.5" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <defs>
                  <linearGradient id="g-logo" x1="4" y1="2" x2="28" y2="30">
                    <stop stopColor="#b76bfb"/>
                    <stop offset="1" stopColor="#7c3aed"/>
                  </linearGradient>
                </defs>
              </svg>
            </span>
            <span className="wordmark"><b>quark</b><i>shield</i></span>
          </div>

          <div className="nav-links">
            <a href="#platform" style={{ textDecoration: 'none' }}>Platform</a>
            <a href="#pricing" style={{ textDecoration: 'none' }}>Pricing</a>
            <a href="#downloads" style={{ textDecoration: 'none' }}>Downloads</a>
            <div
              className={`nav-item ${resDropdownOpen ? 'open' : ''}`}
              ref={resDropdownRef}
              onMouseEnter={() => {
                if (resTimeoutRef.current) clearTimeout(resTimeoutRef.current);
                setResDropdownOpen(true);
              }}
              onMouseLeave={() => {
                resTimeoutRef.current = setTimeout(() => setResDropdownOpen(false), 200);
              }}
            >
              <button
                className="nav-menu-trigger"
                onClick={() => setResDropdownOpen(prev => !prev)}
                aria-expanded={resDropdownOpen}
                style={{ textDecoration: 'none' }}
              >
                Resources <span className="caret">▾</span>
              </button>
              <div className="mega-menu" role="menu">
                <a className="mega-item" role="menuitem" href="https://quarkshield.ai/docs/AGENTLESS_PQC_ARCHITECTURE.md" target="_blank" rel="noopener" style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">📖</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Documentation Center</b><span className="mega-badge docs">Docs</span></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="https://quarkshield.ai/docs/QUARKSHIELD_ENTERPRISE_FEATURES_GUIDE.md" target="_blank" rel="noopener" style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">⚙️</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Enterprise Features &amp; Operations</b><span className="mega-badge tier">3-Tier</span></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="https://quarkshield.ai/docs/WINDOWS_USER_GUIDE.md" target="_blank" rel="noopener" style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">⊞</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Windows User Guide</b></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="https://quarkshield.ai/docs/MACOS_USER_GUIDE.md" target="_blank" rel="noopener" style={{ textDecoration: 'none' }}>
                  <span className="mega-ic"></span>
                  <span className="mega-tx">
                    <span className="mt"><b>macOS User Guide</b></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="https://quarkshield.ai/docs/LINUX_USER_GUIDE.md" target="_blank" rel="noopener" style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">🐧</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Linux User Guide</b></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="#cnsa-news" onClick={() => setResDropdownOpen(false)} style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">📡</span>
                  <span className="mega-tx">
                    <span className="mt"><b>CNSA 2.0 &amp; PQC Intel</b></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="#assessment" onClick={() => setResDropdownOpen(false)} style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">📅</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Mosca's Migration Planner</b><span className="mega-badge xyz">X+Y&gt;Z</span></span>
                  </span>
                </a>
                <a className="mega-item" role="menuitem" href="#faq" onClick={() => setResDropdownOpen(false)} style={{ textDecoration: 'none' }}>
                  <span className="mega-ic">❓</span>
                  <span className="mega-tx">
                    <span className="mt"><b>Post-Quantum FAQs</b></span>
                  </span>
                </a>
              </div>
            </div>
            <a
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setShowSupportModalState(true);
              }}
              style={{ textDecoration: 'none' }}
            >
              Support
            </a>
          </div>

          <div className="nav-cta">
            <a
              href="#"
              className="signin"
              onClick={(e) => {
                e.preventDefault();
                setShowSignInModal(true);
              }}
              style={{ textDecoration: 'none' }}
            >
              Console Sign In
            </a>
            <button className="btn btn-primary btn-sm" onClick={() => openAssessmentModal()}>
              Request Assessment
            </button>
          </div>
        </div>
      </nav>

      {/* ===================== HERO ===================== */}
      <header className="hero" id="platform">
        <div className="wrap hero-grid">
          <div>
            <span className="eyebrow">Post-Quantum Cryptography Readiness</span>
            <h1>
              Know where your cryptography is.<br />
              <span className="accent">Know what's at risk.</span>
            </h1>
            <p className="sub">
              QuarkShield discovers cryptographic assets across your enterprise, identifies quantum-vulnerable algorithms and Harvest-Now-Decrypt-Later exposure, and turns the findings into a prioritized PQC migration roadmap.
            </p>
            <div className="hero-cta">
              <button className="btn btn-primary btn-lg" onClick={() => openAssessmentModal('PQC / Quantum Readiness')}>
                Request a PQC Assessment
              </button>
              <a className="btn btn-ghost btn-lg" href="#probe">
                Test your website now →
              </a>
            </div>
            <div className="trust">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 12l2 2 4-4M12 3l7 3v6c0 5-3.5 7.5-7 9-3.5-1.5-7-4-7-9V6l7-3Z" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              Built for enterprise environments. Works with the PKI, PAM and KMS systems you already trust.
            </div>
          </div>

          {/* Product Mock: Square 3x2 Grid */}
          <div className="mock" aria-label="QuarkShield sample CBOM posture — Sample Enterprise Fleet">
            <div className="mock-top">
              <span className="mock-title">Cryptographic Posture — Sample Enterprise Fleet</span>
              <span className="live-pill"><span className="dot"></span>LIVE</span>
            </div>
            <div className="kpis">
              <div className="kpi">
                <div className="label">Total Assets</div>
                <div className="num">{(spinovationPosture?.totalAssets ?? 4812).toLocaleString()}</div>
                <div className="bar"><span style={{ width: '100%', background: 'var(--muted)' }}></span></div>
              </div>
              <div className="kpi crit">
                <div className="label">Quantum-Vuln</div>
                <div className="num">{(spinovationPosture?.quantumVuln ?? 1367).toLocaleString()}</div>
                <div className="bar"><span style={{ width: '78%', background: 'var(--critical)' }}></span></div>
              </div>
              <div className="kpi warn">
                <div className="label">HNDL Exposed</div>
                <div className="num">{(spinovationPosture?.hndlExposed ?? 214).toLocaleString()}</div>
                <div className="bar"><span style={{ width: '44%', background: 'var(--warning)' }}></span></div>
              </div>
              <div className="kpi warn">
                <div className="label">Config Findings</div>
                <div className="num">{(spinovationPosture?.configFindings ?? 89).toLocaleString()}</div>
                <div className="bar"><span style={{ width: '30%', background: 'var(--warning)' }}></span></div>
              </div>
              <div className="kpi good">
                <div className="label">PQC Ready</div>
                <div className="num">{(spinovationPosture?.pqcReady ?? 642).toLocaleString()}</div>
                <div className="bar"><span style={{ width: '34%', background: 'var(--good)' }}></span></div>
              </div>
              <div className="kpi">
                <div className="label">Risk Grade</div>
                <div className="num" style={{ color: 'var(--critical)' }}>{spinovationPosture?.riskGrade ?? 'D+'}</div>
                <div className="bar"><span style={{ width: '38%', background: 'var(--critical)' }}></span></div>
              </div>
            </div>

            <div className="drill">
              <div className="drill-head">
                <span className="sev">CRITICAL</span>
                <span className="asset">edge-lb-01 · TLS cert (RSA-2048)</span>
              </div>
              <div className="drill-row">
                <span className="k">Impact</span>
                <span className="v">Public edge terminates TLS with <b>classical ECDHE</b> — session traffic is harvestable today for later decryption.</span>
              </div>
              <div className="drill-row">
                <span className="k">Recommend</span>
                <span className="v">Enable hybrid <b>X25519MLKEM768</b> key exchange; re-issue leaf with <b>ML-DSA</b> signature.</span>
              </div>
              <div className="drill-row">
                <span className="k">Remediate</span>
                <span className="v">Roadmap · Phase 1 — HNDL perimeter · <b>0–90 days</b></span>
              </div>
            </div>

          </div>
        </div>
      </header>

      {/* ===================== LIVE TLS PROBE ===================== */}
      <section className="band" id="probe">
        <div className="wrap">
          <span className="band-eyebrow">Live outbound TLS probe · see it in 3 seconds</span>
          <h2>Is your site harvestable today? Test it now.</h2>
          <p className="lead">
            QuarkShield opens a direct TLS 1.3 handshake with any public host and checks whether it negotiates classical ECDHE — vulnerable to Harvest Now, Decrypt Later — or post-quantum <span className="mono">X25519MLKEM768</span> hybrid key exchange. No signup, no agent.
          </p>

          <div className="probe-wrap">
            <div>
              <div className="probe-input">
                <input
                  id="probe-host"
                  type="text"
                  value={probeHostInput}
                  onChange={(e) => setProbeHostInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && runProbe(probeHostInput)}
                  spellCheck={false}
                  aria-label="Hostname to probe"
                  placeholder="yourcompany.com"
                />
                <button
                  className="btn btn-primary"
                  id="probe-run"
                  disabled={probing}
                  onClick={() => runProbe(probeHostInput)}
                >
                  {probing ? 'Probing…' : 'Probe endpoint'}
                </button>
              </div>

              <div className="presets" id="probe-presets">
                {Object.keys(PROBE_PRESETS).map((h) => (
                  <button
                    key={h}
                    className="preset"
                    onClick={() => runProbe(h)}
                  >
                    {h}
                  </button>
                ))}
              </div>

              <div className="probe-mini-note">
                ◆ Simulated handshake in this prototype · the live site performs a real TLS 1.3 socket probe
              </div>
            </div>

            <div className="terminal">
              <div className="term-bar">
                <span className="tdots"><i></i><i></i><i></i></span>
                <span className="tlabel">quarkshield · tls-probe</span>
              </div>
              <div className="term-body" ref={termBodyRef}>
                {probeLogs.map((l, i) => (
                  <span key={i} className={`ln ${l.cls}`}>{l.text}</span>
                ))}
                {probing && <span className="cursor"></span>}

                {probeVerdict && (
                  probeVerdict.pqc ? (
                    <div className="verdict-card vc-green">
                      <div className="vc-top">✓ Post-quantum protected · Grade A</div>
                      <div className="vc-sub">
                        This edge negotiates <b>{probeVerdict.kx}</b> — session keys are safe against Harvest Now, Decrypt Later. Worth confirming the rest of your fleet matches this edge.
                      </div>
                      <button className="btn btn-ghost btn-sm vc-cta" onClick={() => openAssessmentModal('HNDL Assessment')}>
                        Audit your whole fleet →
                      </button>
                    </div>
                  ) : (
                    <div className="verdict-card vc-red">
                      <div className="vc-top">
                        ✕ Harvest Now, Decrypt Later exposure · Grade {probeVerdict.tls === 'TLS 1.2' ? 'D' : 'C+'}
                      </div>
                      <div className="vc-sub">
                        Classical <b>{probeVerdict.kx}</b>{probeVerdict.cert.indexOf('RSA') === 0 ? ` with an ${probeVerdict.cert} signature` : ''}. Traffic captured today is decryptable once a quantum computer arrives. Fix: enable <b>X25519MLKEM768</b> hybrid key exchange and re-issue with an ML-DSA signature.
                      </div>
                      <button className="btn btn-primary btn-sm vc-cta" onClick={() => openAssessmentModal('HNDL Assessment')}>
                        See your full exposure — Request an Assessment
                      </button>
                    </div>
                  )
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== MOSCA PLANNER ===================== */}
      <section className="band" id="assessment">
        <div className="wrap">
          <span className="band-eyebrow">Interactive Risk Horizon · NIST SP 800-227 aligned</span>
          <h2>Are you already exposed? Run the 30-second check.</h2>
          <p className="lead">
            Mosca's inequality proves whether adversaries harvesting your traffic today can decrypt it while it's still sensitive. If your data shelf-life (X) plus migration time (Y) exceeds the quantum horizon (Z), you're already at risk.
          </p>

          <div className="planner">
            <div className="panel">
              <span className="field-label">1 — Select your sector benchmark</span>
              <div className="sectors">
                {SECTOR_BENCHMARKS.map((b) => (
                  <button
                    key={b.name}
                    className="sector"
                    aria-pressed={plannerSector.name === b.name}
                    onClick={() => selectSector(b)}
                  >
                    <span className="s-name">{b.short}</span>
                    <span className="s-meta">{b.meta}</span>
                  </button>
                ))}
              </div>

              <div className="sliders">
                <div className="slider-row">
                  <div className="sl-top">
                    <span className="sl-name">X — Data secrecy shelf-life</span>
                    <span className="sl-val">{sx} yrs</span>
                  </div>
                  <input
                    type="range"
                    min="3"
                    max="50"
                    value={sx}
                    onChange={(e) => setSx(+e.target.value)}
                    aria-label="Data secrecy shelf-life in years"
                    style={{ width: '100%' }}
                  />
                </div>
                <div className="slider-row">
                  <div className="sl-top">
                    <span className="sl-name">Y — Fleet migration time</span>
                    <span className="sl-val">{sy} yrs</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={sy}
                    onChange={(e) => setSy(+e.target.value)}
                    aria-label="Migration time in years"
                    style={{ width: '100%' }}
                  />
                </div>
                <div className="slider-row">
                  <div className="sl-top">
                    <span className="sl-name">Z — Quantum threat horizon</span>
                    <span className="sl-val">{sz} yrs</span>
                  </div>
                  <input
                    type="range"
                    min="3"
                    max="12"
                    value={sz}
                    onChange={(e) => setSz(+e.target.value)}
                    aria-label="Quantum horizon in years"
                    style={{ width: '100%' }}
                  />
                </div>
              </div>
            </div>

            <div className="panel verdict">
              <span className={`verdict-badge ${plannerIsBad ? 'bad' : 'ok'}`}>
                {plannerIsBad ? '● Critical active risk' : '● Within safe horizon'}
              </span>

              <div className="ineq">
                {sx} <span className="op">+</span> {sy} <span className="op">{plannerOp}</span> <span className="zed">{sz}</span>
              </div>

              <p className="explain">
                {plannerIsBad
                  ? "Your required secrecy plus migration transition exceeds the arrival of a quantum computer capable of Shor's algorithm. Traffic harvested today is decryptable while still sensitive."
                  : 'Your migration completes before harvested traffic loses sensitivity — but the margin is thin. A verified CBOM keeps Y honest.'}
              </p>

              <div className="deficit-line">
                <div className={`deficit-num ${plannerIsBad ? 'bad' : 'ok'}`}>
                  {plannerDeficit > 0 ? `+${plannerDeficit}` : (plannerDeficit === 0 ? '0' : String(plannerDeficit))}
                </div>
                <div className="deficit-cap">
                  {plannerDeficit > 0
                    ? 'year exposure deficit'
                    : (plannerDeficit === 0 ? 'years — no margin to spare' : 'years of margin')}
                </div>
              </div>

              <button className="btn btn-primary" onClick={() => openAssessmentModal('Migration Planning')}>
                Close this deficit — Request an Assessment
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== HOW / trust ===================== */}
      <section className="band" id="how">
        <div className="wrap">
          <span className="band-eyebrow">How QuarkShield works</span>
          <h2>Discover → Analyze → Prioritize → Remediate</h2>
          <p className="lead">
            QuarkShield is the cryptographic intelligence layer — not another system of record. It reads from the platforms you already run and hands your teams decisions they can execute.
          </p>
          <div className="persona-grid" style={{ marginTop: '26px' }}>
            <div className="persona">
              <div className="role">01 · Discover</div>
              <p className="q" style={{ fontStyle: 'normal' }}>Find cryptographic assets across servers, endpoints, certificates, TLS, SSH, VPN and cloud.</p>
            </div>
            <div className="persona">
              <div className="role">02 · Analyze</div>
              <p className="q" style={{ fontStyle: 'normal' }}>Identify algorithms, key types and protocols; separate Shor-vulnerable public-key crypto by purpose.</p>
            </div>
            <div className="persona">
              <div className="role">03 · Prioritize</div>
              <p className="q" style={{ fontStyle: 'normal' }}>Correlate technical findings with HNDL exposure and business context — what to migrate first.</p>
            </div>
            <div className="persona">
              <div className="role">04 · Remediate</div>
              <p className="q" style={{ fontStyle: 'normal' }}>Generate verification steps and a phased PQC migration roadmap your teams can execute.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== PERSONAS ===================== */}
      <section className="band" id="personas">
        <div className="wrap">
          <span className="band-eyebrow">Built for the whole security org</span>
          <h2>One assessment, answers for every stakeholder.</h2>
          <div className="persona-grid">
            <div className="persona">
              <div className="role">CISO</div>
              <p className="q">"Do I know where we're exposed to quantum-vulnerable cryptography?"</p>
              <div className="val">Executive exposure, priorities and roadmap.</div>
            </div>
            <div className="persona">
              <div className="role">Security Architect</div>
              <p className="q">"Which cryptographic dependencies need architectural change?"</p>
              <div className="val">Asset relationships, algorithms, migration design.</div>
            </div>
            <div className="persona">
              <div className="role">Security Engineering</div>
              <p className="q">"What do I fix, and how do I verify the change?"</p>
              <div className="val">Findings, remediation actions, verification steps.</div>
            </div>
            <div className="persona">
              <div className="role">GRC / Compliance</div>
              <p className="q">"Can I produce evidence of our PQC readiness program?"</p>
              <div className="val">Inventory, risk evidence, roadmap and reporting.</div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== PRICING ===================== */}
      <section className="band" id="pricing">
        <div className="wrap">
          <span className="band-eyebrow">Predictable commercial licensing</span>
          <h2>Start with an assessment. Scale when you're ready.</h2>
          <p className="lead">
            Every tier begins local-first with a zero-exfiltration audit. Move up as you roll QuarkShield across the fleet — no re-platforming.
          </p>

          <div className="bill-toggle" role="group" aria-label="Billing interval">
            <button
              aria-pressed={!isAnnualBilling}
              onClick={() => setIsAnnualBilling(false)}
            >
              Monthly
            </button>
            <button
              aria-pressed={isAnnualBilling}
              onClick={() => setIsAnnualBilling(true)}
            >
              Annual <span className="save-pill">save ~17%</span>
            </button>
          </div>

          <div className="price-grid">
            {/* Entry Tier */}
            <div className="price-card">
              <span className="pc-tier">Entry</span>
              <div className="pc-name">PQC Assessment</div>
              <div className="pc-price">
                <span className="amt">{isAnnualBilling ? '$249' : '$300'}</span>
                <span className="per">/mo</span>
              </div>
              <div className="pc-sub">{isAnnualBilling ? 'billed annually' : ''}</div>
              <div className="pc-seats">5 endpoint licenses · unlimited local scans</div>
              <ul className="pc-feats">
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Executive Quantum Risk Score &amp; letter grade
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  CycloneDX 1.6 baseline CBOM export
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Board-level PQC migration roadmap
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Zero-exfiltration local audit
                </li>
              </ul>
              <button
                className="btn btn-ghost"
                onClick={() => {
                  setStripeTier('entry');
                  setStripeBillingCycle(isAnnualBilling ? 'annual' : 'monthly');
                  setStripeError(null);
                  setShowStripeModal(true);
                }}
              >
                Start assessment
              </button>
            </div>

            {/* Scale Tier */}
            <div className="price-card featured">
              <span className="pc-badge">★ Most popular</span>
              <span className="pc-tier">Scale</span>
              <div className="pc-name">Growth Fleet</div>
              <div className="pc-price">
                <span className="amt">{isAnnualBilling ? '$2,075' : '$2,500'}</span>
                <span className="per">/mo</span>
              </div>
              <div className="pc-sub">{isAnnualBilling ? 'billed annually' : ''}</div>
              <div className="pc-seats">Up to 50 monitored endpoints</div>
              <ul className="pc-feats">
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Cloud Fleet Central Plane &amp; tenant orchestration
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Automated cryptographic drift detection
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Continuous CBOM &amp; CSV export
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Group enrollment for Intune / Jamf
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Real-time email &amp; webhook alerts
                </li>
              </ul>
              <button
                className="btn btn-primary"
                onClick={() => {
                  setStripeTier('scale');
                  setStripeBillingCycle(isAnnualBilling ? 'annual' : 'monthly');
                  setStripeError(null);
                  setShowStripeModal(true);
                }}
              >
                Deploy Growth Fleet
              </button>
            </div>

            {/* Enterprise Tier */}
            <div className="price-card">
              <span className="pc-tier">Enterprise</span>
              <div className="pc-name">Enterprise Pro</div>
              <div className="price-price pc-price">
                <span className="amt">{isAnnualBilling ? '$8,300' : '$10,000'}</span>
                <span className="per">/mo</span>
              </div>
              <div className="pc-sub">{isAnnualBilling ? 'billed annually' : ''}</div>
              <div className="pc-seats">Up to 250 hybrid endpoints</div>
              <ul className="pc-feats">
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Remote Git scanner (GitHub / GitLab / Bitbucket)
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Full QS Copilot AI with offline / SCIF support
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Dedicated tenant subdomain &amp; isolated channel
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Enterprise 2FA &amp; role-based access policies
                </li>
                <li>
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  Senior cryptographic engineering support
                </li>
              </ul>
              <button className="btn btn-ghost" onClick={() => openAssessmentModal('Enterprise Demo')}>
                Talk to sales
              </button>
            </div>
          </div>

          <div className="partner-strip">
            <div>
              <span className="ps-tier">Partner ecosystem</span>
              <h3>MSP &amp; Migration Partner</h3>
              <p>Multi-tenant partner console, volume licensing and co-branded assessments for MSPs, MSSPs and consultancies.</p>
            </div>
            <button className="btn btn-ghost" onClick={() => openAssessmentModal('Enterprise Demo')}>
              Become a partner
            </button>
          </div>
        </div>
      </section>

      {/* ===================== DOWNLOADS ===================== */}
      <section className="band" id="downloads">
        <div className="wrap">
          <span className="band-eyebrow">Multi-OS host scanners</span>
          <h2>Prefer to run it yourself? Download the signed scanner.</h2>
          <p className="lead">
            Standalone binaries with zero third-party agent dependencies. Deploy by hand or via Intune, Jamf, Ansible or GPO. Every build is code-signed and runs local-first.
          </p>

          <div className="dl-grid">
            <div className="dl-card">
              <div className="dl-os">
                <span className="glyph" aria-hidden="true">⊞</span>
                <div>
                  <div className="name">Windows</div>
                  <div className="plat">10 / 11 &amp; Server · x64</div>
                </div>
              </div>
              <p className="dl-desc">Authenticode-signed scanner. Audits Schannel ciphers, the certificate store, registry-installed crypto tooling, OpenSSH and PKI.</p>
              <div className="dl-actions">
                <a className="btn btn-primary btn-sm" href="/downloads/pqc-scanner-windows-amd64.exe" download style={{ textDecoration: 'none' }}>
                  Download .exe (Installer)
                </a>
              </div>
              <div className="dl-alt">
                <a href="/downloads/pqc-scanner-windows.zip" style={{ color: 'inherit', textDecoration: 'none' }} download>Portable .zip · CLI (x64)</a>
              </div>
            </div>

            <div className="dl-card">
              <div className="dl-os">
                <span className="glyph" aria-hidden="true"></span>
                <div>
                  <div className="name">macOS</div>
                  <div className="plat">Apple Silicon &amp; Intel</div>
                </div>
              </div>
              <p className="dl-desc">Notarized universal build. Discovers Keychain items, OpenSSH &amp; GPG keys, Homebrew OpenSSL and local developer certificates.</p>
              <div className="dl-actions">
                <a className="btn btn-primary btn-sm" href="/downloads/QuarkShield-macOS.dmg" download style={{ textDecoration: 'none' }}>
                  Download .dmg (Universal)
                </a>
              </div>
              <div className="dl-alt">
                <a href="/downloads/quarkshield-scanner-macos.zip" style={{ color: 'inherit', textDecoration: 'none' }} download>Portable .zip · universal CLI</a>
              </div>
            </div>

            <div className="dl-card">
              <div className="dl-os">
                <span className="glyph" aria-hidden="true">🐧</span>
                <div>
                  <div className="name">Linux</div>
                  <div className="plat">Cloud &amp; on-prem · amd64 / arm64</div>
                </div>
              </div>
              <p className="dl-desc">Multi-distro SBOM via dpkg / rpm / apk / pacman. Audits trust stores, OpenSSL &amp; SSH config, and the kernel crypto drivers.</p>
              <div className="dl-actions">
                <a className="btn btn-primary btn-sm" href="/downloads/pqc-scanner-linux.tar.gz" download style={{ textDecoration: 'none' }}>
                  Download .tar.gz (Full Bundle)
                </a>
              </div>
              <div className="dl-alt" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <a href="/downloads/pqc-scanner-linux.zip" style={{ color: 'inherit', textDecoration: 'none' }} download>.zip · systemd unit · install.sh</a>
                <span style={{ fontSize: '0.76rem', color: 'var(--faint)' }}>
                  Raw binaries: <a href="/downloads/pqc-scanner-linux-amd64" style={{ color: 'var(--cyan)', textDecoration: 'none' }} download>amd64</a> · <a href="/downloads/pqc-scanner-linux-arm64" style={{ color: 'var(--cyan)', textDecoration: 'none' }} download>arm64</a>
                </span>
              </div>
            </div>
          </div>

          <div className="code-block">
            <div className="cb-bar">
              <span>Quick install — macOS &amp; Linux</span>
              <button className="copy-btn" onClick={copyInstallCmd}>
                {isCopiedInstall ? 'Copied ✓' : 'Copy'}
              </button>
            </div>
            <pre>
              <span className="c"># 1. Download the universal scanner</span>{'\n'}
              curl -fsSL https://quarkshield.ai/downloads/quarkshield-scanner -o quarkshield-scanner{'\n'}
              <span className="c"># 2. Make it executable</span>{'\n'}
              chmod +x quarkshield-scanner{'\n'}
              <span className="c"># 3. Launch the interactive dashboard (local-first, no data leaves the host)</span>{'\n'}
              ./quarkshield-scanner --server https://quarkshield.ai
            </pre>
          </div>
        </div>
      </section>

      {/* ===================== CNSA 2.0 & REGULATORY RADAR ===================== */}
      <section className="band" id="cnsa-news">
        <div className="wrap">
          <span className="band-eyebrow">Live Regulatory Radar • NIST • NSA • White House OMB</span>
          <h2>Post-Quantum Regulatory Horizons &amp; CNSA 2.0 Intelligence</h2>
          <p className="lead">
            Direct federal policy tracking, NIST FIPS releases, and enforcement deadlines for CISOs, defense suppliers, and enterprise cryptographers.
          </p>

          <div style={{
            background: 'var(--surface)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius)',
            padding: '24px',
            marginTop: '28px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.8rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span style={{ color: 'var(--cyan)', fontSize: '1.2rem' }}>🛡️</span>
                <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 700, color: 'var(--text)' }}>
                  NSA CNSA 2.0 &amp; OMB Migration Horizon
                </h3>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--muted)', background: 'var(--surface-2)', border: '1px solid var(--line-soft)', padding: '0.25rem 0.65rem', borderRadius: '6px', fontFamily: 'var(--font-mono)' }}>
                NSM-10 &amp; OMB M-23-02 Compliance
              </span>
            </div>

            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '14px'
            }}>
              {[
                {
                  year: '2025',
                  title: 'Software & Firmware Code Signing',
                  desc: 'NSA mandates CNSA 2.0 algorithms for all newly released software and firmware signing. Transition begins immediately.',
                  status: 'Active Enforcement',
                  color: 'var(--warning)'
                },
                {
                  year: '2030',
                  title: 'Cloud Gateways & Web TLS',
                  desc: 'Web browsers, edge reverse proxies, cloud endpoints, and network appliances must deploy ML-KEM/ML-DSA.',
                  status: 'Mandatory Transition',
                  color: 'var(--cyan)'
                },
                {
                  year: '2033',
                  title: 'Legacy Cryptography Phaseout',
                  desc: 'Complete elimination of traditional asymmetric algorithms (RSA-2048/4096, Diffie-Hellman, ECDSA) in National Security Systems.',
                  status: 'Full Prohibition',
                  color: 'var(--critical)'
                },
                {
                  year: '2035',
                  title: 'Complete Quantum Resilience',
                  desc: '100% of all national security assets, critical infrastructure protocols, and enterprise data encrypted with PQC standards.',
                  status: 'Permanent Benchmark',
                  color: 'var(--good)'
                }
              ].map((m, idx) => (
                <div key={idx} style={{
                  background: 'var(--surface-2)',
                  padding: '18px',
                  borderRadius: '10px',
                  border: '1px solid var(--line-soft)',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '10px'
                }}>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '1.6rem', fontWeight: 800, color: m.color, letterSpacing: '-0.02em', fontFamily: 'var(--font-display)' }}>
                        {m.year}
                      </span>
                      <span style={{ fontSize: '0.68rem', fontWeight: 700, textTransform: 'uppercase', color: m.color, background: 'rgba(255,255,255,0.04)', border: '1px solid currentColor', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                        {m.status}
                      </span>
                    </div>
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '0.94rem', fontWeight: 700, color: 'var(--text)' }}>
                      {m.title}
                    </h4>
                    <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--muted)', lineHeight: 1.5 }}>
                      {m.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
            gap: '16px',
            marginTop: '20px'
          }}>
            {[
              {
                source: 'NIST',
                tag: 'FIPS Standards',
                date: 'Aug 2024 · Active Enforcement',
                title: 'NIST Finalizes FIPS 203, 204, and 205: Global Post-Quantum Standards Released',
                summary: 'NIST has officially published the final cryptographic standards for post-quantum defense: FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), and FIPS 205 (SLH-DSA / SPHINCS+). Federal and enterprise IT architectures must begin transitioning legacy RSA/ECC public key algorithms immediately.',
                color: 'var(--cyan)'
              },
              {
                source: 'NSA',
                tag: 'CNSA 2.0 Mandate',
                date: 'Updated Quarterly',
                title: 'NSA CNSA 2.0 Cybersecurity Advisory: Mandatory Software & Firmware Signing Deadlines',
                summary: 'The National Security Agency (NSA) Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) designates post-quantum algorithms for National Security Systems (NSS). Software and firmware code signing migration begins in 2025. Web browsers, cloud endpoints, and network boundary devices must deploy ML-KEM/ML-DSA by 2030.',
                color: 'var(--purple)'
              },
              {
                source: 'White House OMB',
                tag: 'Federal Policy',
                date: 'M-23-02 Compliance',
                title: 'White House OMB M-23-02 Mandate: Annual Cryptographic Bill of Materials (CBOM) Reporting',
                summary: 'Office of Management and Budget (OMB) Memorandum M-23-02 requires federal agencies and commercial suppliers to discover, catalog, and submit an annual inventory of all cryptographic assets (CBOM). Critical vulnerabilities exposed to "Harvest Now, Decrypt Later" (HNDL) attacks must be prioritized for immediate remediation.',
                color: 'var(--good)'
              },
              {
                source: 'CISA',
                tag: 'Threat Intel',
                date: 'Active Threat Guidance',
                title: 'CISA, NSA & NIST Joint Advisory: Mitigating "Harvest Now, Decrypt Later" (HNDL) Across TLS Endpoints',
                summary: 'Hostile nation-states are actively harvesting encrypted enterprise network communications, intellectual property, and government records over public internet circuits to decrypt once cryptanalytically relevant quantum computers arrive. Organizations are urged to deploy hybrid post-quantum key encapsulation (X25519MLKEM768) immediately.',
                color: 'var(--critical)'
              }
            ].map((advisory, idx) => (
              <div key={idx} style={{
                background: 'var(--surface)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius)',
                padding: '20px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '12px'
              }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, textTransform: 'uppercase', color: advisory.color, background: 'rgba(255,255,255,0.04)', padding: '2px 6px', borderRadius: '4px', border: '1px solid currentColor', fontFamily: 'var(--font-mono)' }}>
                        {advisory.source}
                      </span>
                      <span style={{ fontSize: '0.74rem', color: 'var(--faint)' }}>
                        • {advisory.tag}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.74rem', color: 'var(--faint)', fontFamily: 'var(--font-mono)' }}>
                      {advisory.date}
                    </span>
                  </div>
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '1rem', fontWeight: 700, color: 'var(--text)', lineHeight: 1.4 }}>
                    {advisory.title}
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.86rem', color: 'var(--muted)', lineHeight: 1.55 }}>
                    {advisory.summary}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ===================== POST-QUANTUM FAQS ===================== */}
      <section className="band" id="faq">
        <div className="wrap">
          <span className="band-eyebrow">Frequently Asked Questions</span>
          <h2>Post-Quantum Cryptography &amp; Platform FAQs</h2>
          <p className="lead">
            Essential guidance on cryptographic key discovery, zero-exfiltration privacy guarantees, Shor's algorithm vulnerabilities, and OS-level PQC readiness.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '28px' }}>
            {[
              {
                q: 'What are "Keys" in QuarkShield, and are my private keys ever uploaded or exfiltrated?',
                a: 'In QuarkShield, "Keys" refers strictly to Cryptographic Assets discovered in the Cryptographic Bill of Materials (CBOM) inventory—such as public certificates (X.509), public key parameters (RSA moduli, ECC curve points), SSH public host keys, and TLS cryptographic cipher suites.\n\nZero-Exfiltration Guarantee: Private keys (BEGIN RSA PRIVATE KEY, BEGIN EC PRIVATE KEY, PKCS#8, seed phrases, or passphrases) are NEVER stored in our cloud, NEVER uploaded, and NEVER exfiltrated. QuarkShield operates on a local-first volatile memory inspection model. The scanner inspects files and keychains in local RAM, extracts only non-sensitive public metadata (algorithm identifier, bit length, curve name, expiration date, and issuer DN), and immediately discards working buffers. Your private keys never leave your device or network perimeter.'
              },
              {
                q: 'Are our current production keys and certificates quantum certified?',
                a: 'Almost certainly not. Over 99% of digital infrastructure in production today relies on classical asymmetric cryptography: RSA-2048/4096, ECDSA (P-256, secp256k1), and Diffie-Hellman. None of these classical primitives are quantum certified. They are mathematically vulnerable to complete factorisation and key extraction by Shor\'s algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC).\n\nTrue quantum-certified algorithms are those newly standardized by NIST in August 2024: FIPS 203 (ML-KEM / Kyber) for general encryption and TLS key exchange, FIPS 204 (ML-DSA / Dilithium) for digital signatures and certificates, and FIPS 205 (SLH-DSA / SPHINCS+) for stateless hash-based signatures. The recommended industry path is Hybrid PQC (e.g., X25519MLKEM768), preserving classical FIPS 140-3 validation while resisting quantum attacks.'
              },
              {
                q: 'What is Harvest Now, Decrypt Later (HNDL) and why is it an urgent threat today?',
                a: 'Harvest Now, Decrypt Later (HNDL) is an active surveillance operation wherein adversarial nation-states intercept and record petabytes of encrypted internet and enterprise communications today. While they cannot decrypt it with classical supercomputers, they will decrypt it retroactively once a quantum computer with sufficient logical qubits comes online.\n\nIf your organization produces data with a secrecy shelf-life (X) of 10–30 years (such as healthcare records, defense IP, financial ledgers, or citizen identities), any data harvested today will be compromised before its secrecy requirement expires. This makes immediate quantum readiness an urgent operational priority.'
              },
              {
                q: 'What is a Cryptographic Bill of Materials (CBOM) and why do NIST and NSA mandate it?',
                a: 'A Cryptographic Bill of Materials (CBOM) is a standardized, machine-readable inventory of every cryptographic algorithm, key length, certificate, protocol, and trust root operating across software, firmware, and infrastructure. Similar to an SBOM for software packages, a CBOM defines cryptographic lineage and posture (CycloneDX 1.6 format).\n\nWhite House OMB M-23-02, NSM-10, and NIST SP 800-227 mandate CBOM inventories because organizations cannot migrate what they cannot see. Automated CBOM generation is now required for federal contractors and public sector defense suppliers.'
              },
              {
                q: 'Can QuarkShield run completely air-gapped in SCIF or classified defense environments?',
                a: 'Yes. QuarkShield provides a fully self-contained offline scanner binary that requires zero outbound internet access and zero connection to external telemetry. It outputs a local JSON or CycloneDX CBOM report directly to disk, allowing defense analysts to ingest reports into isolated enclaves, SIEMs, or offline compliance auditors without touching external networks.'
              },
              {
                q: 'How does Mosca\'s Theorem (X + Y > Z) determine if an organization is already compromised?',
                a: 'Dr. Michele Mosca established the mathematical benchmark for quantum cryptographic risk: X = how many years your sensitive data must remain secret; Y = how many years it will take your organization to fully transition its systems to quantum-safe cryptography; Z = how many years until a quantum computer capable of breaking classical public-key cryptography exists.\n\nIf X + Y > Z, your organization is already in a state of compromised security because data harvested today will still be secret when quantum decryption becomes feasible. QuarkShield\'s interactive migration planner models this exact inequality for your enterprise.'
              }
            ].map((faq, idx) => {
              const isOpen = openFaqIndex === idx;
              return (
                <div key={idx} style={{
                  background: 'var(--surface)',
                  border: isOpen ? '1px solid var(--purple)' : '1px solid var(--line)',
                  borderRadius: '12px',
                  overflow: 'hidden',
                  transition: 'all 0.2s ease'
                }}>
                  <button
                    onClick={() => setOpenFaqIndex(isOpen ? null : idx)}
                    style={{
                      width: '100%',
                      padding: '16px 20px',
                      background: 'none',
                      border: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      color: 'var(--text)'
                    }}
                  >
                    <span style={{ fontSize: '0.98rem', fontWeight: 600, color: isOpen ? 'var(--cyan)' : 'var(--text)' }}>
                      {faq.q}
                    </span>
                    <span style={{ color: isOpen ? 'var(--cyan)' : 'var(--muted)', fontSize: '0.8rem' }}>
                      {isOpen ? '▲' : '▼'}
                    </span>
                  </button>
                  {isOpen && (
                    <div style={{
                      padding: '0 20px 20px 20px',
                      color: 'var(--muted)',
                      fontSize: '0.88rem',
                      lineHeight: 1.65,
                      borderTop: '1px solid var(--line-soft)',
                      paddingTop: '14px',
                      whiteSpace: 'pre-line'
                    }}>
                      {faq.a}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* ===================== ABOUT FEDMITIGATE LLC ===================== */}
      <section className="band" id="about-us">
        <div className="wrap">
          <span className="band-eyebrow">About FedMitigate LLC</span>
          <h2>Engineering National-Grade Cryptographic Defense for the Post-Quantum Horizon</h2>
          <p className="lead">
            QuarkShield is engineered by <strong>FedMitigate LLC</strong>, a specialized defense technology consultancy headquartered in the Washington, D.C. national security corridor. We exist to safeguard sovereign data, critical infrastructure, and distributed enterprise systems against Harvest Now, Decrypt Later (HNDL) state-sponsored adversaries.
          </p>

          <div style={{
            background: 'var(--surface)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius)',
            padding: '28px',
            marginTop: '28px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '28px',
            alignItems: 'center'
          }}>
            <div>
              <div style={{ color: 'var(--cyan)', fontWeight: 700, fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '8px', fontFamily: 'var(--font-mono)' }}>
                Our Core Mission
              </div>
              <h3 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text)', margin: '0 0 12px 0', lineHeight: 1.3 }}>
                Bridging Commercial Agile IT and High-Assurance Defense Cryptography
              </h3>
              <p style={{ color: 'var(--muted)', fontSize: '0.9rem', lineHeight: 1.65, margin: '0 0 12px 0' }}>
                With the finalization of NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA), global public-key cryptography has reached its greatest turning point since the invention of RSA. Classical algorithms are provably insecure against Shor's algorithm on cryptanalytically relevant quantum computers.
              </p>
              <p style={{ color: 'var(--muted)', fontSize: '0.9rem', lineHeight: 1.65, margin: 0 }}>
                QuarkShield solves this vulnerability by providing automated discovery, real-time quantum threat modeling, and continuous Cryptographic Bill of Materials (CBOM) orchestration without requiring kernel modifications or exposing private keys.
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div style={{ background: 'var(--surface-2)', padding: '18px', borderRadius: '10px', border: '1px solid var(--line-soft)' }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--cyan)', fontFamily: 'var(--font-display)' }}>100%</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', marginTop: '4px' }}>Local Secret Isolation</div>
                <div style={{ fontSize: '0.76rem', color: 'var(--faint)', marginTop: '4px' }}>Zero private key exfiltration</div>
              </div>
              <div style={{ background: 'var(--surface-2)', padding: '18px', borderRadius: '10px', border: '1px solid var(--line-soft)' }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--purple)', fontFamily: 'var(--font-display)' }}>CNSA 2.0</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', marginTop: '4px' }}>NSA Modernization Ready</div>
                <div style={{ fontSize: '0.76rem', color: 'var(--faint)', marginTop: '4px' }}>Full 2025–2033 roadmap</div>
              </div>
              <div style={{ background: 'var(--surface-2)', padding: '18px', borderRadius: '10px', border: '1px solid var(--line-soft)' }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--good)', fontFamily: 'var(--font-display)' }}>3-Tier</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', marginTop: '4px' }}>Agentless to Enclave</div>
                <div style={{ fontSize: '0.76rem', color: 'var(--faint)', marginTop: '4px' }}>Probe, host, and enterprise</div>
              </div>
              <div style={{ background: 'var(--surface-2)', padding: '18px', borderRadius: '10px', border: '1px solid var(--line-soft)' }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f59e0b', fontFamily: 'var(--font-display)' }}>Zero Trust</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', marginTop: '4px' }}>Air-Gapped Ready</div>
                <div style={{ fontSize: '0.76rem', color: 'var(--faint)', marginTop: '4px' }}>SCIF and offline deployments</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== CAREERS & APPLIED RESEARCH ===================== */}
      <section className="band" id="careers">
        <div className="wrap">
          <span className="band-eyebrow">Applied Cryptography Careers</span>
          <h2>Join Our Team Protecting Global Infrastructure Against Quantum Threats</h2>
          <p className="lead">
            We are cryptographers, kernel security engineers, and distributed systems architects defending national security systems and global enterprises.
          </p>

          <div style={{
            background: 'var(--surface)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius)',
            padding: '28px',
            marginTop: '28px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px'
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
              {[
                { title: 'Senior Post-Quantum Cryptographer', loc: 'Remote / D.C.', type: 'Full-Time', badge: 'Lattice Algorithms' },
                { title: 'Staff Systems & Kernel Security Engineer', loc: 'Remote (US)', type: 'Full-Time', badge: 'eBPF & Native OS' },
                { title: 'Full-Stack Security Product Engineer', loc: 'Remote (US)', type: 'Full-Time', badge: 'CBOM Analytics' },
                { title: 'Defense PQC Compliance & GRC Lead', loc: 'Washington, D.C.', type: 'Full-Time', badge: 'NSA CNSA 2.0' }
              ].map((role, rIdx) => (
                <div key={rIdx} style={{
                  background: 'var(--surface-2)',
                  border: '1px solid var(--line-soft)',
                  borderRadius: '10px',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  gap: '8px'
                }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--purple)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {role.badge}
                    </span>
                    <h4 style={{ margin: '4px 0', fontSize: '0.96rem', fontWeight: 700, color: 'var(--text)' }}>
                      {role.title}
                    </h4>
                    <span style={{ fontSize: '0.78rem', color: 'var(--faint)' }}>
                      {role.loc} · {role.type}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', paddingTop: '10px', borderTop: '1px solid var(--line-soft)' }}>
              <div style={{ fontSize: '0.88rem', color: 'var(--muted)' }}>
                Explore full job descriptions, algorithm requirements, and security clearances.
              </div>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setShowCareerModal(true)}
              >
                View All Open Roles &amp; Research Positions →
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ===================== FINAL CTA ===================== */}
      <section className="wrap final">
        <h2>Find your cryptographic exposure.<br />Build your PQC migration roadmap.</h2>
        <p>You don't need to wait for a quantum computer to start preparing. The first step is understanding where cryptography is used today.</p>
        <div className="hero-cta" style={{ justifyContent: 'center' }}>
          <button className="btn btn-primary btn-lg" onClick={() => openAssessmentModal()}>
            Request a PQC Assessment
          </button>
          <button className="btn btn-ghost btn-lg" onClick={() => openAssessmentModal('Enterprise Demo')}>
            See a 5-minute demo
          </button>
        </div>
      </section>

      {/* ===================== FOOTER ===================== */}
      <footer>
        <div className="wrap">
          <div className="footer-grid">
            <div className="foot-brand">
              <div className="brand" style={{ marginBottom: '14px' }}>
                <span className="mark" aria-hidden="true">
                  <svg viewBox="0 0 32 32" fill="none">
                    <path d="M16 2 4 7v8c0 7.2 5.1 12.9 12 15 6.9-2.1 12-7.8 12-15V7L16 2Z" fill="url(#g-foot)" stroke="#c084fc" strokeWidth="1.2"/>
                    <path d="M11 16.5 14.5 20 21 12.5" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <defs>
                      <linearGradient id="g-foot" x1="4" y1="2" x2="28" y2="30">
                        <stop stopColor="#b76bfb"/>
                        <stop offset="1" stopColor="#7c3aed"/>
                      </linearGradient>
                    </defs>
                  </svg>
                </span>
                <span className="wordmark"><b>quark</b><i>shield</i></span>
              </div>
              <p>Enterprise cryptographic intelligence — discover, analyze, prioritize and remediate quantum-vulnerable cryptography across your fleet.</p>
              <div className="foot-cta" style={{ marginTop: '16px' }}>
                <button className="btn btn-primary btn-sm" onClick={() => openAssessmentModal()}>
                  Request a PQC Assessment
                </button>
              </div>
            </div>

            <div className="foot-col">
              <h4>Product</h4>
              <ul>
                <li><a href="#platform">Platform</a></li>
                <li><a href="#assessment">PQC Assessment</a></li>
                <li><a href="#probe">TLS Probe</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="#downloads">Downloads</a></li>
              </ul>
            </div>

            <div className="foot-col">
              <h4>Company</h4>
              <ul>
                <li><a href="#about-us">About Us</a></li>
                <li><a href="#careers" onClick={() => setShowCareerModal(true)}>Careers</a></li>
                <li><a href="#" onClick={(e) => { e.preventDefault(); setShowSupportModalState(true); }}>Support</a></li>
                <li><a href="#" onClick={(e) => { e.preventDefault(); setShowSupportModalState(true); }}>Contact</a></li>
              </ul>
            </div>

            <div className="foot-col">
              <h4>Resources</h4>
              <ul>
                <li><a href="https://quarkshield.ai/docs/QUARKSHIELD_ENTERPRISE_FEATURES_GUIDE.md" target="_blank" rel="noopener">Documentation</a></li>
                <li><a href="https://quarkshield.ai/docs/AGENTLESS_PQC_ARCHITECTURE.md" target="_blank" rel="noopener">Agentless PQC Whitepaper</a></li>
                <li><a href="#cnsa-news">Regulatory Radar</a></li>
                <li><a href="https://quarkshield.ai/docs/ENTERPRISE_AGENT_DEPLOYMENT_GUIDE.md" target="_blank" rel="noopener">Deployment Guides</a></li>
              </ul>
            </div>

            <div className="foot-col">
              <h4>Legal</h4>
              <ul>
                <li><a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('privacy'); }}>Privacy Policy</a></li>
                <li><a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('terms'); }}>Terms of Service</a></li>
                <li><a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('disclosure'); }}>Responsible Disclosure</a></li>
              </ul>
            </div>
          </div>

          <div className="foot-bottom">
            <span>© 2026 QuarkShield · a FedMitigate product. All rights reserved.</span>
            <div className="legal-links">
              <a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('privacy'); }}>Privacy Policy</a>
              <a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('terms'); }}>Terms of Service</a>
              <a href="#" onClick={(e) => { e.preventDefault(); setLegalDoc('disclosure'); }}>Responsible Disclosure</a>
            </div>
            <span className="proto-note">◆ Clickable prototype — probes &amp; forms are simulated</span>
          </div>
        </div>
      </footer>

      {/* ===================== ASSESSMENT MODAL (3-STEP) ===================== */}
      {showAssessmentModal && (
        <div className="overlay open" role="dialog" aria-modal="true" onClick={(e) => {
          if (e.target === e.currentTarget) setShowAssessmentModal(false);
        }}>
          <div className="modal">
            <button className="modal-close" onClick={() => setShowAssessmentModal(false)} aria-label="Close">×</button>
            <div className="modal-head">
              <div className="steps">
                <i className={assessmentStep >= 1 ? 'done' : ''}></i>
                <i className={assessmentStep >= 2 ? 'done' : ''}></i>
                <i className={assessmentStep >= 3 ? 'done' : ''}></i>
              </div>
              <h2 className="modal-title">
                {assessmentStep === 1 && 'Request a PQC Readiness Assessment'}
                {assessmentStep === 2 && 'Where should we send it?'}
                {assessmentStep === 3 && "You're all set"}
              </h2>
              <p className="modal-desc">
                {assessmentStep === 1 && 'A concrete first step, not a sales call. Tell us what you\'re focused on.'}
                {assessmentStep === 2 && 'No account needed. We only ask what we need to scope the assessment.'}
                {assessmentStep === 3 && ''}
              </p>
            </div>

            <div className="modal-body">
              {/* STEP 1: Focus chips */}
              {assessmentStep === 1 && (
                <div>
                  <div className="chips">
                    {[
                      'PQC / Quantum Readiness',
                      'Cryptographic Inventory / CBOM',
                      'HNDL Assessment',
                      'Migration Planning',
                      'Enterprise Demo',
                      'Other'
                    ].map((interest) => {
                      const on = selectedInterests.includes(interest);
                      return (
                        <button
                          key={interest}
                          type="button"
                          className="chip"
                          aria-pressed={on}
                          onClick={() => toggleInterest(interest)}
                        >
                          <span className="tick">
                            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="3">
                              <path d="M4 10l4 4 8-8" strokeLinecap="round" strokeLinejoin="round"/>
                            </svg>
                          </span>
                          {interest === 'Cryptographic Inventory / CBOM' ? 'Inventory / CBOM' : interest}
                        </button>
                      );
                    })}
                  </div>
                  <p className="email-fallback">
                    Prefer email? Send your request straight to{' '}
                    <a href="mailto:PQCA@quarkshield.ai?subject=QuarkShield%20PQC%20Assessment%20Request">
                      PQCA@quarkshield.ai
                    </a>
                  </p>
                </div>
              )}

              {/* STEP 2: Details */}
              {assessmentStep === 2 && (
                <div className="form-grid">
                  <div className={`field ${assessmentErrors.name ? 'invalid' : ''}`}>
                    <label>Name <span className="req">*</span></label>
                    <input
                      type="text"
                      placeholder="Jordan Reyes"
                      value={assessmentForm.name}
                      onChange={(e) => setAssessmentForm({ ...assessmentForm, name: e.target.value })}
                    />
                    {assessmentErrors.name && <div className="err">{assessmentErrors.name}</div>}
                  </div>

                  <div className={`field ${assessmentErrors.email ? 'invalid' : ''}`}>
                    <label>Work email <span className="req">*</span></label>
                    <input
                      type="email"
                      placeholder="jordan@acme.com"
                      value={assessmentForm.email}
                      onChange={(e) => setAssessmentForm({ ...assessmentForm, email: e.target.value })}
                    />
                    {assessmentErrors.email && <div className="err">{assessmentErrors.email}</div>}
                  </div>

                  <div className={`field fg-full ${assessmentErrors.company ? 'invalid' : ''}`}>
                    <label>Company <span className="req">*</span></label>
                    <input
                      type="text"
                      placeholder="Acme Corp"
                      value={assessmentForm.company}
                      onChange={(e) => setAssessmentForm({ ...assessmentForm, company: e.target.value })}
                    />
                    {assessmentErrors.company && <div className="err">{assessmentErrors.company}</div>}
                  </div>

                  <div className="field">
                    <label>Role</label>
                    <select
                      value={assessmentForm.role}
                      onChange={(e) => setAssessmentForm({ ...assessmentForm, role: e.target.value })}
                    >
                      <option value="">Select…</option>
                      <option>CISO / CSO</option>
                      <option>CIO / CTO</option>
                      <option>Security Architect</option>
                      <option>Security Engineering</option>
                      <option>PKI / IAM / PAM Lead</option>
                      <option>GRC / Compliance</option>
                      <option>Other</option>
                    </select>
                  </div>

                  <div className="field">
                    <label>Environment size</label>
                    <select
                      value={assessmentForm.size}
                      onChange={(e) => setAssessmentForm({ ...assessmentForm, size: e.target.value })}
                    >
                      <option value="">Select…</option>
                      <option>&lt; 250 endpoints</option>
                      <option>250–1,000</option>
                      <option>1,000–10,000</option>
                      <option>10,000+</option>
                    </select>
                  </div>
                </div>
              )}

              {/* STEP 3: Confirmation */}
              {assessmentStep === 3 && (
                <div className="confirm">
                  <div className="check">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  </div>
                  <h3>Assessment request received</h3>
                  <p>
                    Thanks — your request has been routed to the QuarkShield PQC Assessment team at{' '}
                    <b>PQCA@quarkshield.ai</b>. A cryptography engineer will reply to <b>{assessmentForm.email}</b> within one business day.
                  </p>
                  <div className="next-list">
                    <div className="next-item">
                      <span className="n">1</span>
                      <span>Scoping call (~20 min) to confirm environment and priorities.</span>
                    </div>
                    <div className="next-item">
                      <span className="n">2</span>
                      <span>Deploy the signed desktop scanner to a sample of hosts — zero-exfiltration, local-first.</span>
                    </div>
                    <div className="next-item">
                      <span className="n">3</span>
                      <span>Receive your CBOM, Quantum Risk Score and phased migration roadmap.</span>
                    </div>
                  </div>
                  <div className="recap">
                    <b>Company</b> {assessmentForm.company} &nbsp;·&nbsp; <b>Role</b> {assessmentForm.role || '—'} &nbsp;·&nbsp; <b>Size</b> {assessmentForm.size || '—'}
                    <br />
                    <b>Focus</b> {selectedInterests.join(', ') || 'General PQC readiness'} &nbsp;·&nbsp; <b>Benchmark</b> {plannerSector.name}
                  </div>
                </div>
              )}
            </div>

            <div className="modal-foot">
              {assessmentStep === 2 && (
                <button className="btn btn-ghost btn-sm" onClick={() => setAssessmentStep(1)}>
                  ← Back
                </button>
              )}
              <span className="step-hint">
                {assessmentStep === 1 && 'Step 1 of 3 · pick at least one'}
                {assessmentStep === 2 && 'Step 2 of 3 · your details'}
                {assessmentStep === 3 && 'Step 3 of 3 · confirmed'}
              </span>
              <span className="spacer"></span>
              {assessmentStep === 1 && (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => {
                    if (selectedInterests.length === 0) {
                      showToast('Please select at least one area of focus.');
                      return;
                    }
                    setAssessmentStep(2);
                  }}
                >
                  Continue →
                </button>
              )}
              {assessmentStep === 2 && (
                <button
                  className="btn btn-primary btn-sm"
                  disabled={isSubmittingAssessment}
                  onClick={submitAssessment}
                >
                  {isSubmittingAssessment ? 'Submitting…' : 'Submit request →'}
                </button>
              )}
              {assessmentStep === 3 && (
                <button className="btn btn-primary btn-sm" onClick={() => setShowAssessmentModal(false)}>
                  Done
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================== SUPPORT MODAL ===================== */}
      {showSupportModalState && (
        <div className="overlay open" role="dialog" aria-modal="true" onClick={(e) => {
          if (e.target === e.currentTarget) setShowSupportModalState(false);
        }}>
          <div className="modal">
            <button className="modal-close" onClick={() => setShowSupportModalState(false)} aria-label="Close">×</button>
            <div className="modal-head">
              <h2 className="modal-title">Contact Support</h2>
              <p className="modal-desc">Tell us what's going on — our enterprise support desk will get back to you.</p>
            </div>
            <div className="modal-body">
              {!supportSubmitted ? (
                <div>
                  <div className="form-grid">
                    <div className={`field ${supportErrors.name ? 'invalid' : ''}`}>
                      <label>Name <span className="req">*</span></label>
                      <input
                        type="text"
                        placeholder="Jordan Reyes"
                        value={supportForm.name}
                        onChange={(e) => setSupportForm({ ...supportForm, name: e.target.value })}
                      />
                      {supportErrors.name && <div className="err">{supportErrors.name}</div>}
                    </div>
                    <div className={`field ${supportErrors.email ? 'invalid' : ''}`}>
                      <label>Work email <span className="req">*</span></label>
                      <input
                        type="email"
                        placeholder="jordan@acme.com"
                        value={supportForm.email}
                        onChange={(e) => setSupportForm({ ...supportForm, email: e.target.value })}
                      />
                      {supportErrors.email && <div className="err">{supportErrors.email}</div>}
                    </div>
                    <div className="field">
                      <label>Company</label>
                      <input
                        type="text"
                        placeholder="Acme Corp"
                        value={supportForm.company}
                        onChange={(e) => setSupportForm({ ...supportForm, company: e.target.value })}
                      />
                    </div>
                    <div className="field">
                      <label>Category</label>
                      <select
                        value={supportForm.category}
                        onChange={(e) => setSupportForm({ ...supportForm, category: e.target.value })}
                      >
                        <option>Technical issue</option>
                        <option>Billing</option>
                        <option>Licensing &amp; seats</option>
                        <option>Account &amp; access</option>
                        <option>General question</option>
                      </select>
                    </div>
                    <div className={`field fg-full ${supportErrors.subject ? 'invalid' : ''}`}>
                      <label>Subject <span className="req">*</span></label>
                      <input
                        type="text"
                        placeholder="Brief summary"
                        value={supportForm.subject}
                        onChange={(e) => setSupportForm({ ...supportForm, subject: e.target.value })}
                      />
                      {supportErrors.subject && <div className="err">{supportErrors.subject}</div>}
                    </div>
                    <div className={`field fg-full ${supportErrors.message ? 'invalid' : ''}`}>
                      <label>How can we help? <span className="req">*</span></label>
                      <textarea
                        rows={4}
                        placeholder="Describe the issue, affected hosts/tenant, and any error messages."
                        value={supportForm.message}
                        onChange={(e) => setSupportForm({ ...supportForm, message: e.target.value })}
                      />
                      {supportErrors.message && <div className="err">{supportErrors.message}</div>}
                    </div>
                  </div>
                  <p className="email-fallback">
                    Prefer email? Write to{' '}
                    <a href="mailto:support@quarkshield.ai?subject=QuarkShield%20Support%20Request">
                      support@quarkshield.ai
                    </a>
                  </p>
                </div>
              ) : (
                <div className="confirm">
                  <div className="check">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  </div>
                  <h3>Support request sent</h3>
                  <p>
                    Thanks — your request has been routed to <b>support@quarkshield.ai</b>. We'll reply to{' '}
                    <b>{supportForm.email}</b> within one business day.
                  </p>
                  <div className="recap">
                    <b>Category</b> {supportForm.category} &nbsp;·&nbsp; <b>Subject</b> {supportForm.subject}
                  </div>
                </div>
              )}
            </div>
            <div className="modal-foot">
              <span className="step-hint">
                {supportSubmitted ? 'Sent ✓' : 'Routed to support@quarkshield.ai · reply within 1 business day'}
              </span>
              <span className="spacer"></span>
              {!supportSubmitted ? (
                <button
                  className="btn btn-primary btn-sm"
                  disabled={isSubmittingSupport}
                  onClick={submitSupport}
                >
                  {isSubmittingSupport ? 'Sending…' : 'Send request'}
                </button>
              ) : (
                <button className="btn btn-primary btn-sm" onClick={() => setShowSupportModalState(false)}>
                  Close
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================== LEGAL READER MODAL ===================== */}
      {legalDoc && (
        <div className="overlay open" role="dialog" aria-modal="true" onClick={(e) => {
          if (e.target === e.currentTarget) setLegalDoc(null);
        }}>
          <div className="modal legal-modal">
            <button className="modal-close" onClick={() => setLegalDoc(null)} aria-label="Close">×</button>
            <div className="modal-head">
              <h2 className="modal-title">
                {legalDoc === 'privacy' && 'Privacy Policy'}
                {legalDoc === 'terms' && 'Terms of Service'}
                {legalDoc === 'disclosure' && 'Responsible Disclosure'}
              </h2>
              <p className="modal-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                Last updated: 25 September 2026
              </p>
            </div>
            <div className="legal-body">
              {legalDoc === 'privacy' && (
                <>
                  <p>QuarkShield is built <b>local-first</b>. Cryptographic scanning runs on your own hosts, and by default the resulting Cryptographic Bill of Materials (CBOM) and scan artifacts never leave your environment. This policy explains what we do collect when you use our website, console and scanners.</p>
                  <h4>1. Information we collect</h4>
                  <ul>
                    <li><b>Account &amp; contact</b> — name, work email, company, role, and environment size you provide when requesting an assessment or creating a tenant.</li>
                    <li><b>Billing</b> — processed by Stripe. We store your subscription tier, status and customer identifiers; we never see or store full card numbers.</li>
                    <li><b>Fleet telemetry (opt-in)</b> — when you connect endpoints to the Cloud Fleet plane, we receive the metadata you choose to sync: asset counts, algorithm findings, risk grades and drift events, scoped to your tenant.</li>
                    <li><b>Site usage</b> — standard analytics (pages viewed, CTA interactions) to improve the product. No cross-site advertising trackers.</li>
                  </ul>
                  <h4>2. What stays on your host</h4>
                  <p>Raw scan output — file paths, private-key locations, certificate contents and the full CBOM — is generated and stored locally by the scanner. It is transmitted to QuarkShield only if you explicitly enable cloud sync for a tenant, and then only over TLS to your isolated tenant space.</p>
                  <h4>3. How we use information</h4>
                  <p>To provision and operate your tenant, deliver assessments, process billing, provide support, meet legal obligations, and secure the service. We do not sell personal data.</p>
                  <h4>4. Sub-processors</h4>
                  <p>We use a limited set of vetted providers (for example, cloud hosting, Stripe for payments, and transactional email). A current list is available on request.</p>
                  <h4>5. Retention</h4>
                  <p>Account and billing records are retained for the life of the subscription plus any period required by law. Synced fleet telemetry is retained per your tenant configuration and deleted on request or account closure.</p>
                  <h4>6. Your rights</h4>
                  <p>Depending on your jurisdiction you may request access, correction, export or deletion of your personal data. Contact <b>privacy@quarkshield.ai</b>.</p>
                  <h4>7. Contact</h4>
                  <p>QuarkShield (a FedMitigate product) — <b>privacy@quarkshield.ai</b></p>
                  <div className="disclaimer">◆ Prototype draft for review — not yet legal advice. Have counsel review before publishing to quarkshield.ai.</div>
                </>
              )}

              {legalDoc === 'terms' && (
                <>
                  <p>These Terms govern your access to and use of the QuarkShield website, console, scanners and related services (the "Service"). By using the Service you agree to these Terms.</p>
                  <h4>1. Accounts &amp; eligibility</h4>
                  <p>You must provide accurate information and are responsible for activity under your account and for safeguarding your credentials and 2FA. The Service is intended for business and organizational use.</p>
                  <h4>2. License</h4>
                  <p>Subject to your subscription and these Terms, we grant you a non-exclusive, non-transferable right to use the Service and to run the scanners on endpoints you own or are authorized to assess, up to your licensed endpoint count.</p>
                  <h4>3. Acceptable use</h4>
                  <ul>
                    <li>Only scan systems you own or have explicit authorization to assess.</li>
                    <li>Do not reverse engineer, resell or sublicense the Service except under a signed partner agreement.</li>
                    <li>Do not use the Service to violate law or infringe third-party rights.</li>
                  </ul>
                  <h4>4. Fees &amp; billing</h4>
                  <p>Paid tiers are billed in advance through Stripe on a monthly or annual cycle and renew automatically until cancelled. Fees are non-refundable except where required by law.</p>
                  <h4>5. Your data</h4>
                  <p>You retain all rights to your CBOM, scan output and fleet data. You grant us only the limited rights needed to operate the Service for you. See the Privacy Policy.</p>
                  <h4>6. Warranties &amp; disclaimer</h4>
                  <p>QuarkShield helps you discover and prioritize cryptographic risk but does not guarantee detection of every asset or vulnerability. The Service is provided "as is" without warranties of any kind to the maximum extent permitted by law.</p>
                  <h4>7. Limitation of liability</h4>
                  <p>To the maximum extent permitted by law, neither party is liable for indirect or consequential damages, and our aggregate liability is limited to the fees paid in the twelve months preceding the claim.</p>
                  <h4>8. Term &amp; termination</h4>
                  <p>Either party may terminate for material breach not cured within 30 days. On termination your license ends and you may export your data for 30 days.</p>
                  <h4>9. Governing law</h4>
                  <p>These Terms are governed by the laws of the State of Delaware, USA, unless a signed enterprise agreement states otherwise.</p>
                  <h4>10. Contact</h4>
                  <p><b>legal@quarkshield.ai</b></p>
                  <div className="disclaimer">◆ Prototype draft for review — not yet legal advice. Have counsel review before publishing to quarkshield.ai.</div>
                </>
              )}

              {legalDoc === 'disclosure' && (
                <>
                  <p>Security is core to what QuarkShield does. We welcome reports from researchers and will work with you in good faith to verify and fix valid issues.</p>
                  <h4>Scope</h4>
                  <ul>
                    <li><b>quarkshield.ai</b> and tenant subdomains <b>*.quarkshield.ai</b></li>
                    <li>The QuarkShield console and Cloud Fleet APIs</li>
                    <li>The signed desktop / host scanners and enrollment agent</li>
                  </ul>
                  <h4>How to report</h4>
                  <p>Email <b>security@quarkshield.ai</b> with steps to reproduce, affected components and any proof-of-concept. For sensitive findings, request our PGP key in your first message and we will provide it for encrypted follow-up.</p>
                  <h4>Safe harbor</h4>
                  <p>If you make a good-faith effort to comply with this policy, we will not pursue legal action against you for your research. Act in good faith, avoid privacy violations and service disruption, and only interact with accounts you own or have permission to test.</p>
                  <h4>What to expect</h4>
                  <ul>
                    <li>Acknowledgement within <b>3 business days</b>.</li>
                    <li>Initial triage and severity assessment within <b>10 business days</b>.</li>
                    <li>Coordinated remediation timelines based on severity, with credit if you wish.</li>
                  </ul>
                  <h4>Out of scope</h4>
                  <ul>
                    <li>Denial-of-service and volumetric testing</li>
                    <li>Social engineering, phishing and physical attacks</li>
                    <li>Automated scanner output without a demonstrated, exploitable impact</li>
                  </ul>
                  <h4>Recognition</h4>
                  <p>With your permission we credit valid reports in our security acknowledgements. Contact: <b>security@quarkshield.ai</b></p>
                  <div className="disclaimer">◆ Prototype draft for review — not yet legal advice. Have counsel review before publishing to quarkshield.ai.</div>
                </>
              )}
            </div>
            <div className="modal-foot">
              <span className="step-hint">QuarkShield · a FedMitigate product</span>
              <span className="spacer"></span>
              <button className="btn btn-primary btn-sm" onClick={() => setLegalDoc(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ===================== SIGN-IN MODAL ===================== */}
      {showSignInModal && (
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
          zIndex: 2000,
          padding: '1.5rem'
        }}>
          <div style={{
            background: 'var(--surface-2)',
            maxWidth: '480px',
            width: '100%',
            borderRadius: '14px',
            border: '1px solid var(--line)',
            boxShadow: '0 24px 60px rgba(0, 0, 0, 0.85)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--line-soft)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className="wordmark" style={{ fontSize: '1.4rem' }}><b>quark</b><i>shield</i></span>
                <span style={{ fontSize: '0.85rem', color: 'var(--muted)', fontWeight: 600 }}>| Console Sign In</span>
              </div>
              <button
                onClick={() => {
                  setShowSignInModal(false);
                  setSignInError(null);
                }}
                style={{ background: 'none', border: 'none', color: 'var(--faint)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleSignIn} style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
              {signInError && (
                <div style={{
                  padding: '0.75rem 1rem',
                  borderRadius: '8px',
                  background: 'rgba(251, 90, 118, 0.15)',
                  border: '1px solid rgba(251, 90, 118, 0.3)',
                  color: 'var(--critical)',
                  fontSize: '0.85rem'
                }}>
                  {signInError}
                </div>
              )}

              {signInSuccessMsg && (
                <div style={{
                  padding: '0.75rem 1rem',
                  borderRadius: '8px',
                  background: 'rgba(52, 211, 153, 0.15)',
                  border: '1px solid rgba(52, 211, 153, 0.3)',
                  color: 'var(--good)',
                  fontSize: '0.85rem'
                }}>
                  {signInSuccessMsg}
                </div>
              )}

              <div className="field">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label style={{ margin: 0 }}>Work Email or Account Identifier</label>
                  <span style={{ fontSize: '0.74rem', color: 'var(--muted)', fontWeight: 500 }}>e.g. superadmin or name@company.com</span>
                </div>
                <input
                  type="text"
                  placeholder="e.g. name@company.com or superadmin"
                  value={loginIdentifier}
                  onChange={(e) => {
                    setLoginIdentifier(e.target.value);
                    if (signInError) setSignInError(null);
                  }}
                  autoComplete="username"
                  required
                />
              </div>

              <div className="field">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label style={{ margin: 0 }}>Password</label>
                  <button
                    type="button"
                    onClick={() => {
                      setShowSignInModal(false);
                      setShowForgotPasswordModal(true);
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: 0,
                      color: 'var(--cyan)',
                      fontSize: '0.76rem',
                      cursor: 'pointer'
                    }}
                  >
                    Forgot password?
                  </button>
                </div>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    autoComplete="current-password"
                    style={{ paddingRight: '2.5rem' }}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      position: 'absolute',
                      right: '0.75rem',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'var(--muted)',
                      cursor: 'pointer'
                    }}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="field">
                <label>Workspace Domain (Optional)</label>
                <input
                  type="text"
                  placeholder="spinovationcorp (leave blank for auto-routing)"
                  value={loginWorkspace}
                  onChange={(e) => setLoginWorkspace(e.target.value)}
                />
              </div>

              <div className="field">
                <label>2FA / TOTP Code (Optional)</label>
                <input
                  type="text"
                  placeholder="6-digit authenticator code (if enabled)"
                  value={login2FACode}
                  onChange={(e) => setLogin2FACode(e.target.value)}
                  maxLength={6}
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={isAuthenticating}
                style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}
              >
                {isAuthenticating ? 'Authenticating...' : 'Sign In to Console →'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ===================== FORGOT PASSWORD MODAL ===================== */}
      {showForgotPasswordModal && (
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
          zIndex: 2000,
          padding: '1.5rem'
        }}>
          <div style={{
            background: 'var(--surface-2)',
            maxWidth: '460px',
            width: '100%',
            borderRadius: '14px',
            border: '1px solid var(--line)',
            boxShadow: '0 24px 60px rgba(0, 0, 0, 0.85)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--line-soft)'
            }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Reset Console Password</h3>
              <button
                onClick={() => {
                  setShowForgotPasswordModal(false);
                  setForgotSubmitted(false);
                  setShowSignInModal(true);
                }}
                style={{ background: 'none', border: 'none', color: 'var(--faint)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>
            <div style={{ padding: '1.5rem' }}>
              {forgotSubmitted ? (
                <div style={{ textAlign: 'center' }}>
                  <p style={{ color: 'var(--good)', marginBottom: '1.5rem' }}>
                    If an account exists for {forgotEmail}, a secure reset link has been dispatched.
                  </p>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => {
                      setShowForgotPasswordModal(false);
                      setForgotSubmitted(false);
                      setShowSignInModal(true);
                    }}
                  >
                    Back to Sign In
                  </button>
                </div>
              ) : (
                <form onSubmit={handleForgotPassword} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <p style={{ color: 'var(--muted)', fontSize: '0.88rem' }}>
                    Enter your work email address to receive password reset instructions.
                  </p>
                  {forgotError && <div style={{ color: 'var(--critical)', fontSize: '0.85rem' }}>{forgotError}</div>}
                  <div className="field">
                    <label>Work Email</label>
                    <input
                      type="email"
                      placeholder="admin@company.com"
                      value={forgotEmail}
                      onChange={(e) => setForgotEmail(e.target.value)}
                      required
                    />
                  </div>
                  <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
                    Send Reset Link
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ===================== FORCE CHANGE PASSWORD MODAL ===================== */}
      {showForceChangeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2000,
          padding: '1.5rem'
        }}>
          <div style={{
            background: 'var(--surface-2)',
            maxWidth: '480px',
            width: '100%',
            borderRadius: '14px',
            border: '1px solid var(--purple-line)',
            boxShadow: '0 24px 60px rgba(0, 0, 0, 0.85)',
            padding: '1.5rem'
          }}>
            <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1.15rem' }}>Set Permanent Password</h3>
            <p style={{ color: 'var(--muted)', fontSize: '0.88rem', marginBottom: '1.25rem' }}>
              Your account was provisioned with a temporary password. Please set a secure permanent password to continue.
            </p>

            {forceChangeError && (
              <div style={{ padding: '0.65rem', background: 'rgba(251,90,118,0.15)', color: 'var(--critical)', borderRadius: '8px', fontSize: '0.85rem', marginBottom: '1rem' }}>
                {forceChangeError}
              </div>
            )}
            {forceChangeSuccess && (
              <div style={{ padding: '0.65rem', background: 'rgba(52,211,153,0.15)', color: 'var(--good)', borderRadius: '8px', fontSize: '0.85rem', marginBottom: '1rem' }}>
                {forceChangeSuccess}
              </div>
            )}

            <form onSubmit={handleForceChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div className="field">
                <label>Current Temporary Password</label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showForceCurrent ? 'text' : 'password'}
                    value={forceCurrentPassword}
                    onChange={(e) => setForceCurrentPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowForceCurrent(!showForceCurrent)}
                    style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer' }}
                  >
                    {showForceCurrent ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="field">
                <label>New Permanent Password (min. 8 characters)</label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showForceNew ? 'text' : 'password'}
                    value={forceNewPassword}
                    onChange={(e) => setForceNewPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowForceNew(!showForceNew)}
                    style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer' }}
                  >
                    {showForceNew ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="field">
                <label>Confirm Permanent Password</label>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showForceConfirm ? 'text' : 'password'}
                    value={forceConfirmPassword}
                    onChange={(e) => setForceConfirmPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowForceConfirm(!showForceConfirm)}
                    style={{ position: 'absolute', right: '0.75rem', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer' }}
                  >
                    {showForceConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
                Update Password &amp; Launch Console →
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ===================== STRIPE CHECKOUT MODAL ===================== */}
      {showStripeModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Subscribe to Plan"
          style={{
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
            zIndex: 2000,
            padding: '1.5rem'
          }}
          onClick={() => setShowStripeModal(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--surface-2)',
              maxWidth: '500px',
              width: '100%',
              borderRadius: '14px',
              border: '1px solid var(--line)',
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.85)',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden'
            }}
          >
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--line-soft)'
            }}>
              <h3 style={{ margin: 0, fontSize: '1.15rem' }}>
                Subscribe to {stripeTier === 'entry' ? 'PQC Assessment' : stripeTier === 'scale' ? 'Growth Fleet' : 'Enterprise Pro'}
              </h3>
              <button
                onClick={() => setShowStripeModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--faint)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleStripeCheckout} style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ background: 'var(--surface)', padding: '0.85rem', borderRadius: '8px', fontSize: '0.88rem' }}>
                <b>Plan:</b> {stripeTier.toUpperCase()} &nbsp;·&nbsp;
                <b>Billing:</b> {stripeBillingCycle === 'annual' ? 'Annual (~17% savings)' : 'Monthly'} &nbsp;·&nbsp;
                <b>Price:</b> {stripeTier === 'entry' ? (stripeBillingCycle === 'annual' ? '$249/mo' : '$300/mo') : stripeTier === 'scale' ? (stripeBillingCycle === 'annual' ? '$2,075/mo' : '$2,500/mo') : (stripeBillingCycle === 'annual' ? '$8,300/mo' : '$10,000/mo')}
              </div>
              {stripeError && (
                <div style={{
                  padding: '0.75rem',
                  borderRadius: '6px',
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid var(--critical)',
                  color: '#f87171',
                  fontSize: '0.85rem'
                }}>
                  {stripeError}
                </div>
              )}
              <div className="field">
                <label>Company / Organization Name <span className="req">*</span></label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Aerospace Corp"
                  value={checkoutForm.companyName}
                  onChange={(e) => setCheckoutForm(prev => ({ ...prev, companyName: e.target.value }))}
                />
              </div>
              <div className="field">
                <label>Contact Name</label>
                <input
                  type="text"
                  placeholder="e.g. Jane Doe"
                  value={checkoutForm.contactName}
                  onChange={(e) => setCheckoutForm(prev => ({ ...prev, contactName: e.target.value }))}
                />
              </div>
              <div className="field">
                <label>Corporate Email (Billing &amp; Super Admin) <span className="req">*</span></label>
                <input
                  type="email"
                  required
                  placeholder="admin@acme.com"
                  value={checkoutForm.email}
                  onChange={(e) => setCheckoutForm(prev => ({ ...prev, email: e.target.value }))}
                />
              </div>

              <div style={{
                fontSize: '0.78rem',
                color: 'var(--muted)',
                lineHeight: 1.5,
                background: 'rgba(0, 242, 254, 0.04)',
                border: '1px solid rgba(0, 242, 254, 0.15)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem'
              }}>
                🔒 You will be redirected to Stripe's PCI-DSS Level 1 compliant checkout to finalize your payment securely. Your QuarkShield tenant and license keys will be provisioned immediately.
              </div>

              <button
                type="submit"
                disabled={stripeLoading}
                className="btn btn-primary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.85rem',
                  fontWeight: 700,
                  fontSize: '0.95rem'
                }}
              >
                {stripeLoading ? (
                  <>
                    <RefreshCw size={16} className="spin" style={{ animation: 'spin 1s linear infinite' }} /> Connecting to Stripe...
                  </>
                ) : (
                  <>
                    <Lock size={16} /> Proceed to Stripe Checkout <ArrowRight size={16} />
                  </>
                )}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Careers & Research Positions Modal */}
      {showCareerModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="QuarkShield Careers & Research"
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            backgroundColor: 'rgba(4, 7, 14, 0.82)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.25rem'
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowCareerModal(false);
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: '100%',
              maxWidth: '920px',
              maxHeight: '90vh',
              background: 'linear-gradient(180deg, #0d1322 0%, #080c16 100%)',
              border: '1px solid rgba(168, 85, 247, 0.35)',
              borderRadius: '16px',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 40px rgba(168, 85, 247, 0.15)',
              overflow: 'hidden'
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '1.5rem 1.75rem',
                borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                background: 'rgba(15, 23, 42, 0.6)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '10px',
                    background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(127, 0, 255, 0.35) 100%)',
                    border: '1px solid rgba(168, 85, 247, 0.5)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#c084fc'
                  }}
                >
                  <Briefcase size={22} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.015em' }}>
                    Careers &amp; Applied Cryptography Research
                  </h3>
                  <p style={{ margin: 0, fontSize: '0.86rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Join our team safeguarding national defense systems and enterprise infrastructure against quantum decryption.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowCareerModal(false)}
                aria-label="Close careers modal"
                style={{
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  borderRadius: '8px',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '0.5rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  transition: 'all 0.15s ease'
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body: Scrollable Job Listings */}
            <div
              style={{
                padding: '1.75rem',
                overflowY: 'auto',
                display: 'flex',
                flexDirection: 'column',
                gap: '1.5rem',
                maxHeight: 'calc(90vh - 160px)'
              }}
            >
              {[
                {
                  title: 'Senior Post-Quantum Cryptographer',
                  dept: 'Core Cryptography & Lattice Algorithms',
                  loc: 'Remote (Global) / Hybrid D.C.',
                  type: 'Full-Time',
                  color: '#a855f7',
                  summary: 'Lead algorithm verification, hybrid KEM/DSA protocol design, and hardware-accelerated lattice implementations across our scanner engine and SaaS control plane.',
                  tags: ['NIST FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'FIPS 205 (SLH-DSA)', 'Constant-Time C/Go/Rust', 'Lattice Cryptanalysis'],
                  responsibilities: [
                    'Implement and optimize production-grade ML-KEM and ML-DSA implementations resistant to cache-timing and microarchitectural side-channel attacks.',
                    'Direct the integration of hybrid PQC key exchange schemes (X25519+Kyber/ML-KEM) within enterprise TLS 1.3 and SSH tunnels.',
                    'Collaborate with defense standards bodies and NIST post-quantum standardization committees.'
                  ],
                  applyEmail: 'mailto:careers@quarkshield.ai?subject=Application:%20Senior%20Post-Quantum%20Cryptographer'
                },
                {
                  title: 'Staff Systems & Kernel Security Engineer',
                  dept: 'Endpoint Agent & Native OS Architecture',
                  loc: 'Remote (US/Defense Authorized)',
                  type: 'Full-Time',
                  color: '#c084fc',
                  summary: 'Architect native OS cryptographic store discovery across Windows CryptoAPI/CNG, macOS Keychain/CryptoKit, and Linux NSS/eBPF runtime inspection engines.',
                  tags: ['Windows CNG/CAPI', 'macOS CryptoKit/Security.framework', 'Linux eBPF / OpenSSL 3.x', 'Go & Rust Systems', 'Air-Gapped Daemons'],
                  responsibilities: [
                    'Develop low-overhead, memory-safe agent daemons that discover and inventory private key stores, certificates, and TLS sessions.',
                    'Implement high-throughput kernel event filtering with eBPF and native OS audit hooks for real-time cryptographic posture tracking.',
                    'Ensure zero-crash reliability, strict CPU cap compliance (< 2%), and air-gapped PKI enclave compatibility.'
                  ],
                  applyEmail: 'mailto:careers@quarkshield.ai?subject=Application:%20Staff%20Systems%20%26%20Kernel%20Security%20Engineer'
                },
                {
                  title: 'Full-Stack Security Product Engineer',
                  dept: 'Cloud Platform & Real-Time Visualization',
                  loc: 'Remote (US)',
                  type: 'Full-Time',
                  color: '#38bdf8',
                  summary: 'Build real-time cryptographic BOM (CBOM) visualization graphs, fleet posture analytics, isolated tenant Kubernetes pods, and enterprise RBAC workflows.',
                  tags: ['TypeScript / React', 'Node.js / Express', 'PostgreSQL / Timescale', 'Docker & Kubernetes', 'D3.js / Topology Graphs'],
                  responsibilities: [
                    'Architect reactive, low-latency UI interfaces for visualizing thousands of enterprise cryptographic endpoints and certificates.',
                    'Develop isolated tenant pod provisioning engines, customer SSO integrations (SAML/OIDC), and secure audit log streaming.',
                    'Design automated CycloneDX 1.6 CBOM and NIST SP 800-227 compliance report generators.'
                  ],
                  applyEmail: 'mailto:careers@quarkshield.ai?subject=Application:%20Full-Stack%20Security%20Product%20Engineer'
                },
                {
                  title: 'Defense PQC Compliance & GRC Lead',
                  dept: 'Defense & Regulatory Architecture',
                  loc: 'Washington, D.C. / Remote (US Citizen)',
                  type: 'Full-Time',
                  color: '#fbbf24',
                  summary: 'Align QuarkShield capabilities with NSA CNSA 2.0 milestones, NIST SP 800-171/227, DoD Zero Trust directives, FedRAMP High, and CMMC 2.0 requirements.',
                  tags: ['NSA CNSA 2.0', 'NIST SP 800-171/227', 'CMMC 2.0 Level 3', 'DoD Zero Trust Portfolio', 'FIPS 140-3 CAVP/CMVP'],
                  responsibilities: [
                    'Translate executive orders (M-23-02, NSM-10) and defense procurement mandates into technical assessment criteria in our scanning rules engine.',
                    'Support defense prime contractors and public sector customers with quantum transition roadmaps, risk assessments, and compliance audits.',
                    'Author technical compliance whitepapers and speak at cybersecurity and defense standards conferences.'
                  ],
                  applyEmail: 'mailto:careers@quarkshield.ai?subject=Application:%20Defense%20PQC%20Compliance%20%26%20GRC%20Lead'
                }
              ].map((job, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.55)',
                    border: '1px solid rgba(255, 255, 255, 0.09)',
                    borderRadius: '12px',
                    padding: '1.5rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '1rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap', marginBottom: '0.35rem' }}>
                        <h4 style={{ margin: 0, fontSize: '1.18rem', fontWeight: 800, color: '#ffffff' }}>
                          {job.title}
                        </h4>
                        <span style={{ fontSize: '0.74rem', padding: '0.2rem 0.6rem', borderRadius: '50px', background: `${job.color}20`, color: job.color, fontWeight: 700, border: `1px solid ${job.color}40` }}>
                          {job.type}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
                        <span>{job.dept}</span>
                        <span>•</span>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                          <MapPin size={13} /> {job.loc}
                        </span>
                      </div>
                    </div>
                    <a
                      href={job.applyEmail}
                      style={{
                        background: `linear-gradient(135deg, ${job.color}30 0%, ${job.color}15 100%)`,
                        border: `1px solid ${job.color}60`,
                        color: '#ffffff',
                        padding: '0.55rem 1.15rem',
                        borderRadius: '7px',
                        fontSize: '0.85rem',
                        fontWeight: 700,
                        textDecoration: 'none',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.4rem',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      Apply for Role <ArrowUpRight size={14} />
                    </a>
                  </div>

                  <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                    {job.summary}
                  </p>

                  <div>
                    <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.5rem' }}>
                      Key Responsibilities &amp; Focus
                    </div>
                    <ul style={{ margin: 0, paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      {job.responsibilities.map((resp, rIdx) => (
                        <li key={rIdx} style={{ lineHeight: 1.55 }}>{resp}</li>
                      ))}
                    </ul>
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', paddingTop: '0.25rem' }}>
                    {job.tags.map((tag, tIdx) => (
                      <span
                        key={tIdx}
                        style={{
                          fontSize: '0.74rem',
                          fontFamily: 'var(--font-mono)',
                          padding: '0.25rem 0.55rem',
                          borderRadius: '4px',
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: '#e2e8f0',
                          border: '1px solid rgba(255, 255, 255, 0.08)'
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Modal Footer */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '1.15rem 1.75rem',
                borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                background: 'rgba(15, 23, 42, 0.85)',
                flexWrap: 'wrap',
                gap: '1rem'
              }}
            >
              <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
                Don't see your specific role? Reach out to <a href="mailto:careers@quarkshield.ai" style={{ color: 'var(--accent-cyan)', textDecoration: 'none', fontWeight: 600 }}>careers@quarkshield.ai</a> with your background and research.
              </div>
              <button
                type="button"
                onClick={() => setShowCareerModal(false)}
                style={{
                  background: 'rgba(255, 255, 255, 0.08)',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  color: '#ffffff',
                  padding: '0.5rem 1.25rem',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
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

      {/* Floating Toast Notification */}
      {toastMessage && (
        <div style={{
          position: 'fixed',
          left: '50%',
          bottom: '28px',
          transform: 'translateX(-50%)',
          background: 'var(--surface-2)',
          color: 'var(--text)',
          border: '1px solid var(--line)',
          borderRadius: '10px',
          padding: '12px 18px',
          fontSize: '0.88rem',
          zIndex: 3000,
          boxShadow: '0 18px 40px -18px rgba(0,0,0,0.8)'
        }}>
          {toastMessage}
        </div>
      )}

      {/* Help & Feedback Float */}
      <HelpFeedbackWidget />
    </div>
  );
};

export default LandingPage;
