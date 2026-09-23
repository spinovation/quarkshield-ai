import React, { useState, useEffect } from 'react';
import { 
  GitBranch, 
  GitFork, 
  ShieldAlert, 
  Key, 
  Lock, 
  Unlock, 
  Download, 
  RefreshCw, 
  Search, 
  Code, 
  FileCode, 
  Check, 
  Copy, 
  ChevronDown, 
  ChevronUp, 
  Clock, 
  AlertTriangle, 
  Terminal, 
  ExternalLink,
  Layers,
  Sparkles,
  Info,
  Eye,
  EyeOff,
  ShieldCheck
} from 'lucide-react';

export interface GitFinding {
  id: string;
  category: 'private_key' | 'certificate' | 'source_code' | 'dependency' | 'config' | 'web3';
  filePath: string;
  lineNumber?: number;
  lineContent?: string;
  assetName: string;
  algorithm: string;
  keySize?: number;
  curve?: string;
  quantumThreat: string;
  isVulnerable: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  status: string;
  recommendation: string;
  remediationSnippet?: string;
  complianceStandards: string[];
}

export interface GitScanSummary {
  id: string;
  provider: 'github' | 'bitbucket' | 'gitlab' | 'generic';
  repoUrl: string;
  repoName: string;
  branch: string;
  commitHash?: string;
  commitAuthor?: string;
  commitMessage?: string;
  scannedAt: string;
  scanDurationMs: number;
  totalFilesScanned: number;
  totalAssets: number;
  vulnerableCount: number;
  pqcCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  quantumRiskScore: number;
  cnsaStatus: 'Non-Compliant' | 'Partially Compliant' | 'PQC Ready';
  findings: GitFinding[];
}

interface ScanHistoryItem {
  id: string;
  provider: string;
  repoUrl: string;
  repoName: string;
  branch: string;
  commitHash?: string;
  quantumRiskScore: number;
  totalAssets: number;
  vulnerableCount: number;
  pqcCount: number;
  criticalCount: number;
  summaryText: string;
  scannedAt: string;
}

export const GitRepoAuditor: React.FC = () => {
  // Form State
  const [provider, setProvider] = useState<'github' | 'bitbucket' | 'gitlab' | 'generic'>('github');
  const [repoUrl, setRepoUrl] = useState('');
  const [authType, setAuthType] = useState<'token' | 'public' | 'oauth'>('token');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [branch, setBranch] = useState('main');
  const [showToken, setShowToken] = useState(false);

  // Scanning Execution State
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<GitScanSummary | null>(null);

  // Findings UI State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Scan History
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // CI/CD Security Gate Sub-View State
  const [activeSubView, setActiveSubView] = useState<'scanner' | 'ci_gate'>('scanner');
  const [ciGates, setCiGates] = useState<any[]>([]);
  const [loadingCiGates, setLoadingCiGates] = useState(false);
  const [selectedGateReport, setSelectedGateReport] = useState<any | null>(null);
  const [selectedCiProvider, setSelectedCiProvider] = useState<'github' | 'gitlab' | 'bitbucket' | 'runner'>('github');
  const [ciTemplateCode, setCiTemplateCode] = useState<string>('');
  const [ciCopied, setCiCopied] = useState(false);
  const [testingGate, setTestingGate] = useState(false);

  const fetchCiGates = async () => {
    setLoadingCiGates(true);
    try {
      const res = await fetch('/api/git/ci-gate/history');
      if (res.ok) {
        const data = await res.json();
        setCiGates(data);
      }
    } catch (e) {
      console.error('Error fetching CI gates:', e);
    } finally {
      setLoadingCiGates(false);
    }
  };

  const fetchCiTemplate = async (prov: string) => {
    try {
      const res = await fetch(`/api/git/ci-gate/templates/${prov}`);
      if (res.ok) {
        const text = await res.text();
        setCiTemplateCode(text);
      }
    } catch (e) {
      console.error('Error fetching CI template:', e);
    }
  };

  useEffect(() => {
    if (activeSubView === 'ci_gate') {
      fetchCiGates();
      fetchCiTemplate(selectedCiProvider);
    }
  }, [activeSubView, selectedCiProvider]);

  const handleSimulateGate = async (shouldFail: boolean) => {
    try {
      setTestingGate(true);
      const res = await fetch('/api/git/ci-gate/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedCiProvider === 'runner' ? 'github' : selectedCiProvider,
          repoName: 'spinovation/payments-v2',
          branch: shouldFail ? 'feature/legacy-auth' : 'fix/pqc-kem',
          prNumber: `PR #${Math.floor(110 + Math.random() * 80)}`,
          commitHash: Math.random().toString(16).substring(2, 9),
          commitAuthor: 'devops@spinovation.com',
          commitMessage: shouldFail ? 'feat: implement payment signing with RSA' : 'fix: migrate tokens to NIST FIPS 203 ML-KEM',
          filesChanged: shouldFail ? [
            {
              path: 'src/crypto/signer.ts',
              content: `import crypto from 'crypto';\nconst privateKey = '-----BEGIN RSA PRIVATE KEY-----...';\nexport function sign() { return crypto.createSign('SHA256'); }`
            }
          ] : [
            {
              path: 'src/crypto/pqc.ts',
              content: `import { mlkem768 } from '@quarkshield/pqc';\nexport function keyExchange() { return mlkem768.generateKeyPair(); }`
            }
          ]
        })
      });

      if (res.ok) {
        await fetchCiGates();
      }
    } catch (err) {
      console.error('Error simulating gate:', err);
    } finally {
      setTestingGate(false);
    }
  };

  // Fetch scan history on load
  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await fetch('/api/scan/remote-git/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.warn('Could not fetch git scan history:', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleStartScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!repoUrl.trim()) {
      setErrorMsg('Please enter a repository URL.');
      return;
    }

    setIsScanning(true);
    setErrorMsg(null);
    setScanStep('Initializing secure ephemeral sandbox...');

    try {
      const stepTimer1 = setTimeout(() => setScanStep('Connecting to remote Git server and cloning shallow AST tree...'), 1200);
      const stepTimer2 = setTimeout(() => setScanStep('Traversing source files & inspecting cryptographic signatures...'), 3500);
      const stepTimer3 = setTimeout(() => setScanStep('Analyzing quantum Shor/Grover vulnerabilities and CNSA 2.0 readiness...'), 6000);

      const res = await fetch('/api/scan/remote-git', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl: repoUrl.trim(),
          provider,
          authType,
          token: authType === 'public' ? undefined : token.trim(),
          username: provider === 'bitbucket' ? username.trim() : undefined,
          branch: branch.trim() || 'main',
          tenant: localStorage.getItem('pqc_active_tenant') || 'SPINOVATIONCORP'
        })
      });

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to scan Git repository. Check repository URL and access credentials.');
      }

      setActiveScan(data.summary);
      fetchHistory(); // Refresh history
    } catch (err: any) {
      setErrorMsg(err.message || 'An unexpected error occurred during repository audit.');
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  const handleDownloadCBOM = async (attested: boolean = false) => {
    if (!activeScan) return;
    try {
      const res = await fetch('/api/scan/remote-git/export-cbom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ summary: activeScan, attestation: attested, cdxa: attested })
      });
      if (!res.ok) throw new Error('Failed to generate CycloneDX CBOM');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const baseName = (activeScan.repoName || 'repository').replace(/[\/\\]/g, '_');
      a.download = attested 
        ? `${baseName}_CBOM_CDXA_Attested_1.6.json` 
        : `${baseName}_CBOM_CycloneDX_1.6.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      alert('Failed to download CBOM: ' + err.message);
    }
  };

  const handleExportCSV = () => {
    if (!activeScan || !activeScan.findings.length) return;
    const headers = ['File Path', 'Line Number', 'Asset Name', 'Algorithm', 'Key Size / Curve', 'Risk Level', 'Quantum Vulnerable', 'Quantum Threat', 'Status', 'Recommendation'];
    const rows = activeScan.findings.map(f => [
      `"${f.filePath}"`,
      f.lineNumber || '',
      `"${f.assetName}"`,
      `"${f.algorithm}"`,
      `"${f.keySize || f.curve || ''}"`,
      `"${f.riskLevel.toUpperCase()}"`,
      f.isVulnerable ? 'YES' : 'NO (PQC)',
      `"${f.quantumThreat.replace(/"/g, '""')}"`,
      `"${f.status}"`,
      `"${f.recommendation.replace(/"/g, '""')}"`
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `${(activeScan.repoName || 'repo').replace(/[\/\\]/g, '_')}_crypto_findings.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyCode = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filter findings
  const filteredFindings = activeScan ? activeScan.findings.filter(f => {
    const matchesSearch = searchQuery === '' || 
      f.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.assetName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.algorithm.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.quantumThreat.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesCat = selectedCategory === 'all' || f.category === selectedCategory;
    const matchesSev = selectedSeverity === 'all' || f.riskLevel === selectedSeverity;

    return matchesSearch && matchesCat && matchesSev;
  }) : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      
      {/* SECTION 1: HEADER & BANNER */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(13, 27, 42, 0.95) 0%, rgba(10, 15, 29, 0.95) 100%)',
        border: '1px solid rgba(0, 242, 254, 0.25)',
        borderRadius: '12px',
        padding: '1.5rem 2rem',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute',
          top: '-40px',
          right: '-40px',
          width: '200px',
          height: '200px',
          background: 'radial-gradient(circle, rgba(0, 242, 254, 0.12) 0%, transparent 70%)',
          borderRadius: '50%',
          pointerEvents: 'none'
        }} />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' }}>
              <div style={{
                background: 'rgba(0, 242, 254, 0.15)',
                border: '1px solid var(--accent-cyan)',
                borderRadius: '8px',
                padding: '0.45rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-cyan)'
              }}>
                <GitBranch size={22} />
              </div>
              <h2 style={{ margin: 0, fontSize: '1.45rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.02em' }}>
                Remote Git Repository Auditor
              </h2>
              <span style={{
                background: 'rgba(168, 85, 247, 0.15)',
                border: '1px solid rgba(168, 85, 247, 0.35)',
                color: '#c084fc',
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '0.2rem 0.6rem',
                borderRadius: '999px',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                GitHub & Bitbucket Direct
              </span>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.9rem', maxWidth: '750px', lineHeight: 1.5 }}>
              Scan remote public and private code repositories directly using Personal Access Tokens (PAT) or OAuth credentials. 
              Automatically discovers hardcoded private keys, classical RSA/ECC primitives, insecure dependencies, and generates a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem' }}>
            {activeScan && (
              <button
                onClick={() => setActiveScan(null)}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.2)',
                  color: '#ffffff',
                  padding: '0.6rem 1rem',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem'
                }}
              >
                <RefreshCw size={15} /> Scan New Repo
              </button>
            )}
          </div>
        </div>
      </div>

      {/* SUB-NAVIGATION: SCANNER VS CI/CD SECURITY GATE */}
      <div style={{ display: 'flex', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.25rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)', width: 'fit-content' }}>
        <button
          type="button"
          onClick={() => setActiveSubView('scanner')}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.45rem',
            padding: '0.55rem 1.15rem', borderRadius: '6px', fontSize: '0.84rem', fontWeight: 600,
            background: activeSubView === 'scanner' ? 'rgba(0, 242, 254, 0.15)' : 'transparent',
            border: activeSubView === 'scanner' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
            color: activeSubView === 'scanner' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          <GitBranch size={15} /> On-Demand Repo Scanner
        </button>
        <button
          type="button"
          onClick={() => setActiveSubView('ci_gate')}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.45rem',
            padding: '0.55rem 1.15rem', borderRadius: '6px', fontSize: '0.84rem', fontWeight: 600,
            background: activeSubView === 'ci_gate' ? 'rgba(0, 242, 254, 0.15)' : 'transparent',
            border: activeSubView === 'ci_gate' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
            color: activeSubView === 'ci_gate' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          <ShieldAlert size={15} /> CI/CD Security Gate (PR Scanning)
          <span style={{ fontSize: '0.66rem', padding: '0.1rem 0.45rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 700 }}>
            PQC GATE
          </span>
        </button>
      </div>

      {/* VIEW A: ON-DEMAND SCANNER */}
      {activeSubView === 'scanner' && (
        <>
          {/* SECTION 2: REPOSITORY SCANNER INPUT CARD (Only shown when not showing scan or when toggled) */}
          {!activeScan && (
            <div style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-color)',
              borderRadius: '12px',
              padding: '2rem',
              boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
            }}>
          <form onSubmit={handleStartScan}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              
              {/* Provider Selector Tabs */}
              <div>
                <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  1. Select Git Code Host
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
                  
                  {/* GitHub */}
                  <button
                    type="button"
                    onClick={() => {
                      setProvider('github');
                      if (!repoUrl || repoUrl.includes('bitbucket.org')) setRepoUrl('https://github.com/');
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.85rem 1rem',
                      borderRadius: '8px',
                      background: provider === 'github' ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      border: provider === 'github' ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
                      color: provider === 'github' ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: 'rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                      </svg>
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.92rem' }}>GitHub</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Public / Private Repos</div>
                    </div>
                  </button>

                  {/* Bitbucket */}
                  <button
                    type="button"
                    onClick={() => {
                      setProvider('bitbucket');
                      if (!repoUrl || repoUrl.includes('github.com')) setRepoUrl('https://bitbucket.org/');
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.85rem 1rem',
                      borderRadius: '8px',
                      background: provider === 'bitbucket' ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      border: provider === 'bitbucket' ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
                      color: provider === 'bitbucket' ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: '#0052cc', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M2.667 3h18.666L18.4 18.533a2.667 2.667 0 01-2.64 2.134H8.24a2.667 2.667 0 01-2.64-2.134L2.667 3zm11.386 11.2h-4.1l-.853-4.8h5.806l-.853 4.8z" />
                      </svg>
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.92rem' }}>Bitbucket</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Cloud / App Passwords</div>
                    </div>
                  </button>

                  {/* GitLab */}
                  <button
                    type="button"
                    onClick={() => {
                      setProvider('gitlab');
                      if (!repoUrl) setRepoUrl('https://gitlab.com/');
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.85rem 1rem',
                      borderRadius: '8px',
                      background: provider === 'gitlab' ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      border: provider === 'gitlab' ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
                      color: provider === 'gitlab' ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: '#e24329', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
                      <GitFork size={18} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.92rem' }}>GitLab</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Cloud & Self-Hosted</div>
                    </div>
                  </button>

                  {/* Generic Git */}
                  <button
                    type="button"
                    onClick={() => setProvider('generic')}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      padding: '0.85rem 1rem',
                      borderRadius: '8px',
                      background: provider === 'generic' ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                      border: provider === 'generic' ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
                      color: provider === 'generic' ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: 'rgba(255,255,255,0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff' }}>
                      <Terminal size={18} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.92rem' }}>Generic Git</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>HTTPS / Custom Server</div>
                    </div>
                  </button>

                </div>
              </div>

              {/* Repository URL & Branch Input */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    2. Remote Repository URL (HTTPS)
                  </label>
                  <input
                    type="url"
                    placeholder={provider === 'bitbucket' ? 'https://bitbucket.org/workspace/repo' : 'https://github.com/organization/repo'}
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    required
                    style={{
                      width: '100%',
                      background: 'rgba(0, 0, 0, 0.4)',
                      border: '1px solid rgba(255, 255, 255, 0.15)',
                      borderRadius: '6px',
                      padding: '0.75rem 1rem',
                      color: '#ffffff',
                      fontSize: '0.92rem',
                      outline: 'none',
                      fontFamily: 'monospace'
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Branch
                  </label>
                  <div style={{ position: 'relative' }}>
                    <GitBranch size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                    <input
                      type="text"
                      placeholder="main or master"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      style={{
                        width: '100%',
                        background: 'rgba(0, 0, 0, 0.4)',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        borderRadius: '6px',
                        padding: '0.75rem 1rem 0.75rem 2.2rem',
                        color: '#ffffff',
                        fontSize: '0.92rem',
                        outline: 'none',
                        fontFamily: 'monospace'
                      }}
                    />
                  </div>
                </div>
              </div>

              {/* Authentication Mode Selection */}
              <div>
                <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '0.82rem', fontWeight: 600, marginBottom: '0.6rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  3. Authentication & Access Protocol
                </label>
                <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: '#ffffff', fontSize: '0.9rem' }}>
                    <input
                      type="radio"
                      name="authType"
                      checked={authType === 'token'}
                      onChange={() => setAuthType('token')}
                    />
                    <span>Personal Access Token (PAT) / App Password <span style={{ color: 'var(--accent-cyan)', fontSize: '0.8rem' }}>(Recommended)</span></span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: '#ffffff', fontSize: '0.9rem' }}>
                    <input
                      type="radio"
                      name="authType"
                      checked={authType === 'public'}
                      onChange={() => setAuthType('public')}
                    />
                    <span>Public Repository (No Token Required)</span>
                  </label>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: '#ffffff', fontSize: '0.9rem' }}>
                    <input
                      type="radio"
                      name="authType"
                      checked={authType === 'oauth'}
                      onChange={() => setAuthType('oauth')}
                    />
                    <span>OAuth Bearer Token / App Access</span>
                  </label>
                </div>

                {/* Token and Username inputs if auth required */}
                {authType !== 'public' && (
                  <div style={{ display: 'grid', gridTemplateColumns: provider === 'bitbucket' ? '1fr 1fr' : '1fr', gap: '1rem', background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    {provider === 'bitbucket' && (
                      <div>
                        <label style={{ display: 'block', color: 'var(--text-secondary)', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.3rem' }}>
                          Bitbucket Username / Account ID
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. atlassian_username"
                          value={username}
                          onChange={(e) => setUsername(e.target.value)}
                          style={{
                            width: '100%',
                            background: 'rgba(0, 0, 0, 0.4)',
                            border: '1px solid rgba(255, 255, 255, 0.15)',
                            borderRadius: '6px',
                            padding: '0.65rem 0.85rem',
                            color: '#ffffff',
                            fontSize: '0.88rem',
                            outline: 'none'
                          }}
                        />
                      </div>
                    )}

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                        <label style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', fontWeight: 600 }}>
                          {provider === 'bitbucket' ? 'Bitbucket App Password' : (authType === 'oauth' ? 'OAuth Bearer Token' : 'Personal Access Token (PAT)')}
                        </label>
                        <button
                          type="button"
                          onClick={() => setShowToken(!showToken)}
                          style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                        >
                          {showToken ? <EyeOff size={13} /> : <Eye size={13} />} {showToken ? 'Hide' : 'Show'}
                        </button>
                      </div>

                      <div style={{ position: 'relative' }}>
                        <Key size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
                        <input
                          type={showToken ? 'text' : 'password'}
                          placeholder={provider === 'github' ? 'ghp_xxxxxxxxxxxxxxxxxxxx or github_pat_...' : (provider === 'bitbucket' ? 'App Password with repository:read' : 'glpat-xxxxxxxxxxxx')}
                          value={token}
                          onChange={(e) => setToken(e.target.value)}
                          required
                          style={{
                            width: '100%',
                            background: 'rgba(0, 0, 0, 0.4)',
                            border: '1px solid rgba(255, 255, 255, 0.15)',
                            borderRadius: '6px',
                            padding: '0.65rem 0.85rem 0.65rem 2.2rem',
                            color: '#ffffff',
                            fontSize: '0.88rem',
                            outline: 'none',
                            fontFamily: 'monospace'
                          }}
                        />
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: '0.3rem' }}>
                        🔒 Security Guarantee: Tokens are never stored or logged in plain text. Clones are executed into an isolated ephemeral RAM/tmpfs sandbox and wiped immediately upon completion.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Error Message */}
              {errorMsg && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  color: '#f87171',
                  borderRadius: '8px',
                  padding: '0.85rem 1.25rem',
                  fontSize: '0.88rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem'
                }}>
                  <AlertTriangle size={18} />
                  <span>{errorMsg}</span>
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '1.25rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Quick Public Sample:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setProvider('github');
                      setRepoUrl('https://github.com/torvalds/linux');
                      setAuthType('public');
                      setBranch('master');
                    }}
                    style={{
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid rgba(255,255,255,0.15)',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.6rem',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    Linux Kernel (Public)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setProvider('github');
                      setRepoUrl('https://github.com/catallicpankaj/pqc-starter-lib');
                      setAuthType('public');
                      setBranch('main');
                    }}
                    style={{
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid rgba(255,255,255,0.15)',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.6rem',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    PQC Starter Lib
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={isScanning}
                  style={{
                    background: isScanning ? 'rgba(0, 242, 254, 0.4)' : 'linear-gradient(135deg, var(--accent-cyan) 0%, #0072ff 100%)',
                    border: 'none',
                    color: '#000000',
                    fontWeight: 700,
                    fontSize: '0.95rem',
                    padding: '0.8rem 2rem',
                    borderRadius: '8px',
                    cursor: isScanning ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.6rem',
                    boxShadow: isScanning ? 'none' : '0 0 20px rgba(0, 242, 254, 0.35)',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {isScanning ? (
                    <>
                      <RefreshCw size={18} className="animate-spin" />
                      <span>Auditing Repository...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={18} />
                      <span>Start Quantum Audit</span>
                    </>
                  )}
                </button>
              </div>

              {/* Progress Indicator */}
              {isScanning && (
                <div style={{
                  background: 'rgba(0, 242, 254, 0.08)',
                  border: '1px solid rgba(0, 242, 254, 0.25)',
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.85rem'
                }}>
                  <div style={{
                    width: '20px',
                    height: '20px',
                    border: '3px solid rgba(0, 242, 254, 0.3)',
                    borderTop: '3px solid var(--accent-cyan)',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite'
                  }} />
                  <div style={{ color: '#ffffff', fontSize: '0.88rem', fontWeight: 500 }}>
                    {scanStep || 'Executing shallow clone and extracting AST cryptographic signatures...'}
                  </div>
                </div>
              )}

            </div>
          </form>
        </div>
      )}

      {/* SECTION 3: SCAN RESULTS DASHBOARD (Rendered when activeScan is present) */}
      {activeScan && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Top Repository Summary Card */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: '12px',
            padding: '1.5rem 2rem',
            boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1.5rem'
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.3rem' }}>
                <span style={{
                  background: activeScan.provider === 'bitbucket' ? '#0052cc' : 'rgba(255,255,255,0.1)',
                  color: '#ffffff',
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  textTransform: 'uppercase'
                }}>
                  {activeScan.provider}
                </span>
                <h3 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 700, color: '#ffffff' }}>
                  {activeScan.repoName}
                </h3>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', fontFamily: 'monospace' }}>
                  ({activeScan.branch} @ {activeScan.commitHash || 'HEAD'})
                </span>
              </div>
              <div style={{ display: 'flex', gap: '1.25rem', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                <span>Audited: {new Date(activeScan.scannedAt).toLocaleTimeString()} ({new Date(activeScan.scannedAt).toLocaleDateString()})</span>
                <span>Duration: {(activeScan.scanDurationMs / 1000).toFixed(2)}s</span>
                <span>Files Checked: {activeScan.totalFilesScanned}</span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
              {/* Radial Risk Gauge */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.85rem',
                background: 'rgba(0,0,0,0.3)',
                padding: '0.6rem 1rem',
                borderRadius: '10px',
                border: '1px solid rgba(255,255,255,0.08)'
              }}>
                <div style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '50%',
                  background: activeScan.quantumRiskScore > 70 ? 'rgba(239, 68, 68, 0.2)' : (activeScan.quantumRiskScore > 40 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'),
                  border: `3px solid ${activeScan.quantumRiskScore > 70 ? '#ef4444' : (activeScan.quantumRiskScore > 40 ? '#f59e0b' : '#10b981')}`,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                  fontWeight: 800,
                  fontSize: '1.1rem'
                }}>
                  {activeScan.quantumRiskScore}
                </div>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Quantum Risk
                  </div>
                  <div style={{
                    fontWeight: 700,
                    fontSize: '0.95rem',
                    color: activeScan.quantumRiskScore > 70 ? '#ef4444' : (activeScan.quantumRiskScore > 40 ? '#f59e0b' : '#10b981')
                  }}>
                    {activeScan.quantumRiskScore > 70 ? 'CRITICAL RISK' : (activeScan.quantumRiskScore > 40 ? 'HIGH RISK' : 'PQC PROTECTED')}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  onClick={() => handleDownloadCBOM(false)}
                  title="Download Standard CycloneDX 1.6 Cryptographic Bill of Materials in JSON format"
                  style={{
                    background: 'rgba(0, 242, 254, 0.15)',
                    border: '1px solid var(--accent-cyan)',
                    color: 'var(--accent-cyan)',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    padding: '0.55rem 1rem',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.45rem'
                  }}
                >
                  <Download size={15} /> CBOM JSON (1.6)
                </button>

                <button
                  onClick={() => handleDownloadCBOM(true)}
                  title="Download CycloneDX 1.6 with CDXA Attestation Declarations (NIST SP 800-218, CNSA 2.0) and ML-DSA-65 Signature"
                  style={{
                    background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(56, 189, 248, 0.25) 100%)',
                    border: '1px solid rgba(168, 85, 247, 0.5)',
                    color: '#c084fc',
                    fontWeight: 700,
                    fontSize: '0.85rem',
                    padding: '0.55rem 1rem',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.45rem',
                    boxShadow: '0 0 12px rgba(168, 85, 247, 0.15)'
                  }}
                >
                  <ShieldCheck size={15} color="#c084fc" /> Attested CDXA
                </button>

                <button
                  onClick={handleExportCSV}
                  title="Export tabular findings to CSV"
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    padding: '0.55rem 0.9rem',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.45rem'
                  }}
                >
                  <Download size={15} /> CSV
                </button>
              </div>
            </div>
          </div>

          {/* Metric KPI Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
            
            <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1.25rem' }}>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Crypto Assets</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff', marginTop: '0.2rem' }}>{activeScan.totalAssets}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>Primitves & keys discovered</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '10px', padding: '1.25rem' }}>
              <div style={{ color: '#f87171', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Quantum Vulnerable</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ef4444', marginTop: '0.2rem' }}>{activeScan.vulnerableCount}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>Shor's / Grover's attack target</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '10px', padding: '1.25rem' }}>
              <div style={{ color: '#34d399', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Post-Quantum Secure</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#10b981', marginTop: '0.2rem' }}>{activeScan.pqcCount}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>NIST FIPS 203/204/205</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '10px', padding: '1.25rem' }}>
              <div style={{ color: '#f87171', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Critical / Private Keys</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ef4444', marginTop: '0.2rem' }}>{activeScan.criticalCount}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>Hardcoded secrets in repo</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '1.25rem' }}>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>CNSA 2.0 Status</div>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: activeScan.cnsaStatus === 'PQC Ready' ? '#10b981' : (activeScan.cnsaStatus === 'Partially Compliant' ? '#38bdf8' : '#f59e0b'), marginTop: '0.4rem' }}>
                {activeScan.cnsaStatus}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>Federal Mandate OMB M-23-02</div>
            </div>

          </div>

          {/* Filter & Search Bar */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '1rem 1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            {/* Search */}
            <div style={{ position: 'relative', width: '320px' }}>
              <Search size={16} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                type="text"
                placeholder="Search file path, algorithm, threat..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '6px',
                  padding: '0.55rem 0.85rem 0.55rem 2.2rem',
                  color: '#ffffff',
                  fontSize: '0.85rem',
                  outline: 'none'
                }}
              />
            </div>

            {/* Category Pills */}
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              {[
                { id: 'all', label: 'All' },
                { id: 'private_key', label: 'Keys' },
                { id: 'source_code', label: 'Code Calls' },
                { id: 'dependency', label: 'Dependencies' },
                { id: 'config', label: 'Configs/TLS' },
                { id: 'web3', label: 'Web3' }
              ].map(cat => (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCategory(cat.id)}
                  style={{
                    background: selectedCategory === cat.id ? 'rgba(0, 242, 254, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                    border: selectedCategory === cat.id ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.1)',
                    color: selectedCategory === cat.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    borderRadius: '4px',
                    padding: '0.35rem 0.75rem',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  {cat.label}
                </button>
              ))}
            </div>

            {/* Severity Pills */}
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              {[
                { id: 'all', label: 'All Severities' },
                { id: 'critical', label: 'Critical' },
                { id: 'high', label: 'High' },
                { id: 'secure', label: 'Secure (PQC)' }
              ].map(sev => (
                <button
                  key={sev.id}
                  onClick={() => setSelectedSeverity(sev.id)}
                  style={{
                    background: selectedSeverity === sev.id ? 'rgba(255, 255, 255, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                    border: selectedSeverity === sev.id ? '1px solid #ffffff' : '1px solid rgba(255, 255, 255, 0.08)',
                    color: selectedSeverity === sev.id ? '#ffffff' : 'var(--text-secondary)',
                    borderRadius: '4px',
                    padding: '0.35rem 0.7rem',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  {sev.label}
                </button>
              ))}
            </div>
          </div>

          {/* Interactive Findings Table */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: '12px',
            overflow: 'hidden',
            boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
          }}>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.08)', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>File & Line</th>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>Asset / Primitive</th>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>Algorithm / Curve</th>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>Risk Level</th>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>Quantum Status</th>
                    <th style={{ padding: '0.85rem 1.25rem', fontWeight: 600, textAlign: 'right' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ padding: '3rem 1.25rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                        No cryptographic assets matched the current filters.
                      </td>
                    </tr>
                  ) : (
                    filteredFindings.map(finding => {
                      const isExpanded = expandedFindingId === finding.id;
                      const badgeBg = finding.riskLevel === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 
                                      finding.riskLevel === 'high' ? 'rgba(245, 158, 11, 0.15)' : 
                                      finding.riskLevel === 'secure' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(56, 189, 248, 0.15)';
                      const badgeColor = finding.riskLevel === 'critical' ? '#ef4444' : 
                                         finding.riskLevel === 'high' ? '#f59e0b' : 
                                         finding.riskLevel === 'secure' ? '#10b981' : '#38bdf8';

                      return (
                        <React.Fragment key={finding.id}>
                          <tr 
                            onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                            style={{
                              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                              cursor: 'pointer',
                              background: isExpanded ? 'rgba(0, 242, 254, 0.04)' : 'transparent',
                              transition: 'background 0.15s ease'
                            }}
                          >
                            <td style={{ padding: '1rem 1.25rem', fontFamily: 'monospace', color: '#ffffff' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                <FileCode size={15} color="var(--accent-cyan)" />
                                <span>{finding.filePath}</span>
                                {finding.lineNumber && (
                                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>:L{finding.lineNumber}</span>
                                )}
                              </div>
                            </td>
                            <td style={{ padding: '1rem 1.25rem', color: '#ffffff', fontWeight: 500 }}>
                              {finding.assetName}
                            </td>
                            <td style={{ padding: '1rem 1.25rem', fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>
                              {finding.algorithm} {finding.keySize ? `(${finding.keySize}-bit)` : (finding.curve ? `(${finding.curve})` : '')}
                            </td>
                            <td style={{ padding: '1rem 1.25rem' }}>
                              <span style={{
                                background: badgeBg,
                                color: badgeColor,
                                border: `1px solid ${badgeColor}40`,
                                padding: '0.25rem 0.6rem',
                                borderRadius: '4px',
                                fontSize: '0.72rem',
                                fontWeight: 700,
                                textTransform: 'uppercase'
                              }}>
                                {finding.riskLevel}
                              </span>
                            </td>
                            <td style={{ padding: '1rem 1.25rem', fontSize: '0.82rem', color: finding.isVulnerable ? '#f87171' : '#34d399' }}>
                              {finding.status}
                            </td>
                            <td style={{ padding: '1rem 1.25rem', textAlign: 'right', color: 'var(--text-secondary)' }}>
                              {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            </td>
                          </tr>

                          {/* Expanded Detail View */}
                          {isExpanded && (
                            <tr style={{ background: 'rgba(0,0,0,0.3)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                              <td colSpan={6} style={{ padding: '1.25rem 2rem' }}>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                  
                                  {/* Code Snippet */}
                                  {finding.lineContent && (
                                    <div>
                                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>
                                        Detected Code Line
                                      </div>
                                      <div style={{
                                        background: 'rgba(0,0,0,0.6)',
                                        border: '1px solid rgba(255,255,255,0.1)',
                                        borderRadius: '6px',
                                        padding: '0.75rem 1rem',
                                        fontFamily: 'monospace',
                                        fontSize: '0.85rem',
                                        color: '#fca5a5',
                                        overflowX: 'auto',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center'
                                      }}>
                                        <span>{finding.lineContent}</span>
                                        <button
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleCopyCode(finding.lineContent || '', finding.id + '-line');
                                          }}
                                          style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                                        >
                                          {copiedId === finding.id + '-line' ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                                        </button>
                                      </div>
                                    </div>
                                  )}

                                  {/* Quantum Threat & Cryptanalysis */}
                                  <div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>
                                      Cryptanalysis & Quantum Threat
                                    </div>
                                    <div style={{ color: '#ffffff', fontSize: '0.88rem', lineHeight: 1.5, background: 'rgba(255,255,255,0.02)', padding: '0.75rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                                      {finding.quantumThreat}
                                    </div>
                                  </div>

                                  {/* Recommendation & Remediation Snippet */}
                                  <div>
                                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>
                                      NIST PQC Migration Guidance & Code Replacement
                                    </div>
                                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginBottom: '0.5rem' }}>
                                      {finding.recommendation}
                                    </div>

                                    {finding.remediationSnippet && (
                                      <div style={{
                                        background: 'rgba(16, 185, 129, 0.05)',
                                        border: '1px solid rgba(16, 185, 129, 0.25)',
                                        borderRadius: '6px',
                                        padding: '0.75rem 1rem',
                                        fontFamily: 'monospace',
                                        fontSize: '0.82rem',
                                        color: '#34d399',
                                        overflowX: 'auto',
                                        whiteSpace: 'pre-wrap',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'flex-start'
                                      }}>
                                        <span>{finding.remediationSnippet}</span>
                                        <button
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleCopyCode(finding.remediationSnippet || '', finding.id + '-remed');
                                          }}
                                          style={{ background: 'transparent', border: 'none', color: '#34d399', cursor: 'pointer', paddingLeft: '0.5rem' }}
                                        >
                                          {copiedId === finding.id + '-remed' ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                                        </button>
                                      </div>
                                    )}
                                  </div>

                                  {/* Compliance Tags */}
                                  {finding.complianceStandards && finding.complianceStandards.length > 0 && (
                                    <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
                                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Compliance:</span>
                                      {finding.complianceStandards.map((std, idx) => (
                                        <span key={idx} style={{
                                          background: 'rgba(255,255,255,0.06)',
                                          border: '1px solid rgba(255,255,255,0.12)',
                                          padding: '0.15rem 0.45rem',
                                          borderRadius: '3px',
                                          fontSize: '0.72rem',
                                          color: '#ffffff'
                                        }}>
                                          {std}
                                        </span>
                                      ))}
                                    </div>
                                  )}

                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* SECTION 4: RECENT REPOSITORY AUDIT HISTORY */}
      {history.length > 0 && (
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          padding: '1.5rem',
          boxShadow: '0 4px 20px rgba(0,0,0,0.3)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Clock size={16} color="var(--accent-cyan)" /> Recent Remote Repository Audits
            </h3>
            <button
              onClick={fetchHistory}
              style={{ background: 'transparent', border: 'none', color: 'var(--accent-cyan)', fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              <RefreshCw size={13} /> Refresh
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
            {history.slice(0, 6).map(item => (
              <div
                key={item.id}
                onClick={() => {
                  setRepoUrl(item.repoUrl);
                  setBranch(item.branch || 'main');
                  // Quick populate
                }}
                style={{
                  background: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: '8px',
                  padding: '1rem',
                  cursor: 'pointer',
                  transition: 'border 0.2s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                  <span style={{ fontWeight: 600, color: '#ffffff', fontSize: '0.9rem', wordBreak: 'break-all' }}>
                    {item.repoName}
                  </span>
                  <span style={{
                    background: item.quantumRiskScore > 70 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                    color: item.quantumRiskScore > 70 ? '#ef4444' : '#f59e0b',
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    padding: '0.15rem 0.4rem',
                    borderRadius: '4px'
                  }}>
                    Risk: {item.quantumRiskScore}
                  </span>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', marginBottom: '0.4rem' }}>
                  Branch: {item.branch} • {item.totalAssets} crypto assets ({item.vulnerableCount} vulnerable)
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>
                  {new Date(item.scannedAt).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      </>
      )}

      {/* VIEW B: CI/CD PIPELINE CBOM SECURITY GATE */}
      {activeSubView === 'ci_gate' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Top Metrics */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                PRs Evaluated
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff', marginTop: '0.35rem' }}>
                {ciGates.length}
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                Across GitHub, GitLab &amp; Bitbucket
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(239, 68, 68, 0.25)', background: 'rgba(239, 68, 68, 0.03)' }}>
              <div style={{ fontSize: '0.75rem', color: '#f87171', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                Merges Blocked (Exit 1)
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ef4444', marginTop: '0.35rem' }}>
                {ciGates.filter(g => g.status === 'BLOCKED').length}
              </div>
              <div style={{ fontSize: '0.76rem', color: '#fca5a5', marginTop: '0.3rem' }}>
                Vulnerable RSA/ECC algorithms stopped
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(16, 185, 129, 0.25)', background: 'rgba(16, 185, 129, 0.03)' }}>
              <div style={{ fontSize: '0.75rem', color: '#34d399', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                Merges Passed (Exit 0)
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#10b981', marginTop: '0.35rem' }}>
                {ciGates.filter(g => g.status === 'PASSED').length}
              </div>
              <div style={{ fontSize: '0.76rem', color: '#6ee7b7', marginTop: '0.3rem' }}>
                100% PQC &amp; CNSA 2.0 compliant
              </div>
            </div>

            <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                Active Policy Gate
              </div>
              <div style={{ fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', marginTop: '0.5rem' }}>
                CNSA 2.0 Strict Gate
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                Blocks RSA, ECC, 3DES, MD5 &amp; SHA-1
              </div>
            </div>
          </div>

          {/* 1-Click CI/CD Integration Card */}
          <div className="glass-panel" style={{ padding: '1.75rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#ffffff', fontWeight: 600 }}>
                  Automated Pipeline Setup &amp; Workflow Configurations
                </h3>
                <p style={{ margin: '0.2rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                  Copy these pre-packaged actions into your repository to enforce quantum security gates on every Pull Request.
                </p>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {(['github', 'gitlab', 'bitbucket', 'runner'] as const).map(p => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setSelectedCiProvider(p)}
                    style={{
                      padding: '0.45rem 0.85rem',
                      borderRadius: '6px',
                      fontSize: '0.8rem',
                      fontWeight: 600,
                      background: selectedCiProvider === p ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                      border: `1px solid ${selectedCiProvider === p ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.1)'}`,
                      color: selectedCiProvider === p ? '#ffffff' : 'var(--text-secondary)',
                      cursor: 'pointer',
                      textTransform: 'uppercase'
                    }}
                  >
                    {p === 'runner' ? 'CLI RUNNER' : p}
                  </button>
                ))}

                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(ciTemplateCode);
                    setCiCopied(true);
                    setTimeout(() => setCiCopied(false), 2000);
                  }}
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', padding: '0.45rem 0.85rem' }}
                >
                  {ciCopied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
                  {ciCopied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <pre style={{
              background: '#030712',
              padding: '1.25rem',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              fontSize: '0.82rem',
              fontFamily: 'monospace',
              color: '#38bdf8',
              overflowX: 'auto',
              lineHeight: 1.5,
              maxHeight: '380px'
            }}>
              {ciTemplateCode}
            </pre>

            <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                💡 Tip: Set repository secret <code style={{ color: 'var(--accent-cyan)' }}>QUARKSHIELD_API_TOKEN</code> in your repo settings to authenticate runner webhooks.
              </div>

              {/* Simulation buttons */}
              <div style={{ display: 'flex', gap: '0.6rem' }}>
                <button
                  type="button"
                  disabled={testingGate}
                  onClick={() => handleSimulateGate(false)}
                  className="btn btn-secondary"
                  style={{ fontSize: '0.78rem', padding: '0.45rem 0.85rem', color: '#10b981', borderColor: 'rgba(16, 185, 129, 0.3)' }}
                >
                  {testingGate ? 'Testing...' : 'Simulate Passing PR (ML-KEM)'}
                </button>
                <button
                  type="button"
                  disabled={testingGate}
                  onClick={() => handleSimulateGate(true)}
                  className="btn btn-secondary"
                  style={{ fontSize: '0.78rem', padding: '0.45rem 0.85rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.3)' }}
                >
                  {testingGate ? 'Testing...' : 'Simulate Blocked PR (RSA-2048)'}
                </button>
              </div>
            </div>
          </div>

          {/* PR Evaluation History Table */}
          <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#ffffff', fontWeight: 600 }}>
                  Automated Pull-Request Gate Log ({ciGates.length})
                </h3>
                <p style={{ margin: '0.2rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                  Live history of pull requests and commits analyzed against quantum security policies.
                </p>
              </div>

              <button
                type="button"
                onClick={fetchCiGates}
                className="btn btn-secondary"
                style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem', padding: '0.45rem 0.75rem' }}
              >
                <RefreshCw size={13} className={loadingCiGates ? 'spin-animation' : ''} /> Refresh Logs
              </button>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Gate Decision</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Repository &amp; Branch</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>PR / Commit</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Author</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Violations</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 0.5rem' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {ciGates.map(g => (
                    <tr key={g.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                      <td style={{ padding: '0.75rem 0.5rem' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          padding: '0.2rem 0.55rem',
                          borderRadius: '4px',
                          background: g.status === 'PASSED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          color: g.status === 'PASSED' ? '#10b981' : '#ef4444',
                          border: `1px solid ${g.status === 'PASSED' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                        }}>
                          {g.status === 'PASSED' ? '✓ MERGE ALLOWED' : '✕ MERGE BLOCKED'}
                        </span>
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', fontWeight: 600, color: '#ffffff' }}>
                        <div>{g.repo_name}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                          branch: {g.branch}
                        </div>
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>
                        <div>{g.pr_number}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{g.commit_hash?.substring(0, 7)}</div>
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-secondary)' }}>
                        {g.commit_author}
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', fontWeight: 700, color: g.violations_count > 0 ? '#ef4444' : '#10b981' }}>
                        {g.violations_count} violations
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', fontWeight: 700, color: g.quantum_risk_score > 50 ? '#ef4444' : '#10b981' }}>
                        {g.quantum_risk_score} / 100
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                        {new Date(g.created_at).toLocaleString()}
                      </td>

                      <td style={{ padding: '0.75rem 0.5rem' }}>
                        <button
                          type="button"
                          onClick={() => setSelectedGateReport(g)}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.74rem', padding: '0.3rem 0.65rem' }}
                        >
                          View Report
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Gate Report Modal */}
          {selectedGateReport && (
            <div style={{
              position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
              background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(5px)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
            }}>
              <div className="glass-panel" style={{ width: '680px', maxHeight: '85vh', overflowY: 'auto', padding: '2rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.75rem' }}>
                  <h3 style={{ margin: 0, color: '#ffffff', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <ShieldAlert size={18} color={selectedGateReport.status === 'PASSED' ? '#10b981' : '#ef4444'} />
                    CI/CD Gate Evaluation Report: {selectedGateReport.pr_number}
                  </h3>
                  <button
                    type="button"
                    onClick={() => setSelectedGateReport(null)}
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}
                  >
                    ✕
                  </button>
                </div>

                <div style={{
                  padding: '0.75rem 1rem',
                  borderRadius: '6px',
                  marginBottom: '1rem',
                  background: selectedGateReport.status === 'PASSED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  border: `1px solid ${selectedGateReport.status === 'PASSED' ? '#10b981' : '#ef4444'}`,
                  color: '#ffffff',
                  fontWeight: 600,
                  fontSize: '0.88rem'
                }}>
                  {selectedGateReport.status === 'PASSED' ? '✅ Gate Passed: Codebase is fully quantum-safe.' : '❌ Gate Blocked: Pull Request introduces quantum-vulnerable cryptographic algorithms.'}
                </div>

                <pre style={{
                  background: '#030712',
                  padding: '1.25rem',
                  borderRadius: '8px',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  fontSize: '0.82rem',
                  fontFamily: 'monospace',
                  color: '#f1f5f9',
                  whiteSpace: 'pre-wrap',
                  lineHeight: 1.6
                }}>
                  {selectedGateReport.markdown_report}
                </pre>

                <div style={{ marginTop: '1.5rem', textAlign: 'right' }}>
                  <button
                    type="button"
                    onClick={() => setSelectedGateReport(null)}
                    className="btn btn-primary"
                    style={{ padding: '0.5rem 1.25rem' }}
                  >
                    Close Report
                  </button>
                </div>
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
