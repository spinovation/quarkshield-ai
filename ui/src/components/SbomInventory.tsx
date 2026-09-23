import React, { useState, useEffect, useMemo } from 'react';
import {
  Package,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  Copy,
  Check,
  ExternalLink,
  Search,
  RefreshCw,
  FileCode,
  Terminal,
  Layers,
  Wrench,
  CheckCircle2,
  X,
  Info,
  BookOpen
} from 'lucide-react';

interface VulnerabilityDetail {
  cveId: string;
  title: string;
  cvssScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  fixedVersion: string;
  remediationCmd: string;
  description: string;
}

interface SbomComponent {
  id: string;
  tenant_name: string;
  source: string;
  source_ref: string;
  file_path: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  license: string;
  has_vulnerabilities: boolean;
  vuln_count: number;
  max_severity: string;
  vulnerabilities: VulnerabilityDetail[];
  created_at: string;
  updated_at: string;
}

interface SbomStats {
  totalComponents: number;
  vulnerableComponents: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  cleanCount: number;
  patchableCount: number;
  patchablePercent: number;
}

interface SbomInventoryProps {
  tenant?: string;
  apiUrl?: string;
  isSuperAdmin?: boolean;
}

export default function SbomInventory({ tenant = 'SPINOVATIONCORP', apiUrl = '', isSuperAdmin = false }: SbomInventoryProps) {
  const [selectedScope, setSelectedScope] = useState<'platform' | 'client'>(
    isSuperAdmin ? (tenant.toLowerCase().includes('quarkshield') ? 'platform' : 'platform') : 'client'
  );
  const activeTenant = (isSuperAdmin && selectedScope === 'platform') ? 'quarkshield.ai' : tenant;

  const [components, setComponents] = useState<SbomComponent[]>([]);
  const [stats, setStats] = useState<SbomStats>({
    totalComponents: 0,
    vulnerableComponents: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    cleanCount: 0,
    patchableCount: 0,
    patchablePercent: 100
  });
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [ecosystemFilter, setEcosystemFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [activeAdvisory, setActiveAdvisory] = useState<{ comp: SbomComponent; vuln: VulnerabilityDetail } | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  const [showSuperAdminDocModal, setShowSuperAdminDocModal] = useState(false);
  const [guideContent, setGuideContent] = useState<string>('');
  const [guideLoading, setGuideLoading] = useState(false);

  const handleFetchGuide = async () => {
    setShowSuperAdminDocModal(true);
    if (!guideContent) {
      setGuideLoading(true);
      try {
        const res = await fetch(`${apiUrl}/api/sbom/superadmin-guide?format=json&admin=true`, {
          headers: { 'x-admin-role': 'super_admin' }
        });
        if (res.ok) {
          const data = await res.json();
          setGuideContent(data.content || '');
        }
      } catch (err) {
        console.error('Failed to load Super Admin guide', err);
      } finally {
        setGuideLoading(false);
      }
    }
  };

  const fetchSbomData = async () => {
    setLoading(true);
    try {
      const tenantParam = encodeURIComponent(activeTenant);
      const headers: Record<string, string> = {};
      if (isSuperAdmin) {
        headers['x-admin-role'] = 'super_admin';
      }
      const [compRes, statsRes] = await Promise.all([
        fetch(`${apiUrl}/api/sbom/components?tenant=${tenantParam}&limit=200`, { headers }),
        fetch(`${apiUrl}/api/sbom/stats?tenant=${tenantParam}`, { headers })
      ]);

      if (compRes.ok) {
        const compData = await compRes.json();
        if (compData.success && Array.isArray(compData.components)) {
          setComponents(compData.components);
        }
      }

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        if (statsData.success && statsData.stats) {
          setStats(statsData.stats);
        }
      }
    } catch (err) {
      console.error('Failed to fetch SBOM data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSbomData();
  }, [activeTenant, selectedScope]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2500);
  };

  const filteredComponents = useMemo(() => {
    return components.filter(c => {
      if (ecosystemFilter !== 'all' && c.ecosystem !== ecosystemFilter) return false;
      if (severityFilter !== 'all') {
        if (severityFilter === 'clean' && c.has_vulnerabilities) return false;
        if (severityFilter !== 'clean' && c.max_severity !== severityFilter) return false;
      }
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const matchesName = c.name.toLowerCase().includes(q);
        const matchesPurl = (c.purl || '').toLowerCase().includes(q);
        const matchesRef = (c.source_ref || '').toLowerCase().includes(q);
        const matchesCve = Array.isArray(c.vulnerabilities) && c.vulnerabilities.some(v => v.cveId.toLowerCase().includes(q) || v.title.toLowerCase().includes(q));
        if (!matchesName && !matchesPurl && !matchesRef && !matchesCve) return false;
      }
      return true;
    });
  }, [components, ecosystemFilter, severityFilter, searchQuery]);

  const paginatedComponents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredComponents.slice(start, start + pageSize);
  }, [filteredComponents, currentPage]);

  const totalPages = Math.ceil(filteredComponents.length / pageSize) || 1;

  const handleExportJson = () => {
    const adminParam = isSuperAdmin ? '&admin=true' : '';
    window.open(`${apiUrl}/api/sbom/export?tenant=${encodeURIComponent(activeTenant)}${adminParam}`, '_blank');
  };

  const handleDownloadFixScript = () => {
    const adminParam = isSuperAdmin ? '&admin=true' : '';
    window.open(`${apiUrl}/api/sbom/fix-script?tenant=${encodeURIComponent(activeTenant)}${adminParam}`, '_blank');
  };

  const exportCsv = () => {
    const headers = ['Component Name', 'Installed Version', 'Ecosystem', 'PURL', 'Max Severity', 'CVE Count', 'CVE IDs', 'Fixed Version Target', 'Remediation Command', 'Source Reference'];
    const rows = filteredComponents.map(c => {
      const cves = Array.isArray(c.vulnerabilities) ? c.vulnerabilities.map(v => v.cveId).join('; ') : '';
      const fixedVer = Array.isArray(c.vulnerabilities) && c.vulnerabilities.length > 0 ? c.vulnerabilities[0].fixedVersion : 'N/A';
      const remCmd = Array.isArray(c.vulnerabilities) && c.vulnerabilities.length > 0 ? c.vulnerabilities[0].remediationCmd : 'N/A';
      return [
        `"${c.name}"`,
        `"${c.version}"`,
        `"${c.ecosystem}"`,
        `"${c.purl || ''}"`,
        `"${c.max_severity}"`,
        `"${c.vuln_count || 0}"`,
        `"${cves}"`,
        `"${fixedVer}"`,
        `"${remCmd}"`,
        `"${c.source_ref || ''}"`
      ].join(',');
    });
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `${activeTenant.toLowerCase()}-sbom-inventory.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Super Admin Privileged Access Banner & Scope Selector */}
      {isSuperAdmin && (
        <div style={{
          background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.12) 0%, rgba(56, 189, 248, 0.12) 100%)',
          border: '1px solid rgba(168, 85, 247, 0.4)',
          borderRadius: '12px',
          padding: '1.25rem 1.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
              <ShieldCheck size={20} color="#c084fc" />
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
                QuarkShield Platform Architecture &amp; System Stack SBOM
              </h3>
              <span style={{ fontSize: '0.68rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(168, 85, 247, 0.25)', color: '#c084fc', border: '1px solid rgba(168, 85, 247, 0.5)', fontWeight: 700 }}>
                Super Admin Only
              </span>
            </div>
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted, #94a3b8)', maxWidth: '780px' }}>
              Privileged infrastructure inventory documenting <strong>quarkshield.ai</strong> production runtime packages, database drivers, scanner binaries, and container layers. Evaluated against NVD &amp; GitHub Security Advisories.
            </p>
          </div>

          {/* Scope Toggle */}
          <div style={{ display: 'flex', background: 'rgba(0, 0, 0, 0.45)', padding: '3px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
            <button
              onClick={() => { setSelectedScope('platform'); setCurrentPage(1); }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.45rem 0.9rem',
                borderRadius: '6px',
                border: 'none',
                background: selectedScope === 'platform' ? 'rgba(168, 85, 247, 0.35)' : 'transparent',
                color: selectedScope === 'platform' ? '#c084fc' : 'var(--text-muted, #94a3b8)',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Package size={14} /> QuarkShield Platform Stack (quarkshield.ai)
            </button>
            <button
              onClick={() => { setSelectedScope('client'); setCurrentPage(1); }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.45rem 0.9rem',
                borderRadius: '6px',
                border: 'none',
                background: selectedScope === 'client' ? 'rgba(56, 189, 248, 0.25)' : 'transparent',
                color: selectedScope === 'client' ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Layers size={14} /> Customer Enrolled Workloads ({tenant})
            </button>
          </div>
        </div>
      )}

      {/* 1. Summary Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
        {/* Total Components */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '10px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600, textTransform: 'uppercase' }}>
              Software Components
            </span>
            <Package size={18} color="var(--accent-cyan, #38bdf8)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff' }}>
            {stats.totalComponents}
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
            Tracked across npm, PyPI, Go &amp; OS manifests
          </div>
        </div>

        {/* Vulnerable Components */}
        <div style={{
          background: 'rgba(239, 68, 68, 0.04)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          borderRadius: '10px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 600, textTransform: 'uppercase' }}>
              Vulnerable Components
            </span>
            <AlertTriangle size={18} color="#f87171" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f87171' }}>
            {stats.vulnerableComponents}
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
            {stats.cleanCount} packages clean of known CVEs
          </div>
        </div>

        {/* Critical & High CVEs */}
        <div style={{
          background: 'rgba(245, 158, 11, 0.04)',
          border: '1px solid rgba(245, 158, 11, 0.25)',
          borderRadius: '10px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: '#fbbf24', fontWeight: 600, textTransform: 'uppercase' }}>
              Critical &amp; High CVEs
            </span>
            <ShieldAlert size={18} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fbbf24' }}>
            {stats.criticalCount + stats.highCount}
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
            {stats.criticalCount} Critical • {stats.highCount} High • {stats.mediumCount} Medium
          </div>
        </div>

        {/* Automated Patchability */}
        <div style={{
          background: 'rgba(16, 185, 129, 0.04)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          borderRadius: '10px',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 600, textTransform: 'uppercase' }}>
              100% Patchable
            </span>
            <CheckCircle2 size={18} color="#34d399" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#34d399' }}>
            {stats.patchablePercent}%
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>
            {stats.patchableCount} of {stats.vulnerableComponents} have safe target upgrade fixes
          </div>
        </div>
      </div>

      {/* 2. Control Toolbar (Search, Filter, Export) */}
      <div style={{
        background: 'rgba(255, 255, 255, 0.02)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '10px',
        padding: '1.15rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', flex: '1 1 280px', maxWidth: '420px' }}>
            <Search size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted, #94a3b8)' }} />
            <input
              type="text"
              placeholder="Search component, PURL, CVE-ID, or repository..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              style={{
                width: '100%',
                background: 'rgba(0, 0, 0, 0.35)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '6px',
                padding: '0.5rem 0.85rem 0.5rem 2.2rem',
                fontSize: '0.85rem',
                color: '#ffffff',
                outline: 'none'
              }}
            />
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <button
              onClick={handleExportJson}
              style={{
                background: 'rgba(56, 189, 248, 0.12)',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                color: 'var(--accent-cyan, #38bdf8)',
                padding: '0.48rem 0.9rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem'
              }}
            >
              <FileCode size={14} /> Export CycloneDX 1.6 SBOM
            </button>

            <button
              onClick={handleDownloadFixScript}
              style={{
                background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25) 0%, rgba(56, 189, 248, 0.25) 100%)',
                border: '1px solid rgba(168, 85, 247, 0.4)',
                color: '#c084fc',
                padding: '0.48rem 0.9rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem'
              }}
            >
              <Wrench size={14} /> Download Fix Script (.sh)
            </button>

            <button
              onClick={exportCsv}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: 'var(--text-secondary, #cbd5e1)',
                padding: '0.48rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem'
              }}
            >
              <Download size={14} /> CSV
            </button>

            {isSuperAdmin && (
              <button
                onClick={handleFetchGuide}
                style={{
                  background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(56, 189, 248, 0.2) 100%)',
                  border: '1px solid rgba(168, 85, 247, 0.45)',
                  color: '#e9d5ff',
                  padding: '0.48rem 0.9rem',
                  borderRadius: '6px',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem'
                }}
                title="Super Admin Architecture Guide & Competitor Review"
              >
                <BookOpen size={14} /> Super Admin Guide &amp; Competitors
              </button>
            )}

            <button
              onClick={fetchSbomData}
              disabled={loading}
              title="Refresh SBOM"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: 'var(--text-secondary, #cbd5e1)',
                padding: '0.48rem 0.65rem',
                borderRadius: '6px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: '0.75rem' }}>
          {/* Ecosystem Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600, marginRight: '0.25rem' }}>
              Ecosystem:
            </span>
            {['all', 'npm', 'pypi', 'golang', 'os_pkg'].map(eco => (
              <button
                key={eco}
                onClick={() => { setEcosystemFilter(eco); setCurrentPage(1); }}
                style={{
                  padding: '0.25rem 0.65rem',
                  borderRadius: '4px',
                  border: 'none',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  background: ecosystemFilter === eco ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                  color: ecosystemFilter === eco ? '#38bdf8' : 'var(--text-muted, #94a3b8)',
                  transition: 'all 0.15s ease'
                }}
              >
                {eco === 'all' ? 'All' : eco === 'npm' ? 'npm (Node.js)' : eco === 'pypi' ? 'PyPI (Python)' : eco === 'golang' ? 'Go' : 'OS Packages'}
              </button>
            ))}
          </div>

          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600, marginRight: '0.25rem' }}>
              Severity:
            </span>
            {[
              { id: 'all', label: 'All' },
              { id: 'critical', label: 'Critical' },
              { id: 'high', label: 'High' },
              { id: 'medium', label: 'Medium' },
              { id: 'clean', label: 'Clean / Secure' }
            ].map(sev => (
              <button
                key={sev.id}
                onClick={() => { setSeverityFilter(sev.id); setCurrentPage(1); }}
                style={{
                  padding: '0.25rem 0.65rem',
                  borderRadius: '4px',
                  border: 'none',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  background: severityFilter === sev.id ? 'rgba(168, 85, 247, 0.25)' : 'rgba(255, 255, 255, 0.04)',
                  color: severityFilter === sev.id ? '#c084fc' : 'var(--text-muted, #94a3b8)',
                  transition: 'all 0.15s ease'
                }}
              >
                {sev.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Interactive Component Table */}
      <div style={{
        background: 'rgba(10, 15, 28, 0.85)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        overflow: 'hidden'
      }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
            <thead>
              <tr style={{ background: 'rgba(255, 255, 255, 0.03)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <th style={{ padding: '0.85rem 1.15rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Software Component &amp; PURL</th>
                <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Version</th>
                <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Ecosystem</th>
                <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>CVE Vulnerabilities</th>
                <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Severity</th>
                <th style={{ padding: '0.85rem 1.15rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>Actionable Fix &amp; Remediation</th>
              </tr>
            </thead>
            <tbody>
              {paginatedComponents.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted, #94a3b8)' }}>
                    No software components matching the selected criteria.
                  </td>
                </tr>
              ) : (
                paginatedComponents.map(comp => {
                  const hasVulns = comp.has_vulnerabilities && Array.isArray(comp.vulnerabilities) && comp.vulnerabilities.length > 0;
                  const primaryVuln = hasVulns ? comp.vulnerabilities[0] : null;

                  return (
                    <tr
                      key={comp.id}
                      style={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                        transition: 'background 0.15s ease'
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      {/* Component Name & PURL */}
                      <td style={{ padding: '0.85rem 1.15rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Package size={15} color={hasVulns ? '#f87171' : '#34d399'} />
                          <strong style={{ color: '#ffffff', fontSize: '0.88rem' }}>{comp.name}</strong>
                          {comp.license && (
                            <span style={{ fontSize: '0.66rem', padding: '0.1rem 0.35rem', borderRadius: '3px', background: 'rgba(255, 255, 255, 0.06)', color: 'var(--text-muted, #94a3b8)' }}>
                              {comp.license}
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted, #94a3b8)', fontFamily: 'var(--font-mono, monospace)', marginTop: '0.2rem' }}>
                          {comp.purl || `pkg:${comp.ecosystem}/${comp.name}@${comp.version}`}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'rgba(255, 255, 255, 0.4)', marginTop: '0.15rem' }}>
                          {comp.source_ref}
                        </div>
                      </td>

                      {/* Version */}
                      <td style={{ padding: '0.85rem 1rem' }}>
                        <span style={{
                          fontFamily: 'var(--font-mono, monospace)',
                          fontSize: '0.8rem',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: 'rgba(255, 255, 255, 0.05)',
                          color: '#e2e8f0'
                        }}>
                          v{comp.version}
                        </span>
                      </td>

                      {/* Ecosystem */}
                      <td style={{ padding: '0.85rem 1rem' }}>
                        <span style={{
                          fontSize: '0.72rem',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontWeight: 600,
                          background: comp.ecosystem === 'npm' ? 'rgba(239, 68, 68, 0.15)' : comp.ecosystem === 'pypi' ? 'rgba(56, 189, 248, 0.15)' : comp.ecosystem === 'golang' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          color: comp.ecosystem === 'npm' ? '#f87171' : comp.ecosystem === 'pypi' ? '#38bdf8' : comp.ecosystem === 'golang' ? '#34d399' : '#fbbf24',
                          border: `1px solid ${comp.ecosystem === 'npm' ? 'rgba(239, 68, 68, 0.3)' : comp.ecosystem === 'pypi' ? 'rgba(56, 189, 248, 0.3)' : comp.ecosystem === 'golang' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
                        }}>
                          {comp.ecosystem}
                        </span>
                      </td>

                      {/* CVE Vulnerabilities */}
                      <td style={{ padding: '0.85rem 1rem' }}>
                        {hasVulns ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                            {comp.vulnerabilities.map((v, i) => (
                              <button
                                key={i}
                                onClick={() => setActiveAdvisory({ comp, vuln: v })}
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  padding: 0,
                                  textAlign: 'left',
                                  cursor: 'pointer',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.35rem'
                                }}
                              >
                                <span style={{
                                  fontSize: '0.72rem',
                                  padding: '0.15rem 0.45rem',
                                  borderRadius: '3px',
                                  fontWeight: 700,
                                  fontFamily: 'var(--font-mono, monospace)',
                                  background: v.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' : v.severity === 'high' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(56, 189, 248, 0.15)',
                                  color: v.severity === 'critical' ? '#f87171' : v.severity === 'high' ? '#fbbf24' : '#38bdf8',
                                  border: `1px solid ${v.severity === 'critical' ? 'rgba(239, 68, 68, 0.4)' : v.severity === 'high' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(56, 189, 248, 0.3)'}`
                                }}>
                                  {v.cveId} ({v.cvssScore})
                                </span>
                                <Info size={13} color="var(--text-muted, #94a3b8)" />
                              </button>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: '#34d399', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                            <Check size={13} /> Zero Known CVEs
                          </span>
                        )}
                      </td>

                      {/* Max Severity */}
                      <td style={{ padding: '0.85rem 1rem' }}>
                        <span style={{
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '0.2rem 0.55rem',
                          borderRadius: '4px',
                          background: comp.max_severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' : comp.max_severity === 'high' ? 'rgba(245, 158, 11, 0.2)' : comp.max_severity === 'medium' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                          color: comp.max_severity === 'critical' ? '#f87171' : comp.max_severity === 'high' ? '#fbbf24' : comp.max_severity === 'medium' ? '#38bdf8' : '#34d399',
                          border: `1px solid ${comp.max_severity === 'critical' ? 'rgba(239, 68, 68, 0.4)' : comp.max_severity === 'high' ? 'rgba(245, 158, 11, 0.4)' : comp.max_severity === 'medium' ? 'rgba(56, 189, 248, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`
                        }}>
                          {comp.max_severity === 'none' ? 'Secure' : comp.max_severity}
                        </span>
                      </td>

                      {/* Remediation & Actionable Fix */}
                      <td style={{ padding: '0.85rem 1.15rem' }}>
                        {hasVulns && primaryVuln ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                              <span style={{ fontSize: '0.74rem', color: 'var(--text-muted, #94a3b8)' }}>Target Fix:</span>
                              <strong style={{ color: '#34d399', fontSize: '0.82rem', fontFamily: 'var(--font-mono, monospace)' }}>
                                {primaryVuln.fixedVersion}
                              </strong>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                              <code style={{
                                background: 'rgba(0, 0, 0, 0.4)',
                                padding: '0.2rem 0.5rem',
                                borderRadius: '4px',
                                fontSize: '0.74rem',
                                color: 'var(--accent-cyan, #38bdf8)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                maxWidth: '240px'
                              }}>
                                {primaryVuln.remediationCmd}
                              </code>
                              <button
                                onClick={() => copyToClipboard(primaryVuln.remediationCmd, comp.id)}
                                title="Copy Fix Command"
                                style={{
                                  background: 'rgba(255, 255, 255, 0.06)',
                                  border: '1px solid rgba(255, 255, 255, 0.15)',
                                  color: copiedCmd === comp.id ? '#34d399' : '#ffffff',
                                  padding: '0.25rem 0.45rem',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.25rem',
                                  fontSize: '0.7rem'
                                }}
                              >
                                {copiedCmd === comp.id ? <Check size={12} /> : <Copy size={12} />}
                                {copiedCmd === comp.id ? 'Copied' : 'Copy'}
                              </button>
                            </div>
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.76rem', color: 'var(--text-muted, #94a3b8)' }}>
                            No remediation required
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '0.85rem 1.25rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          fontSize: '0.8rem',
          color: 'var(--text-muted, #94a3b8)'
        }}>
          <div>
            Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, filteredComponents.length)} of {filteredComponents.length} components
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: currentPage === 1 ? 'rgba(255, 255, 255, 0.2)' : '#ffffff',
                padding: '0.3rem 0.7rem',
                borderRadius: '4px',
                cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
              }}
            >
              Previous
            </button>
            <span>Page {currentPage} of {totalPages}</span>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                color: currentPage === totalPages ? 'rgba(255, 255, 255, 0.2)' : '#ffffff',
                padding: '0.3rem 0.7rem',
                borderRadius: '4px',
                cursor: currentPage === totalPages ? 'not-allowed' : 'pointer'
              }}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* 4. Advisory Details Modal */}
      {activeAdvisory && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1.5rem'
          }}
          onClick={(e) => { if (e.target === e.currentTarget) setActiveAdvisory(null); }}
        >
          <div style={{
            background: '#0d1322',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '560px',
            padding: '1.75rem',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <span style={{
                  fontSize: '0.74rem',
                  fontFamily: 'var(--font-mono, monospace)',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  background: activeAdvisory.vuln.severity === 'critical' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                  color: activeAdvisory.vuln.severity === 'critical' ? '#f87171' : '#fbbf24',
                  fontWeight: 700
                }}>
                  {activeAdvisory.vuln.cveId} (CVSS {activeAdvisory.vuln.cvssScore})
                </span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#ffffff', margin: '0.6rem 0 0 0' }}>
                  {activeAdvisory.vuln.title}
                </h3>
              </div>
              <button
                onClick={() => setActiveAdvisory(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted, #94a3b8)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary, #cbd5e1)', lineHeight: 1.6 }}>
              {activeAdvisory.vuln.description}
            </div>

            <div style={{ background: 'rgba(0, 0, 0, 0.4)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>
                AFFECTED COMPONENT:
              </div>
              <div style={{ fontSize: '0.85rem', color: '#ffffff', fontFamily: 'var(--font-mono, monospace)' }}>
                {activeAdvisory.comp.name} v{activeAdvisory.comp.version} ({activeAdvisory.comp.ecosystem})
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted, #94a3b8)' }}>
                Path: {activeAdvisory.comp.file_path}
              </div>
            </div>

            <div style={{ background: 'rgba(16, 185, 129, 0.06)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.25)', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.78rem', color: '#34d399', fontWeight: 700 }}>
                  RECOMMENDED SAFE FIX:
                </span>
                <span style={{ fontSize: '0.78rem', color: '#ffffff', fontFamily: 'var(--font-mono, monospace)' }}>
                  Target: <strong>{activeAdvisory.vuln.fixedVersion}</strong>
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <code style={{
                  background: 'rgba(0, 0, 0, 0.5)',
                  padding: '0.4rem 0.65rem',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                  color: 'var(--accent-cyan, #38bdf8)',
                  flex: 1,
                  fontFamily: 'var(--font-mono, monospace)'
                }}>
                  {activeAdvisory.vuln.remediationCmd}
                </code>
                <button
                  onClick={() => copyToClipboard(activeAdvisory.vuln.remediationCmd, 'modal-fix')}
                  style={{
                    background: 'rgba(16, 185, 129, 0.2)',
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    color: '#34d399',
                    padding: '0.4rem 0.8rem',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.3rem'
                  }}
                >
                  {copiedCmd === 'modal-fix' ? <Check size={14} /> : <Copy size={14} />}
                  {copiedCmd === 'modal-fix' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Super Admin Privileged Architecture & Competitive Review Modal */}
      {isSuperAdmin && showSuperAdminDocModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 10000,
          padding: '1.5rem'
        }}>
          <div style={{
            background: 'var(--bg-card, #0f172a)',
            border: '1px solid rgba(168, 85, 247, 0.45)',
            borderRadius: '12px',
            maxWidth: '1050px',
            width: '100%',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column',
            boxShadow: '0 25px 60px -15px rgba(168, 85, 247, 0.35)',
            overflow: 'hidden'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.15) 0%, rgba(15, 23, 42, 0.8) 100%)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <BookOpen size={20} color="#c084fc" />
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>
                    Super Admin SBOM Architecture &amp; Competitive Analysis
                  </h3>
                  <span style={{ fontSize: '0.72rem', color: '#c084fc', fontWeight: 600 }}>
                    STRICTLY CONFIDENTIAL • SUPER ADMIN ONLY • NIST SP 800-218 &amp; CYCLONEDX 1.6
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <button
                  onClick={() => window.open(`${apiUrl}/api/sbom/superadmin-guide?admin=true`, '_blank')}
                  style={{
                    background: 'rgba(168, 85, 247, 0.25)',
                    border: '1px solid rgba(168, 85, 247, 0.5)',
                    color: '#e9d5ff',
                    padding: '0.4rem 0.85rem',
                    borderRadius: '6px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem'
                  }}
                >
                  <Download size={14} /> Download Guide (.md)
                </button>
                <button
                  onClick={() => setShowSuperAdminDocModal(false)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted, #94a3b8)', cursor: 'pointer' }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Modal Body / Markdown Container */}
            <div style={{
              padding: '1.5rem',
              overflowY: 'auto',
              flex: 1,
              fontSize: '0.88rem',
              lineHeight: 1.65,
              color: 'var(--text-secondary, #cbd5e1)'
            }}>
              {guideLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', gap: '0.5rem', color: '#c084fc' }}>
                  <RefreshCw size={20} className="animate-spin" /> Loading privileged architectural document...
                </div>
              ) : (
                <pre style={{
                  whiteSpace: 'pre-wrap',
                  wordWrap: 'break-word',
                  fontFamily: 'inherit',
                  margin: 0,
                  fontSize: '0.86rem'
                }}>
                  {guideContent}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
