import React, { useState, useMemo } from 'react';
import { 
  Calendar, 
  Clock, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowRight, 
  Download, 
  Sparkles, 
  HelpCircle, 
  ChevronRight, 
  Layers, 
  Activity, 
  Key, 
  Lock, 
  Server, 
  FileText, 
  RefreshCw, 
  ExternalLink,
  Shield,
  Zap,
  Info
} from 'lucide-react';

export interface MoscaMigrationPlannerProps {
  variant?: 'landing' | 'console';
  initialIndustry?: string;
  onNavigateToScan?: () => void;
  onNavigateToDownloads?: () => void;
  totalFleetEndpoints?: number;
  totalVulnerableAssets?: number;
}

interface IndustryPreset {
  id: string;
  name: string;
  sector: string;
  shelfLifeX: number; // X: Data shelf-life in years
  migrationTimeY: number; // Y: Migration time in years
  crqcHorizonZ: number; // Z: Years until CRQC
  shelfLifeExample: string;
  migrationExample: string;
  description: string;
  color: string;
}

const INDUSTRY_PRESETS: IndustryPreset[] = [
  {
    id: 'healthcare',
    name: 'Healthcare & Life Sciences',
    sector: 'HIPAA / HITECH / EHR',
    shelfLifeX: 25,
    migrationTimeY: 5,
    crqcHorizonZ: 7,
    shelfLifeExample: 'Patient records, genomic data, clinical trials, HIPAA mandates 25–50 yr secrecy.',
    migrationExample: 'Certified medical hardware, legacy PACS imaging, multi-cloud EHR integrations.',
    description: 'Patient health data transmitted today will remain sensitive well past Q-Day, creating an immediate HNDL deficit.',
    color: '#38bdf8'
  },
  {
    id: 'defense',
    name: 'Defense & Aerospace',
    sector: 'NSA CNSA 2.0 / CMMC',
    shelfLifeX: 30,
    migrationTimeY: 7,
    crqcHorizonZ: 5,
    shelfLifeExample: 'Classified blueprints, SATCOM telemetry, weapon systems, zero-trust enclaves.',
    migrationExample: 'Air-gapped facilities, MIL-STD hardware, rigorous CAVP/CMVP certification cycles.',
    description: 'Foreign adversaries actively wiretap and harvest defense communications for future quantum decryption.',
    color: '#fbbf24'
  },
  {
    id: 'banking',
    name: 'Financial Services & Banking',
    sector: 'PCI-DSS / GLBA / SWIFT',
    shelfLifeX: 10,
    migrationTimeY: 4,
    crqcHorizonZ: 7,
    shelfLifeExample: 'Long-term credit contracts, audit ledgers, SWIFT message signing, KYC/PII.',
    migrationExample: 'Mainframe core banking, fleet HSM upgrades, multi-bank payment networks.',
    description: 'Financial transactions signed with RSA/ECDSA risk offline forgery and repudiation once CRQCs emerge.',
    color: '#34d399'
  },
  {
    id: 'tech_ip',
    name: 'Corporate IP & Technology',
    sector: 'SaaS / Semi / Biotech',
    shelfLifeX: 15,
    migrationTimeY: 3,
    crqcHorizonZ: 7,
    shelfLifeExample: 'Proprietary source code, chip designs, chemical formulations, strategic M&A.',
    migrationExample: 'Containerized microservices, multi-cloud clusters, CI/CD code-signing pipelines.',
    description: 'Proprietary code exfiltrated today will be decrypted by competitors in the 2030s if not protected by PQC.',
    color: '#c084fc'
  },
  {
    id: 'energy',
    name: 'Critical Infrastructure & Energy',
    sector: 'NERC CIP / SCADA / OT',
    shelfLifeX: 20,
    migrationTimeY: 8,
    crqcHorizonZ: 6,
    shelfLifeExample: 'Power grid dispatch keys, pipeline telemetry, industrial PLC root certificates.',
    migrationExample: 'Field OT devices with 15-year lifecycles, air-gapped substations, physical firmware flashing.',
    description: 'Industrial control networks cannot be patched over-the-air, necessitating immediate hardware-level PQC planning.',
    color: '#f97316'
  }
];

export const MoscaMigrationPlanner: React.FC<MoscaMigrationPlannerProps> = ({
  variant = 'landing',
  initialIndustry = 'defense',
  onNavigateToScan,
  onNavigateToDownloads,
  totalFleetEndpoints,
  totalVulnerableAssets
}) => {
  const currentYear = 2026;

  // Selected preset or custom
  const [selectedPresetId, setSelectedPresetId] = useState<string>(initialIndustry);

  // The 3 core Mosca variables:
  // X: Data Shelf-life (years)
  const [shelfLifeX, setShelfLifeX] = useState<number>(25);
  // Y: Migration Runway (years)
  const [migrationTimeY, setMigrationTimeY] = useState<number>(5);
  // Z: Quantum Threat Horizon (years until CRQC)
  const [crqcHorizonZ, setCrqcHorizonZ] = useState<number>(7);

  // Active FAQ / Info tooltip state
  const [showFormulaDetails, setShowFormulaDetails] = useState<boolean>(false);

  // Sync state when a preset is selected
  const handleSelectPreset = (preset: IndustryPreset) => {
    setSelectedPresetId(preset.id);
    setShelfLifeX(preset.shelfLifeX);
    setMigrationTimeY(preset.migrationTimeY);
    setCrqcHorizonZ(preset.crqcHorizonZ);
  };

  // Real-time calculations
  const {
    crqcYear,
    migrationCompletionYear,
    dataSecrecyEndYear,
    deficitMargin,
    isAtRisk,
    retroactiveExposureYear,
    statusText,
    badgeColor
  } = useMemo(() => {
    const crqc = currentYear + crqcHorizonZ;
    const migDone = currentYear + migrationTimeY;
    const secDone = currentYear + shelfLifeX;
    
    // Mosca's Inequality: X + Y > Z
    const deficit = (shelfLifeX + migrationTimeY) - crqcHorizonZ;
    const atRisk = deficit > 0;
    
    // Earliest year of data currently exposed to retrospective decryption
    const retroYear = Math.max(2015, currentYear + crqcHorizonZ - shelfLifeX);

    let text = 'Quantum Resilient Runway';
    let color = '#10b981';

    if (deficit > 3) {
      text = `CRITICAL ACTIVE RISK (+${deficit} Yr Deficit)`;
      color = '#ef4444';
    } else if (deficit > 0) {
      text = `ACTIVE RISK (+${deficit} Yr Deficit)`;
      color = '#f97316';
    } else if (deficit === 0) {
      text = 'BORDERLINE HORIZON (0-Year Buffer)';
      color = '#f59e0b';
    } else {
      text = `QUANTUM RESILIENT (${Math.abs(deficit)} Yr Safety Buffer)`;
      color = '#10b981';
    }

    return {
      crqcYear: crqc,
      migrationCompletionYear: migDone,
      dataSecrecyEndYear: secDone,
      deficitMargin: deficit,
      isAtRisk: atRisk,
      retroactiveExposureYear: retroYear,
      statusText: text,
      badgeColor: color
    };
  }, [shelfLifeX, migrationTimeY, crqcHorizonZ, currentYear]);

  // Export JSON summary of the plan
  const handleExportPlan = () => {
    const plan = {
      title: "QuarkShield Post-Quantum Migration Assessment",
      model: "Mosca's Theorem (X + Y > Z)",
      generatedAt: new Date().toISOString(),
      parameters: {
        currentYear,
        dataShelfLifeYears_X: shelfLifeX,
        dataSecrecyExpiresYear: dataSecrecyEndYear,
        migrationRunwayYears_Y: migrationTimeY,
        migrationCompletionYear: migrationCompletionYear,
        crqcThreatHorizonYears_Z: crqcHorizonZ,
        estimatedCrqcArrivalYear: crqcYear
      },
      calculus: {
        deficitMarginYears: deficitMargin,
        status: statusText,
        isActivelyCompromisedToday: isAtRisk,
        retroactiveExposureSinceYear: retroactiveExposureYear
      },
      recommendedMilestones: [
        {
          phase: "Phase 1 (Days 0-90)",
          title: "Immediate HNDL Perimeter Shielding",
          action: "Deploy hybrid TLS 1.3 key encapsulation (X25519MLKEM768) on public edge proxies and API gateways."
        },
        {
          phase: "Phase 2 (Months 3-12)",
          title: "Cryptographic BOM Baseline Inventory",
          action: "Run QuarkShield Desktop Scanner fleetwide to inventory private keys, certificates, and algorithms into CycloneDX 1.6 CBOM."
        },
        {
          phase: "Phase 3 (Years 1-3)",
          title: "Enterprise PKI & CA Modernization",
          action: "Transition internal CAs to dual-signature certificates using NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)."
        },
        {
          phase: "Phase 4 (Years 3 to " + migrationTimeY + ")",
          title: "Hardware HSMs & Supply Chain Agility",
          action: "Upgrade HSM firmware and enforce strict PQC attestation in all software procurement SLAs."
        }
      ]
    };

    const blob = new Blob([JSON.stringify(plan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `QuarkShield_PQC_Migration_Plan_${selectedPresetId}_${currentYear}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div 
      className="mosca-planner-root"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '2rem',
        width: '100%',
        maxWidth: '1240px',
        margin: '0 auto',
        color: '#ffffff'
      }}
    >
      {/* Section Header */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2) 0%, rgba(168, 85, 247, 0.25) 100%)',
              border: '1px solid rgba(0, 242, 254, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-cyan)'
            }}>
              <Calendar size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, padding: '0.2rem 0.6rem', borderRadius: '50px', background: 'rgba(0, 242, 254, 0.12)', color: 'var(--accent-cyan)', border: '1px solid rgba(0, 242, 254, 0.3)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Interactive Risk Horizon Engine
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  NIST SP 800-227 &amp; CNSA 2.0 Aligned
                </span>
              </div>
              <h2 style={{ fontSize: 'clamp(1.5rem, 3.2vw, 2.2rem)', fontWeight: 800, margin: '0.35rem 0 0 0', letterSpacing: '-0.02em', color: '#ffffff' }}>
                Mosca&apos;s Quantum Migration Planner
              </h2>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              type="button"
              onClick={() => setShowFormulaDetails(!showFormulaDetails)}
              style={{
                background: showFormulaDetails ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                border: showFormulaDetails ? '1px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.12)',
                color: showFormulaDetails ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                fontSize: '0.84rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s ease'
              }}
            >
              <Info size={15} />
              <span>How the Math Works</span>
            </button>

            <button
              type="button"
              onClick={handleExportPlan}
              style={{
                background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(5, 150, 105, 0.25) 100%)',
                border: '1px solid rgba(16, 185, 129, 0.45)',
                color: '#34d399',
                padding: '0.5rem 1.15rem',
                borderRadius: '8px',
                fontSize: '0.84rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                transition: 'all 0.15s ease'
              }}
            >
              <Download size={15} />
              <span>Export Migration Plan</span>
            </button>
          </div>
        </div>

        <p style={{ margin: 0, fontSize: '0.96rem', color: 'var(--text-secondary)', lineHeight: 1.65, maxWidth: '880px' }}>
          Formulated by Dr. Michele Mosca, <strong>Mosca&apos;s Theorem</strong> mathematically proves when an organization is already compromised today. If your data shelf-life (<code style={{ color: '#c084fc' }}>X</code>) plus your migration time (<code style={{ color: 'var(--accent-cyan)' }}>Y</code>) exceeds the quantum threat horizon (<code style={{ color: '#ef4444' }}>Z</code>), adversaries capturing your encrypted traffic today will decrypt it offline while it remains sensitive.
        </p>

        {/* Expandable Explanation of Formula */}
        {showFormulaDetails && (
          <div style={{
            background: 'rgba(15, 23, 42, 0.85)',
            border: '1px solid rgba(0, 242, 254, 0.3)',
            borderRadius: '12px',
            padding: '1.25rem 1.5rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.85rem'
          }}>
            <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Zap size={16} color="var(--accent-cyan)" />
              The Mathematical Theorem: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>X + Y &gt; Z</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              <div style={{ padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', borderLeft: '3px solid #c084fc' }}>
                <strong style={{ color: '#ffffff' }}>X = Data Shelf-Life</strong>: Duration in years data must remain confidential (e.g., patient health records 30y, defense specs 25y, financial audits 10y).
              </div>
              <div style={{ padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', borderLeft: '3px solid var(--accent-cyan)' }}>
                <strong style={{ color: '#ffffff' }}>Y = Migration Time</strong>: Duration in years required to discover (CBOM), re-architect, test, and deploy post-quantum algorithms across the fleet.
              </div>
              <div style={{ padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', borderLeft: '3px solid #ef4444' }}>
                <strong style={{ color: '#ffffff' }}>Z = Threat Horizon</strong>: Years until a Cryptanalytically Relevant Quantum Computer (CRQC) arrives capable of executing Shor&apos;s algorithm.
              </div>
            </div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              * If <code>X + Y &gt; Z</code>, waiting to migrate until year <code>Z</code> guarantees total loss of confidentiality. The difference <code>(X + Y) - Z</code> represents your organization&apos;s active exposure deficit.
            </div>
          </div>
        )}
      </div>

      {/* Industry Sector Quick-Select Chips */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        <div style={{ fontSize: '0.82rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
          Step 1: Select Your Organization Profile or Benchmark Sector
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.75rem' }}>
          {INDUSTRY_PRESETS.map(preset => {
            const isSelected = selectedPresetId === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                style={{
                  padding: '0.85rem 1rem',
                  borderRadius: '10px',
                  background: isSelected ? 'rgba(0, 242, 254, 0.12)' : 'rgba(255, 255, 255, 0.03)',
                  border: isSelected ? '1.5px solid var(--accent-cyan)' : '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.35rem',
                  textAlign: 'left',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  boxShadow: isSelected ? '0 0 16px rgba(0, 242, 254, 0.2)' : 'none'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.88rem', fontWeight: 700, color: isSelected ? '#ffffff' : '#e2e8f0' }}>
                    {preset.name}
                  </span>
                  {isSelected && <CheckCircle2 size={14} color="var(--accent-cyan)" />}
                </div>
                <div style={{ fontSize: '0.74rem', color: preset.color, fontFamily: 'var(--font-mono)' }}>
                  {preset.sector}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  X={preset.shelfLifeX}y • Y={preset.migrationTimeY}y • Z={preset.crqcHorizonZ}y
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main 2-Column Workspace: Interactive Controls & Real-Time Gantt Timeline */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 420px), 1fr))',
        gap: '1.75rem',
        alignItems: 'start'
      }}>
        
        {/* Left Column: The 3 Interactive Questions with Realistic Guidance & Sliders */}
        <div className="glass-panel" style={{
          padding: '1.75rem',
          borderRadius: '14px',
          background: 'linear-gradient(135deg, rgba(13, 19, 33, 0.85) 0%, rgba(10, 15, 28, 0.95) 100%)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.75rem',
          minWidth: 0
        }}>
          <div>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--accent-cyan)', letterSpacing: '0.04em', marginBottom: '0.35rem' }}>
              Step 2: Model Your Organizational Parameters
            </div>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 800, color: '#ffffff' }}>
              Three Critical Timeline Questions
            </h3>
          </div>

          {/* QUESTION 1: Data Shelf-Life (X) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '22px', height: '22px', borderRadius: '50%', background: 'rgba(168, 85, 247, 0.25)', color: '#c084fc', fontSize: '0.78rem' }}>1</span>
                  How many years must your data remain secret? (<code style={{ color: '#c084fc' }}>X</code>)
                </label>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Data Secrecy Shelf-Life (e.g., patient EHR, defense specs, financial PII)
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.25rem', background: 'rgba(168, 85, 247, 0.15)', padding: '0.25rem 0.65rem', borderRadius: '6px', border: '1px solid rgba(168, 85, 247, 0.35)' }}>
                <span style={{ fontSize: '1.25rem', fontWeight: 800, color: '#c084fc' }}>{shelfLifeX}</span>
                <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Years</span>
              </div>
            </div>

            <input
              type="range"
              min={1}
              max={35}
              step={1}
              value={shelfLifeX}
              onChange={(e) => {
                setShelfLifeX(Number(e.target.value));
                setSelectedPresetId('custom');
              }}
              style={{
                width: '100%',
                accentColor: '#c084fc',
                cursor: 'pointer'
              }}
            />

            {/* Contextual Examples for X */}
            <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(0, 0, 0, 0.3)', borderRadius: '8px', fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'flex-start', gap: '0.5rem', lineHeight: 1.45 }}>
              <Info size={14} color="#c084fc" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>Benchmark Examples:</strong> Healthcare/Genomics: 25–50 yrs; Defense/Weapons: 25–35 yrs; Financial Ledgers: 7–10 yrs; Proprietary IP: 10–20 yrs; General SaaS: 3–5 yrs.
              </div>
            </div>
          </div>

          <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.06)' }} />

          {/* QUESTION 2: Migration Time (Y) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '22px', height: '22px', borderRadius: '50%', background: 'rgba(0, 242, 254, 0.2)', color: 'var(--accent-cyan)', fontSize: '0.78rem' }}>2</span>
                  How many years to fully migrate your fleet? (<code style={{ color: 'var(--accent-cyan)' }}>Y</code>)
                </label>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Time to inventory (CBOM), replace legacy algorithms, re-issue PKI &amp; update HSMs
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.25rem', background: 'rgba(0, 242, 254, 0.12)', padding: '0.25rem 0.65rem', borderRadius: '6px', border: '1px solid rgba(0, 242, 254, 0.35)' }}>
                <span style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{migrationTimeY}</span>
                <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Years</span>
              </div>
            </div>

            <input
              type="range"
              min={1}
              max={12}
              step={1}
              value={migrationTimeY}
              onChange={(e) => {
                setMigrationTimeY(Number(e.target.value));
                setSelectedPresetId('custom');
              }}
              style={{
                width: '100%',
                accentColor: 'var(--accent-cyan)',
                cursor: 'pointer'
              }}
            />

            {/* Contextual Examples for Y */}
            <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(0, 0, 0, 0.3)', borderRadius: '8px', fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'flex-start', gap: '0.5rem', lineHeight: 1.45 }}>
              <Info size={14} color="var(--accent-cyan)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>Migration Speed Factors:</strong> Cloud-native single stack: 2–3 yrs; Standard Enterprise (hundreds of servers): 4–5 yrs; Global Bank / Defense with hardware HSMs: 6–8+ yrs.
              </div>
            </div>
          </div>

          <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.06)' }} />

          {/* QUESTION 3: Threat Horizon (Z) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '22px', height: '22px', borderRadius: '50%', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', fontSize: '0.78rem' }}>3</span>
                  In how many years will CRQC arrive? (<code style={{ color: '#f87171' }}>Z</code>)
                </label>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Time until a quantum computer executes Shor&apos;s algorithm against RSA / ECC
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.25rem', background: 'rgba(239, 68, 68, 0.15)', padding: '0.25rem 0.65rem', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.35)' }}>
                <span style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f87171' }}>{crqcHorizonZ}</span>
                <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Years ({crqcYear})</span>
              </div>
            </div>

            <input
              type="range"
              min={2}
              max={12}
              step={1}
              value={crqcHorizonZ}
              onChange={(e) => {
                setCrqcHorizonZ(Number(e.target.value));
                setSelectedPresetId('custom');
              }}
              style={{
                width: '100%',
                accentColor: '#ef4444',
                cursor: 'pointer'
              }}
            />

            {/* Contextual Examples for Z */}
            <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(0, 0, 0, 0.3)', borderRadius: '8px', fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'flex-start', gap: '0.5rem', lineHeight: 1.45 }}>
              <Info size={14} color="#f87171" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>Expert Scenarios:</strong> Aggressive state breakthrough: 2029 (3 yrs); NSA CNSA 2.0 full mandate: 2030–2033 (4–7 yrs); NIST / BSI commercial consensus: 2035 (9 yrs).
              </div>
            </div>
          </div>

        </div>

        {/* Right Column: Calculated Risk Verdict & Visual Timeline */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Risk Verdict Banner */}
          <div style={{
            padding: '1.75rem',
            borderRadius: '14px',
            background: isAtRisk 
              ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.95) 100%)' 
              : 'linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(15, 23, 42, 0.95) 100%)',
            border: `1.5px solid ${badgeColor}60`,
            borderLeft: `6px solid ${badgeColor}`,
            boxShadow: `0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px ${badgeColor}20`,
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                {isAtRisk ? <ShieldAlert size={24} color="#ef4444" /> : <CheckCircle2 size={24} color="#10b981" />}
                <div>
                  <span style={{ fontSize: '0.74rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', color: badgeColor }}>
                    Mosca Inequality Evaluation
                  </span>
                  <h4 style={{ margin: 0, fontSize: '1.3rem', fontWeight: 900, color: '#ffffff', letterSpacing: '-0.015em' }}>
                    {statusText}
                  </h4>
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Formula Calculus</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.05rem', fontWeight: 800, color: badgeColor }}>
                  {shelfLifeX} + {migrationTimeY} {isAtRisk ? '>' : '<='} {crqcHorizonZ}
                </div>
              </div>
            </div>

            <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {isAtRisk ? (
                <>
                  Your required secrecy (<code style={{ color: '#c084fc' }}>{shelfLifeX} yrs</code>) + migration transition (<code style={{ color: 'var(--accent-cyan)' }}>{migrationTimeY} yrs</code>) exceeds the arrival of a cryptanalytically relevant quantum computer (<code style={{ color: '#f87171' }}>{crqcHorizonZ} yrs / {crqcYear}</code>). <strong>Adversaries tapping network connections today can harvest your traffic now and decrypt it in {crqcYear} while your data is still sensitive!</strong>
                </>
              ) : (
                <>
                  Your migration schedule completes in <code style={{ color: 'var(--accent-cyan)' }}>{migrationCompletionYear}</code>, ahead of the projected quantum threat horizon (<code style={{ color: '#10b981' }}>{crqcYear}</code>). You possess a <strong style={{ color: '#10b981' }}>{Math.abs(deficitMargin)}-year security runway</strong>, provided your migration starts immediately.
                </>
              )}
            </p>

            {/* Quick Metrics Bar */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.75rem',
              paddingTop: '0.5rem',
              borderTop: '1px solid rgba(255, 255, 255, 0.08)'
            }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Current Year</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff' }}>{currentYear}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>CRQC Q-Day (Z)</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f87171' }}>{crqcYear}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>PQC Deployment (Y)</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{migrationCompletionYear}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Secrecy End (X)</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#c084fc' }}>{dataSecrecyEndYear}</div>
              </div>
            </div>
          </div>

          {/* Visual Gantt Timeline Graphic */}
          <div className="glass-panel" style={{
            padding: '1.5rem',
            borderRadius: '14px',
            background: 'rgba(10, 15, 28, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1.25rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
                Visual Timeline Modeling (2026 – {Math.max(dataSecrecyEndYear, crqcYear + 5)})
              </span>
              <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                Scale: 1 yr/increment
              </span>
            </div>

            {/* Timeline Bars */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              
              {/* Timeline Axis Labels */}
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', padding: '0 0.5rem' }}>
                <span>{currentYear} (Now)</span>
                <span>{Math.round((currentYear + Math.max(dataSecrecyEndYear, crqcYear)) / 2)}</span>
                <span>{Math.max(dataSecrecyEndYear, crqcYear + 5)}</span>
              </div>

              {/* Bar 1: Migration Time Y */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <RefreshCw size={12} /> System Migration Runway (Y)
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Complete by {migrationCompletionYear} ({migrationTimeY} yrs)
                  </span>
                </div>
                <div style={{ width: '100%', height: '14px', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '50px', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    width: `${Math.min(100, (migrationTimeY / (Math.max(dataSecrecyEndYear, crqcYear + 5) - currentYear)) * 100)}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #00f2fe 0%, #2563eb 100%)',
                    borderRadius: '50px',
                    boxShadow: '0 0 10px rgba(0, 242, 254, 0.4)'
                  }} />
                </div>
              </div>

              {/* Bar 2: Data Shelf-Life X */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                  <span style={{ color: '#c084fc', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Lock size={12} /> Data Confidentiality Lifespan (X)
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Secret until {dataSecrecyEndYear} ({shelfLifeX} yrs)
                  </span>
                </div>
                <div style={{ width: '100%', height: '14px', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '50px', overflow: 'hidden', position: 'relative' }}>
                  <div style={{
                    width: `${Math.min(100, (shelfLifeX / (Math.max(dataSecrecyEndYear, crqcYear + 5) - currentYear)) * 100)}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #c084fc 0%, #7c3aed 100%)',
                    borderRadius: '50px',
                    boxShadow: '0 0 10px rgba(168, 85, 247, 0.4)'
                  }} />
                </div>
              </div>

              {/* Bar 3: CRQC Arrival Line (Z) */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', marginTop: '0.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                  <span style={{ color: '#f87171', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <AlertTriangle size={12} /> Quantum Threat Horizon (Z: {crqcYear})
                  </span>
                  <span style={{ color: '#f87171', fontFamily: 'var(--font-mono)' }}>
                    Q-Day: CRQC executes Shor&apos;s
                  </span>
                </div>
                
                {/* Visual Position of Z marker */}
                <div style={{ width: '100%', height: '18px', position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <div style={{ width: '100%', height: '2px', background: 'rgba(255, 255, 255, 0.1)' }} />
                  <div style={{
                    position: 'absolute',
                    left: `${Math.min(95, (crqcHorizonZ / (Math.max(dataSecrecyEndYear, crqcYear + 5) - currentYear)) * 100)}%`,
                    transform: 'translateX(-50%)',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '2px'
                  }}>
                    <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#ef4444', border: '2px solid #ffffff', boxShadow: '0 0 12px #ef4444' }} />
                    <span style={{ fontSize: '0.7rem', color: '#f87171', fontWeight: 700, whiteSpace: 'nowrap' }}>
                      {crqcYear}
                    </span>
                  </div>
                </div>
              </div>

            </div>

            {/* Retroactive Decryption Callout */}
            {isAtRisk && (
              <div style={{
                padding: '0.85rem 1rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem'
              }}>
                <ShieldAlert size={20} color="#ef4444" style={{ flexShrink: 0 }} />
                <div style={{ fontSize: '0.82rem', color: '#fca5a5', lineHeight: 1.5 }}>
                  <strong>HNDL Retroactive Decryption Exposure:</strong> Any encrypted data generated between <strong>{retroactiveExposureYear}</strong> and <strong>{migrationCompletionYear}</strong> will be decrypted by adversaries before its {shelfLifeX}-year confidentiality requirement expires!
                </div>
              </div>
            )}
          </div>

        </div>

      </div>

      {/* Step 3: Prioritized 4-Phase Migration Roadmap */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--accent-cyan)', letterSpacing: '0.04em', marginBottom: '0.2rem' }}>
              Step 3: Actionable Transition Milestones
            </div>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 800, color: '#ffffff' }}>
              Prioritized Post-Quantum Migration Milestones
            </h3>
          </div>
          <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Tailored to your {shelfLifeX}y shelf-life and {migrationTimeY}y migration schedule
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
          
          {/* Phase 1 */}
          <div className="glass-panel" style={{
            padding: '1.35rem',
            borderRadius: '12px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderTop: '4px solid #ef4444',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
            minWidth: 0
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.74rem', fontWeight: 800, padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                DAYS 0 – 90
              </span>
              <span style={{ fontSize: '0.72rem', color: '#ef4444', fontWeight: 700 }}>
                PRIORITY 1: CRITICAL
              </span>
            </div>
            <h4 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
              HNDL Perimeter Neutralization
            </h4>
            <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
              Activate hybrid post-quantum key encapsulation (<code style={{ color: 'var(--accent-cyan)' }}>X25519MLKEM768</code>) on public edge reverse proxies, CDN gateways, and external APIs. This stops adversaries from wiretapping and archiving ongoing traffic today.
            </p>
            <div style={{ marginTop: 'auto', paddingTop: '0.5rem', fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <Zap size={13} /> Test Outbound TLS Probe
            </div>
          </div>

          {/* Phase 2 */}
          <div className="glass-panel" style={{
            padding: '1.35rem',
            borderRadius: '12px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(0, 242, 254, 0.3)',
            borderTop: '4px solid var(--accent-cyan)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
            minWidth: 0
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.74rem', fontWeight: 800, padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)' }}>
                MONTHS 3 – 12
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                PRIORITY 2: DISCOVERY
              </span>
            </div>
            <h4 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
              Cryptographic BOM Baseline
            </h4>
            <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
              Deploy QuarkShield Desktop Scanner fleetwide across Windows, macOS, and Linux workstations and servers. Generate an automated CycloneDX 1.6 Cryptographic BOM (CBOM) to catalogue all RSA/ECC private keys, certificates, and hardcoded tokens.
            </p>
            <div style={{ marginTop: 'auto', paddingTop: '0.5rem', fontSize: '0.76rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <Layers size={13} /> Export CycloneDX 1.6 CBOM
            </div>
          </div>

          {/* Phase 3 */}
          <div className="glass-panel" style={{
            padding: '1.35rem',
            borderRadius: '12px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(168, 85, 247, 0.3)',
            borderTop: '4px solid #c084fc',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
            minWidth: 0
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.74rem', fontWeight: 800, padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>
                YEARS 1 – 3
              </span>
              <span style={{ fontSize: '0.72rem', color: '#c084fc', fontWeight: 700 }}>
                PRIORITY 3: INFRASTRUCTURE
              </span>
            </div>
            <h4 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
              PKI, CAs &amp; Identity Transition
            </h4>
            <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
              Transition internal Certificate Authorities to dual-signature roots using NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). Re-sign internal microservice mTLS identities, code-signing certificates, and corporate VPN profiles.
            </p>
            <div style={{ marginTop: 'auto', paddingTop: '0.5rem', fontSize: '0.76rem', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <Key size={13} /> Dual-Signature Root Trust
            </div>
          </div>

          {/* Phase 4 */}
          <div className="glass-panel" style={{
            padding: '1.35rem',
            borderRadius: '12px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderTop: '4px solid #34d399',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
            minWidth: 0
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.74rem', fontWeight: 800, padding: '0.2rem 0.6rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
                YEARS 3 – {migrationTimeY}
              </span>
              <span style={{ fontSize: '0.72rem', color: '#34d399', fontWeight: 700 }}>
                PRIORITY 4: SUPPLY CHAIN
              </span>
            </div>
            <h4 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
              HSM Hardware &amp; Vendor SLAs
            </h4>
            <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
              Upgrade physical Hardware Security Modules (HSMs) to FIPS 140-3 lattice firmware. Enforce mandatory post-quantum compliance clauses in all third-party vendor procurement contracts to meet NSA CNSA 2.0 deadlines.
            </p>
            <div style={{ marginTop: 'auto', paddingTop: '0.5rem', fontSize: '0.76rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <Shield size={13} /> Full CNSA 2.0 Attestation
            </div>
          </div>

        </div>
      </div>

      {/* Action Footer Call-to-Action Card */}
      <div className="glass-panel" style={{
        padding: '1.75rem 2rem',
        borderRadius: '14px',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(10, 15, 28, 0.95) 100%)',
        border: '1px solid rgba(0, 242, 254, 0.3)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1.25rem'
      }}>
        <div>
          <h4 style={{ margin: '0 0 0.3rem 0', fontSize: '1.2rem', fontWeight: 800, color: '#ffffff' }}>
            Ready to accurately measure your organization&apos;s true migration runway?
          </h4>
          <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--text-secondary)', maxWidth: '680px', lineHeight: 1.55 }}>
            Don&apos;t rely on guesses for <code style={{ color: 'var(--accent-cyan)' }}>Y (Migration Time)</code>. Run QuarkShield&apos;s native desktop scanner to automatically catalogue your exact keys, certificates, and cipher suites in minutes.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
          {variant === 'landing' ? (
            <>
              <a
                href="#downloads"
                className="btn-primary"
                style={{
                  padding: '0.75rem 1.6rem',
                  borderRadius: '8px',
                  fontSize: '0.92rem',
                  fontWeight: 700,
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  boxShadow: '0 0 20px rgba(0, 242, 254, 0.35)'
                }}
              >
                <Download size={16} /> Download Desktop Scanner
              </a>
              <a
                href="#probe"
                style={{
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  color: '#ffffff',
                  padding: '0.75rem 1.35rem',
                  borderRadius: '8px',
                  fontSize: '0.92rem',
                  fontWeight: 600,
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem'
                }}
              >
                <Zap size={16} color="var(--accent-cyan)" /> Test Outbound TLS Probe
              </a>
            </>
          ) : (
            <>
              {onNavigateToScan && (
                <button
                  type="button"
                  onClick={onNavigateToScan}
                  className="btn-primary"
                  style={{
                    padding: '0.75rem 1.6rem',
                    borderRadius: '8px',
                    fontSize: '0.92rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.45rem'
                  }}
                >
                  <Server size={16} /> Deploy Agent to Fleet
                </button>
              )}
              <button
                type="button"
                onClick={handleExportPlan}
                style={{
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  color: '#ffffff',
                  padding: '0.75rem 1.35rem',
                  borderRadius: '8px',
                  fontSize: '0.92rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem'
                }}
              >
                <FileText size={16} color="var(--accent-cyan)" /> Save Executive Roadmap
              </button>
            </>
          )}
        </div>
      </div>

    </div>
  );
};

export default MoscaMigrationPlanner;
