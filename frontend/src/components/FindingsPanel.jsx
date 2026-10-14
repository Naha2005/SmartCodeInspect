import React, { useState } from 'react';

export function FindingsPanel({ findings = [], summary = { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0 }, hasScanned = false, isAnalyzing = false, onSelectForAI }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === 'ALL') return true;
    return f.severity?.toUpperCase() === filterSeverity;
  });

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px' }} id="findings-panel">
      {/* Header and Summary stats */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff' }}>
            Vulnerability Findings ({hasScanned ? summary?.total_findings || 0 : 0})
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Deterministic static inspection AST and pattern matches
          </p>
        </div>

        {/* Severity counters pills */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <span className="badge badge-critical">Critical: {hasScanned ? summary?.critical || 0 : 0}</span>
          <span className="badge badge-high">High: {hasScanned ? summary?.high || 0 : 0}</span>
          <span className="badge badge-medium">Medium: {hasScanned ? summary?.medium || 0 : 0}</span>
          <span className="badge badge-low">Low: {hasScanned ? summary?.low || 0 : 0}</span>
        </div>
      </div>

      {/* Filter Tabs — only show active if scanned */}
      {hasScanned && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', overflowX: 'auto', paddingBottom: '4px' }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              type="button"
              className={`btn ${filterSeverity === sev ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '4px 12px', fontSize: '0.78rem' }}
              onClick={() => setFilterSeverity(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      )}

      {/* Active Analyzing State */}
      {isAnalyzing && (
        <div style={{ textAlign: 'center', padding: '40px 20px', background: 'rgba(6, 182, 212, 0.05)', borderRadius: '8px', border: '1px dashed rgba(6, 182, 212, 0.3)' }}>
          <span style={{ fontSize: '2rem' }}>⚡</span>
          <h4 style={{ color: 'var(--accent-cyan)', marginTop: '10px', fontSize: '1rem', fontWeight: '700' }}>
            Running Deterministic AST Security Analysis…
          </h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '6px', maxWidth: '480px', margin: '6px auto 0 auto' }}>
            Evaluating Abstract Syntax Tree tokens, pattern visitors, and OWASP Top 10 security rules…
          </p>
        </div>
      )}

      {/* Placeholder State before any scan is performed */}
      {!isAnalyzing && !hasScanned && (
        <div style={{ textAlign: 'center', padding: '36px 20px', background: 'rgba(0, 0, 0, 0.2)', borderRadius: '8px', border: '1px dashed var(--border-subtle)' }}>
          <span style={{ fontSize: '2.4rem' }}>🛡️</span>
          <h4 style={{ color: '#ffffff', marginTop: '10px', fontSize: '1.05rem', fontWeight: '700' }}>
            Awaiting Security Inspection
          </h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '6px', maxWidth: '440px', margin: '6px auto 0 auto' }}>
            Click <strong>⚡ Inspect &amp; Analyze</strong> or upload a <code>.py</code> / <code>.java</code> file to run deterministic AST security rules across OWASP categories.
          </p>

          <div
            style={{
              marginTop: '18px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '10px',
              textAlign: 'left'
            }}
          >
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#f87171' }}>💉 SQL &amp; Command Injection</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>A03:2021 &bull; Raw queries &amp; shell commands</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#fb923c' }}>🔑 Hardcoded Secrets &amp; Keys</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>A07:2021 &bull; Passwords, tokens &amp; API keys</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#fbbf24' }}>📦 Insecure Deserialization</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>A08:2021 &bull; Python pickle &amp; Java ObjectInputStream</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#38bdf8' }}>📁 Path Traversal &amp; Files</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>A01:2021 &bull; Directory traversal sequences</div>
            </div>
          </div>
        </div>
      )}

      {/* Findings List or Empty State (when scan is complete) */}
      {!isAnalyzing && hasScanned && filteredFindings.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 20px', background: 'rgba(0, 0, 0, 0.2)', borderRadius: '8px', border: '1px dashed var(--border-subtle)' }}>
          <span style={{ fontSize: '2rem' }}>🎉</span>
          <h4 style={{ color: '#ffffff', marginTop: '10px', fontSize: '1rem' }}>No Vulnerabilities Detected</h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
            {findings.length > 0
              ? 'No findings match the selected severity filter.'
              : 'The inspected source code adheres to all configured deterministic security rules.'}
          </p>
        </div>
      )}

      {!isAnalyzing && hasScanned && filteredFindings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredFindings.map((finding, idx) => (
            <div key={`${finding.rule_id}-${idx}`} className="finding-card">
              {/* Finding Top Row */}
              <div className="finding-header">
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '6px' }}>
                    <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                      {finding.severity?.toUpperCase()}
                    </span>
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: '#38bdf8' }}>
                      {finding.rule_id}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Line {finding.line}
                    </span>
                  </div>
                  <h3 className="finding-title">{finding.title}</h3>
                </div>

                <button
                  type="button"
                  className="btn btn-ai"
                  style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                  onClick={() => onSelectForAI(finding)}
                >
                  ✨ AI Advisory
                </button>
              </div>

              {/* OWASP Category */}
              <div style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', marginBottom: '8px' }}>
                <b>OWASP Category:</b> {finding.owasp_category}
              </div>

              {/* Code Evidence snippet */}
              {finding.evidence && (
                <div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Code Evidence
                  </div>
                  <pre className="code-evidence-box">{finding.evidence}</pre>
                </div>
              )}

              {/* Risk Explanation */}
              <div style={{ marginTop: '8px' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Risk Explanation
                </div>
                <p style={{ fontSize: '0.88rem', color: '#cbd5e1', marginTop: '2px' }}>
                  {finding.risk_explanation}
                </p>
              </div>

              {/* Mitigation recommendation */}
              <div style={{ marginTop: '8px' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Remediation
                </div>
                <p style={{ fontSize: '0.88rem', color: '#34d399', marginTop: '2px' }}>
                  {finding.mitigation}
                </p>
              </div>

              {/* OWASP Citations */}
              {finding.owasp_references && finding.owasp_references.length > 0 && (
                <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>OWASP Reference: </span>
                  {finding.owasp_references.map((url, uIdx) => (
                    <a
                      key={uIdx}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: 'var(--accent-cyan)', fontSize: '0.8rem', marginLeft: '6px', textDecoration: 'none' }}
                    >
                      🔗 {url.replace('https://', '').split('/')[0]}
                    </a>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
