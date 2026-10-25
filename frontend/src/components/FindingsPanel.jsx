import React, { useState } from 'react';

export function FindingsPanel({
  findings = [],
  summary = {
    total_findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    security_findings_count: 0,
    code_quality_findings_count: 0,
    code_quality_score: 100,
    security_posture: 'Clean'
  },
  hasScanned = false,
  isAnalyzing = false,
  onSelectForAI
}) {
  const [filterType, setFilterType] = useState('ALL');

  const filteredFindings = findings.filter((f) => {
    if (filterType === 'ALL') return true;
    if (filterType === 'SECURITY') return f.agent === 'Security Vulnerability Agent';
    if (filterType === 'QUALITY') return f.agent === 'Code Analysis Agent';
    return f.severity?.toUpperCase() === filterType;
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

  const getAgentBadgeStyle = (agent) => {
    if (agent === 'Security Vulnerability Agent') {
      return {
        background: 'rgba(239, 68, 68, 0.15)',
        color: '#fca5a5',
        border: '1px solid rgba(239, 68, 68, 0.3)'
      };
    }
    return {
      background: 'rgba(56, 189, 248, 0.15)',
      color: '#7dd3fc',
      border: '1px solid rgba(56, 189, 248, 0.3)'
    };
  };

  return (
    <div className="glass-panel" style={{ padding: '24px' }} id="findings-panel">
      {/* Header and Summary stats */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff' }}>
            Unified Findings Registry ({hasScanned ? summary?.total_findings || 0 : 0})
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Parallel multi-agent static analysis: Security Vulnerability Agent + Code Analysis Agent
          </p>
        </div>

        {/* Severity & Agent counters pills */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
          {hasScanned && summary?.security_findings_count !== undefined && (
            <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239,68,68,0.4)' }}>
              🛡️ Security: {summary.security_findings_count}
            </span>
          )}
          {hasScanned && summary?.code_quality_findings_count !== undefined && (
            <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.4)' }}>
              🔍 Quality: {summary.code_quality_findings_count}
            </span>
          )}
          {hasScanned && summary?.code_quality_score !== undefined && (
            <span className="badge" style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16,185,129,0.4)' }}>
              ⭐ Quality Score: {summary.code_quality_score}/100
            </span>
          )}
          <span className="badge badge-critical">Critical: {hasScanned ? summary?.critical || 0 : 0}</span>
          <span className="badge badge-high">High: {hasScanned ? summary?.high || 0 : 0}</span>
          <span className="badge badge-medium">Medium: {hasScanned ? summary?.medium || 0 : 0}</span>
          <span className="badge badge-low">Low: {hasScanned ? summary?.low || 0 : 0}</span>
        </div>
      </div>

      {/* Filter Tabs — only show active if scanned */}
      {hasScanned && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', overflowX: 'auto', paddingBottom: '4px' }}>
          {[
            { id: 'ALL', label: 'All Findings' },
            { id: 'SECURITY', label: '🛡️ Security Only' },
            { id: 'QUALITY', label: '🔍 Quality Only' },
            { id: 'CRITICAL', label: 'Critical' },
            { id: 'HIGH', label: 'High' },
            { id: 'MEDIUM', label: 'Medium' },
            { id: 'LOW', label: 'Low' }
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              className={`btn ${filterType === tab.id ? 'btn-primary' : 'btn-secondary'}`}
              style={{ padding: '4px 12px', fontSize: '0.78rem' }}
              onClick={() => setFilterType(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {/* Active Analyzing State */}
      {isAnalyzing && (
        <div style={{ textAlign: 'center', padding: '40px 20px', background: 'rgba(6, 182, 212, 0.05)', borderRadius: '8px', border: '1px dashed rgba(6, 182, 212, 0.3)' }}>
          <span style={{ fontSize: '2rem' }}>⚡</span>
          <h4 style={{ color: 'var(--accent-cyan)', marginTop: '10px', fontSize: '1rem', fontWeight: '700' }}>
            Multi-Agent Orchestration in Progress…
          </h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '6px', maxWidth: '520px', margin: '6px auto 0 auto' }}>
            Running <strong>Security Vulnerability Agent</strong> (OWASP Top 10) and <strong>Code Analysis Agent</strong> (Smells, Complexity, Anti-Patterns) in parallel…
          </p>
        </div>
      )}

      {/* Placeholder State before any scan is performed */}
      {!isAnalyzing && !hasScanned && (
        <div style={{ textAlign: 'center', padding: '36px 20px', background: 'rgba(0, 0, 0, 0.2)', borderRadius: '8px', border: '1px dashed var(--border-subtle)' }}>
          <span style={{ fontSize: '2.4rem' }}>🛡️</span>
          <h4 style={{ color: '#ffffff', marginTop: '10px', fontSize: '1.05rem', fontWeight: '700' }}>
            Awaiting Multi-Agent Inspection
          </h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '6px', maxWidth: '480px', margin: '6px auto 0 auto' }}>
            Click <strong>⚡ Inspect &amp; Analyze</strong> or upload a <code>.py</code> / <code>.java</code> file to orchestrate parallel security and code quality audits.
          </p>

          <div
            style={{
              marginTop: '18px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '10px',
              textAlign: 'left'
            }}
          >
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#f87171' }}>🛡️ Security Vulnerability Agent</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>OWASP A01–A10 &bull; SQLi, RCE, Secrets, Path Traversal, SSRF</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#38bdf8' }}>🔍 Code Analysis Agent</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Code smells, Cyclomatic complexity, Anti-patterns, Leaks</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#fbbf24' }}>⚡ Parallel Multi-Agent Orchestration</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Concurrent thread pooling &amp; unified findings merging</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#34d399' }}>📊 Severity Scoring &amp; Posture</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Severity scoring 1–10 &bull; Quality score &bull; Grade A–F</div>
            </div>
          </div>
        </div>
      )}

      {/* Findings List or Empty State (when scan is complete) */}
      {!isAnalyzing && hasScanned && filteredFindings.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 20px', background: 'rgba(0, 0, 0, 0.2)', borderRadius: '8px', border: '1px dashed var(--border-subtle)' }}>
          <span style={{ fontSize: '2rem' }}>🎉</span>
          <h4 style={{ color: '#ffffff', marginTop: '10px', fontSize: '1rem' }}>No Issues Detected</h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
            {findings.length > 0
              ? 'No findings match the selected filter.'
              : 'The inspected source code adheres to all configured security and quality rules.'}
          </p>
        </div>
      )}

      {!isAnalyzing && hasScanned && filteredFindings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredFindings.map((finding, idx) => (
            <div key={`${finding.rule_id}-${finding.line}-${idx}`} className="finding-card">
              {/* Finding Top Row */}
              <div className="finding-header">
                <div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '6px' }}>
                    <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                      {finding.severity?.toUpperCase()}
                    </span>

                    {/* Agent Pill */}
                    <span className="badge" style={getAgentBadgeStyle(finding.agent)}>
                      {finding.agent === 'Code Analysis Agent' ? '🔍 Code Quality' : '🛡️ Security'}
                    </span>

                    {/* Category Pill */}
                    {finding.category && (
                      <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: '#cbd5e1' }}>
                        {finding.category}
                      </span>
                    )}

                    {/* Severity Score Pill */}
                    {finding.severity_score !== undefined && (
                      <span className="badge" style={{ background: 'rgba(251, 191, 36, 0.15)', color: '#fbbf24', border: '1px solid rgba(251, 191, 36, 0.3)' }}>
                        Score: {finding.severity_score}/10
                      </span>
                    )}

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

              {/* OWASP / CWE Category row */}
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', fontSize: '0.8rem', marginBottom: '8px' }}>
                {finding.owasp_category && (
                  <div style={{ color: 'var(--accent-cyan)' }}>
                    <b>OWASP Category:</b> {finding.owasp_category}
                  </div>
                )}
                {finding.cwe_id && (
                  <div style={{ color: '#94a3b8' }}>
                    <b>Standard:</b> {finding.cwe_id}
                  </div>
                )}
              </div>

              {/* Code Evidence snippet */}
              {finding.evidence && (
                <div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Code Evidence (Line {finding.line})
                  </div>
                  <pre className="code-evidence-box">{finding.evidence}</pre>
                </div>
              )}

              {/* Risk Explanation */}
              <div style={{ marginTop: '8px' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Risk &amp; Impact Analysis
                </div>
                <p style={{ fontSize: '0.88rem', color: '#cbd5e1', marginTop: '2px' }}>
                  {finding.risk_explanation}
                </p>
              </div>

              {/* Mitigation recommendation */}
              <div style={{ marginTop: '8px' }}>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Remediation Guidance
                </div>
                <p style={{ fontSize: '0.88rem', color: '#34d399', marginTop: '2px' }}>
                  {finding.mitigation}
                </p>
              </div>

              {/* Citations / Links */}
              {finding.owasp_references && finding.owasp_references.length > 0 && (
                <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Reference Documentation: </span>
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
