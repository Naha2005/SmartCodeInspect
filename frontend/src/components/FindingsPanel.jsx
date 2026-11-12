import React, { useState } from 'react';
import { copyToClipboard } from '../utils/clipboard';

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
    overall_code_health_score: 100,
    security_posture: 'Clean'
  },
  hasScanned = false,
  isAnalyzing = false,
  onSelectForAI,
  onOpenAssistant,
  onOpenPrSummary,
  onApplyFix,
  fixedFindingKeys = new Set(),
  fixedLinesMap = {},
  onFixAll
}) {
  const [filterType, setFilterType] = useState('ALL');
  const [expandedRemediations, setExpandedRemediations] = useState({});
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [appliedIndex, setAppliedIndex] = useState(null);
  const [diffViewIndex, setDiffViewIndex] = useState({}); // idx: boolean (true for diff, false for clean)
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('severity'); // 'severity' | 'line' | 'rule'

  const toggleRemediation = (idx) => {
    setExpandedRemediations((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const handleCopyCode = async (code, idx) => {
    if (!code) return;
    const success = await copyToClipboard(code);
    if (success) {
      setCopiedIndex(idx);
      setTimeout(() => setCopiedIndex(null), 2500);
    }
  };

  const handleApplyClick = (finding, correctedCode, idx) => {
    if (onApplyFix && correctedCode) {
      onApplyFix(finding, correctedCode);
      setAppliedIndex(idx);
      setTimeout(() => setAppliedIndex(null), 3000);
    }
  };

  const severityWeight = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };

  const processedFindings = findings
    .filter((f) => {
      // Category / severity tab filter
      if (filterType === 'SECURITY' && f.agent !== 'Security Vulnerability Agent') return false;
      if (filterType === 'QUALITY' && f.agent !== 'Code Analysis Agent') return false;
      if (!['ALL', 'SECURITY', 'QUALITY'].includes(filterType) && f.severity?.toUpperCase() !== filterType) return false;

      // Text search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesRule = (f.rule_id || '').toLowerCase().includes(q);
        const matchesTitle = (f.title || '').toLowerCase().includes(q);
        const matchesEvidence = (f.evidence || '').toLowerCase().includes(q);
        const matchesCwe = (f.cwe_id || '').toLowerCase().includes(q);
        const matchesCategory = (f.category || '').toLowerCase().includes(q);
        return matchesRule || matchesTitle || matchesEvidence || matchesCwe || matchesCategory;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'line') {
        return (a.line || 0) - (b.line || 0);
      }
      if (sortBy === 'rule') {
        return (a.rule_id || '').localeCompare(b.rule_id || '');
      }
      // default: severity high to low
      const wA = severityWeight[a.severity?.toLowerCase()] ?? 0;
      const wB = severityWeight[b.severity?.toLowerCase()] ?? 0;
      if (wB !== wA) return wB - wA;
      return (a.line || 0) - (b.line || 0);
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

  const healthScore = summary?.overall_code_health_score ?? (
    summary?.critical > 0 ? 55 : summary?.high > 0 ? 70 : (summary?.code_quality_score ?? 90)
  );

  const getHealthBadgeStyle = (score) => {
    if (score >= 80) {
      return { background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.4)' };
    }
    if (score >= 60) {
      return { background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.4)' };
    }
    return { background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)' };
  };

  return (
    <div className="glass-panel" style={{ padding: '24px' }} id="findings-panel">
      {/* Header and Summary stats */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff' }}>
              Findings &amp; Remediation Portal ({hasScanned ? summary?.total_findings || 0 : 0})
            </h2>
            {hasScanned && (
              <span className="badge" style={getHealthBadgeStyle(healthScore)}>
                Health: {healthScore}/100
              </span>
            )}
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Multi-Agent Inspection: Security Vulnerability Agent + Code Analysis Agent + Remediation Agent
          </p>
        </div>

        {/* Action Buttons: PR Summary & Chat Assistant */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          {hasScanned && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onOpenPrSummary}
              style={{ fontSize: '0.8rem', padding: '6px 14px', background: 'rgba(56, 189, 248, 0.1)', borderColor: 'rgba(56, 189, 248, 0.3)', color: '#7dd3fc' }}
            >
              📋 PR Review Summary
            </button>
          )}

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onOpenAssistant && onOpenAssistant(null)}
            style={{ fontSize: '0.8rem', padding: '6px 14px' }}
          >
            🤖 AI Code Assistant
          </button>
        </div>
      </div>

      {/* Severity & Metrics Bar */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '14px' }}>
        {hasScanned && (
          <span
            className="badge"
            style={{
              background: (summary?.active_errors_count === 0 && findings.length > 0) ? 'rgba(34, 197, 94, 0.25)' : 'rgba(239, 68, 68, 0.25)',
              color: (summary?.active_errors_count === 0 && findings.length > 0) ? '#4ade80' : '#fca5a5',
              border: (summary?.active_errors_count === 0 && findings.length > 0) ? '1px solid rgba(34, 197, 94, 0.45)' : '1px solid rgba(239, 68, 68, 0.45)',
              fontWeight: '700'
            }}
          >
            {summary?.active_errors_count === 0 && findings.length > 0 ? '🎉 0 Active Errors' : `🔴 Active Errors: ${summary?.active_errors_count ?? (findings.length - (fixedFindingKeys?.size || 0))}`}
          </span>
        )}
        {hasScanned && ((fixedFindingKeys?.size || 0) > 0 || (summary?.fixed_count || 0) > 0) && (
          <span
            className="badge"
            style={{
              background: 'rgba(34, 197, 94, 0.2)',
              color: '#4ade80',
              border: '1px solid rgba(34, 197, 94, 0.4)',
              fontWeight: '700'
            }}
          >
            🟢 Remediated: {summary?.fixed_count ?? (fixedFindingKeys?.size || 0)}
          </span>
        )}
        {hasScanned && summary?.security_findings_count !== undefined && (
          <span
            className="badge"
            style={{
              background: summary.security_findings_count === 0 ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
              color: summary.security_findings_count === 0 ? '#4ade80' : '#f87171',
              border: `1px solid ${summary.security_findings_count === 0 ? 'rgba(34,197,94,0.4)' : 'rgba(239,68,68,0.4)'}`
            }}
          >
            🛡️ Security: {summary.security_findings_count}
          </span>
        )}
        {hasScanned && summary?.code_quality_findings_count !== undefined && (
          <span
            className="badge"
            style={{
              background: summary.code_quality_findings_count === 0 ? 'rgba(34, 197, 94, 0.2)' : 'rgba(56, 189, 248, 0.2)',
              color: summary.code_quality_findings_count === 0 ? '#4ade80' : '#38bdf8',
              border: `1px solid ${summary.code_quality_findings_count === 0 ? 'rgba(34,197,94,0.4)' : 'rgba(56,189,248,0.4)'}`
            }}
          >
            🔍 Quality: {summary.code_quality_findings_count}
          </span>
        )}
        {hasScanned && summary?.code_quality_score !== undefined && (
          <span className="badge" style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16,185,129,0.4)' }}>
            ⭐ Quality Score: {summary.code_quality_score}/100
          </span>
        )}
        {hasScanned && summary?.security_posture && (
          <span
            className="badge"
            style={{
              background: (summary.security_posture.includes('A') || summary.active_errors_count === 0) ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
              color: (summary.security_posture.includes('A') || summary.active_errors_count === 0) ? '#34d399' : '#f87171',
              border: `1px solid ${(summary.security_posture.includes('A') || summary.active_errors_count === 0) ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`
            }}
            title={`Security Posture: ${summary.security_posture}`}
          >
            🛡️ Grade: {summary.active_errors_count === 0 || summary.security_posture.includes('A+') ? 'A+' : summary.security_posture.includes('A') ? 'A' : (summary.security_posture.split(' ')[1] || summary.security_posture.split(' ')[0])}
          </span>
        )}
        <span
          className={`badge ${summary?.critical === 0 ? 'badge-low' : 'badge-critical'}`}
          style={summary?.critical === 0 ? { background: 'rgba(34, 197, 94, 0.18)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.35)' } : undefined}
        >
          Critical: {hasScanned ? summary?.critical || 0 : 0}
        </span>
        <span
          className={`badge ${summary?.high === 0 ? 'badge-low' : 'badge-high'}`}
          style={summary?.high === 0 ? { background: 'rgba(34, 197, 94, 0.18)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.35)' } : undefined}
        >
          High: {hasScanned ? summary?.high || 0 : 0}
        </span>
        <span
          className={`badge ${summary?.medium === 0 ? 'badge-low' : 'badge-medium'}`}
          style={summary?.medium === 0 ? { background: 'rgba(34, 197, 94, 0.18)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.35)' } : undefined}
        >
          Medium: {hasScanned ? summary?.medium || 0 : 0}
        </span>
        <span
          className="badge badge-low"
          style={summary?.low === 0 ? { background: 'rgba(34, 197, 94, 0.18)', color: '#4ade80', border: '1px solid rgba(34, 197, 94, 0.35)' } : undefined}
        >
          Low: {hasScanned ? summary?.low || 0 : 0}
        </span>
      </div>

      {/* Filter Tabs — only show active if scanned */}
      {hasScanned && (
        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', overflowX: 'auto', paddingBottom: '4px' }}>
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

      {/* Advanced Search & Sort Bar (Milestone 3 Feature) */}
      {hasScanned && (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '220px', position: 'relative' }}>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="🔍 Search findings by rule ID, title, evidence, or CWE..."
              style={{
                width: '100%',
                background: 'rgba(0, 0, 0, 0.35)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '6px 12px',
                color: '#ffffff',
                fontSize: '0.8rem',
                outline: 'none'
              }}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                style={{
                  position: 'absolute',
                  right: '8px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  fontSize: '0.8rem'
                }}
              >
                ✕
              </button>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <span>Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              style={{
                background: '#090e1a',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                color: '#cbd5e1',
                padding: '5px 10px',
                fontSize: '0.78rem',
                outline: 'none'
              }}
            >
              <option value="severity">Severity (High to Low)</option>
              <option value="line">Line Number</option>
              <option value="rule">Rule ID</option>
            </select>
          </div>

          {searchQuery && (
            <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
              Showing {processedFindings.length} of {findings.length}
            </span>
          )}
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
            Running <strong>Security Vulnerability Agent</strong> (OWASP Top 10), <strong>Code Analysis Agent</strong> (Smells, Complexity), and <strong>Remediation Agent</strong> (Fixes &amp; Code Examples)…
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
            Click <strong>⚡ Inspect &amp; Analyze</strong> or upload a <code>.py</code> / <code>.java</code> file to orchestrate parallel security, quality, and remediation audits.
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
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>OWASP Top 10 &bull; SQLi, RCE, Secrets, Path Traversal, SSRF</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#38bdf8' }}>🔍 Code Analysis Agent</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Code smells, Cyclomatic complexity, Anti-patterns, Leaks</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#34d399' }}>🛠️ Remediation Agent</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Corrected code examples &amp; step-by-step fix recommendations</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#c084fc' }}>📋 PR Summary &amp; Assistant</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '2px' }}>Structured PR review report &bull; Conversational RAG assistant</div>
            </div>
          </div>
        </div>
      )}

      {/* Findings List or Empty State */}
      {!isAnalyzing && hasScanned && processedFindings.length === 0 && (
        <div style={{ textAlign: 'center', padding: '40px 20px', background: 'rgba(0, 0, 0, 0.2)', borderRadius: '8px', border: '1px dashed var(--border-subtle)' }}>
          <span style={{ fontSize: '2rem' }}>🎉</span>
          <h4 style={{ color: '#ffffff', marginTop: '10px', fontSize: '1rem' }}>No Issues Detected</h4>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '4px' }}>
            {findings.length > 0
              ? 'No findings match the selected filter or search query.'
              : 'The inspected source code adheres to all configured security and quality rules.'}
          </p>
        </div>
      )}

      {!isAnalyzing && hasScanned && processedFindings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {processedFindings.map((finding, idx) => {
            const isRemediationOpen = expandedRemediations[idx] !== false; // open by default
            const remediation = finding.remediation;
            const isDiffActive = Boolean(diffViewIndex[idx]);
            const findingKey = `${finding.rule_id || 'RULE'}-${finding.line || 0}-${(finding.evidence || '').slice(0, 30)}`;
            const isFixed = fixedFindingKeys?.has(findingKey) || fixedLinesMap?.[finding.line];

            return (
              <div
                key={`${finding.rule_id}-${finding.line}-${idx}`}
                className="finding-card"
                style={{
                  border: isFixed ? '1px solid rgba(34, 197, 94, 0.45)' : undefined,
                  boxShadow: isFixed ? '0 0 14px rgba(34, 197, 94, 0.1)' : undefined
                }}
              >
                {/* Finding Top Row */}
                <div className="finding-header">
                  <div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '6px' }}>
                      <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity?.toUpperCase()}
                      </span>

                      {/* Remediation Status Pill */}
                      {isFixed && (
                        <span
                          className="badge"
                          style={{
                            background: 'rgba(34, 197, 94, 0.2)',
                            color: '#4ade80',
                            border: '1px solid rgba(34, 197, 94, 0.45)',
                            fontWeight: '700'
                          }}
                        >
                          ✅ Remediated &amp; Fixed
                        </span>
                      )}

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

                  {/* Actions for Finding */}
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      style={{ padding: '6px 12px', fontSize: '0.78rem', background: 'rgba(6, 182, 212, 0.15)', borderColor: 'rgba(6, 182, 212, 0.3)', color: 'var(--accent-cyan)' }}
                      onClick={() => onOpenAssistant && onOpenAssistant(finding)}
                      title="Ask follow-up questions about this finding"
                    >
                      💬 Ask Assistant
                    </button>
                    <button
                      type="button"
                      className="btn btn-ai"
                      style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                      onClick={() => onSelectForAI && onSelectForAI(finding)}
                    >
                      ✨ AI Advisory
                    </button>
                  </div>
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
                  <div className="code-evidence-box">
                    <span style={{ color: '#94a3b8', fontSize: '0.74rem', display: 'block', marginBottom: '4px' }}>
                      Flagged Code Context (Line {finding.line}):
                    </span>
                    <code>{finding.evidence}</code>
                  </div>
                )}

                {/* Risk Explanation */}
                {finding.risk_explanation && (
                  <p style={{ fontSize: '0.85rem', color: '#cbd5e1', margin: '8px 0', lineHeight: '1.45' }}>
                    <strong>Risk Impact:</strong> {finding.risk_explanation}
                  </p>
                )}

                {/* ========================================================= */}
                {/* Advanced Remediation Agent Section with Diff & Apply Fix  */}
                {/* ========================================================= */}
                <div
                  style={{
                    marginTop: '12px',
                    background: 'rgba(16, 185, 129, 0.05)',
                    border: '1px solid rgba(16, 185, 129, 0.25)',
                    borderRadius: '8px',
                    padding: '12px 14px'
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      cursor: 'pointer',
                      userSelect: 'none'
                    }}
                    onClick={() => toggleRemediation(idx)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '1rem' }}>🛠️</span>
                      <span style={{ fontSize: '0.85rem', fontWeight: '700', color: '#34d399' }}>
                        Remediation Agent: {remediation?.title || 'Specific Fix Recommendation'}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {isRemediationOpen ? '▲ Collapse Fix' : '▼ Expand Fix'}
                    </span>
                  </div>

                  {isRemediationOpen && (
                    <div style={{ marginTop: '10px' }}>
                      {/* Step-by-step guidance */}
                      <p style={{ fontSize: '0.85rem', color: '#e2e8f0', lineHeight: '1.45' }}>
                        {remediation?.recommendation || finding.mitigation}
                      </p>

                      {/* Corrected Code Example Box with Diff Toggle & Apply Fix */}
                      {remediation?.corrected_code && (
                        <div style={{ marginTop: '10px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '6px' }}>
                            {/* View Switcher: Clean Code vs Unified Diff */}
                            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                              <span style={{ fontSize: '0.74rem', fontWeight: '600', color: '#34d399', textTransform: 'uppercase', letterSpacing: '0.04em', marginRight: '4px' }}>
                                View:
                              </span>
                              <button
                                type="button"
                                className={`btn ${!isDiffActive ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => setDiffViewIndex(prev => ({ ...prev, [idx]: false }))}
                                style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                              >
                                ✨ Clean Code
                              </button>
                              <button
                                type="button"
                                className={`btn ${isDiffActive ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => setDiffViewIndex(prev => ({ ...prev, [idx]: true }))}
                                style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                              >
                                🔄 Unified Diff
                              </button>
                            </div>

                            {/* Action Buttons: Copy Fix & Apply to Editor */}
                            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                              {onApplyFix && (
                                <button
                                  type="button"
                                  className="btn btn-secondary"
                                  onClick={() => handleApplyClick(finding, remediation.corrected_code, idx)}
                                  style={{
                                    padding: '3px 8px',
                                    fontSize: '0.72rem',
                                    background: isFixed ? 'rgba(34, 197, 94, 0.18)' : 'rgba(6, 182, 212, 0.15)',
                                    borderColor: isFixed ? 'rgba(34, 197, 94, 0.4)' : 'rgba(6, 182, 212, 0.35)',
                                    color: isFixed ? '#4ade80' : 'var(--accent-cyan)'
                                  }}
                                  title="Replace vulnerable line in active editor with this secure code"
                                >
                                  {isFixed ? '✅ Remediated' : appliedIndex === idx ? '⚡ Applied!' : '⚡ Apply to Editor'}
                                </button>
                              )}

                              <button
                                type="button"
                                className="btn btn-secondary"
                                onClick={() => handleCopyCode(remediation.corrected_code, idx)}
                                style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                              >
                                {copiedIndex === idx ? '✅ Copied!' : '📋 Copy Fix'}
                              </button>
                            </div>
                          </div>

                          {/* Clean Code View */}
                          {!isDiffActive ? (
                            <pre
                              style={{
                                background: '#090e1a',
                                padding: '10px 12px',
                                borderRadius: '6px',
                                fontSize: '0.8rem',
                                color: '#6ee7b7',
                                overflowX: 'auto',
                                border: '1px solid rgba(16, 185, 129, 0.2)',
                                fontFamily: 'var(--font-mono)'
                              }}
                            >
                              {remediation.corrected_code}
                            </pre>
                          ) : (
                            /* Unified Diff View (Milestone 3 Advanced Visual) */
                            <div
                              style={{
                                background: '#090e1a',
                                borderRadius: '6px',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                overflow: 'hidden',
                                fontSize: '0.78rem',
                                fontFamily: 'var(--font-mono)'
                              }}
                            >
                              {finding.evidence && (
                                <div style={{ padding: '8px 12px', background: 'rgba(239, 68, 68, 0.15)', color: '#fca5a5', borderBottom: '1px solid rgba(239, 68, 68, 0.25)', whiteSpace: 'pre-wrap' }}>
                                  <span style={{ userSelect: 'none', marginRight: '8px', color: '#f87171', fontWeight: '700' }}>- [Line {finding.line}]</span>
                                  {finding.evidence}
                                </div>
                              )}
                              <div style={{ padding: '8px 12px', background: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', whiteSpace: 'pre-wrap' }}>
                                <span style={{ userSelect: 'none', marginRight: '8px', color: '#34d399', fontWeight: '700' }}>+ [Remediated]</span>
                                {remediation.corrected_code}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Best practices checklist */}
                      {remediation?.best_practices && remediation.best_practices.length > 0 && (
                        <div style={{ marginTop: '10px', fontSize: '0.8rem' }}>
                          <span style={{ fontWeight: '600', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                            Key Best Practices:
                          </span>
                          <ul style={{ paddingLeft: '18px', marginTop: '4px', color: '#94a3b8' }}>
                            {remediation.best_practices.map((bp, bpIdx) => (
                              <li key={bpIdx} style={{ marginTop: '2px' }}>{bp}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Citations / References */}
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
            );
          })}
        </div>
      )}
    </div>
  );
}
