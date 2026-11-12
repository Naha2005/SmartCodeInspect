import React, { useState } from 'react';
import { copyToClipboard } from '../utils/clipboard';

export function PRSummaryModal({
  prSummary,
  summary,
  filename,
  language,
  onClose,
  onOpenAssistant,
  onApplyFix
}) {
  const [copied, setCopied] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'fixes' | 'markdown'
  const [fixFilter, setFixFilter] = useState('all'); // 'all' | 'p0' | 'p1'
  const [copiedCodeIdx, setCopiedCodeIdx] = useState(null);
  const [appliedFixIdx, setAppliedFixIdx] = useState(null);
  const [checkedItems, setCheckedItems] = useState({});

  if (!prSummary) return null;

  const verdict = prSummary.verdict || {
    decision: 'NEEDS_WORK',
    label: '🟡 Review Needed',
    reason: 'Review findings before merging.'
  };

  const healthScore = prSummary.overall_health_score ?? 85;
  const qualityScore = prSummary.code_quality_score ?? 90;
  const securityPosture = prSummary.security_posture ?? 'A';
  const prioritized = prSummary.prioritized_fix_list || { p0_blockers: [], p1_important: [], p2_maintainability: [] };
  const checklist = prSummary.merge_checklist || [];

  const getMarkdownContent = () => {
    if (prSummary.markdown && prSummary.markdown.trim()) {
      return prSummary.markdown;
    }
    return [
      `# 📋 Pull Request Review Summary: ${filename || 'inspected_file'}`,
      `**Target File:** \`${filename || 'inspected_file'}\` (${language?.toUpperCase() || 'PYTHON'})`,
      `**Verdict:** ${verdict.label} — ${verdict.reason}`,
      `**Health Score:** ${healthScore}/100 | **Quality Score:** ${qualityScore}/100 | **Security Posture:** ${securityPosture}`,
      `**Total Findings:** ${prSummary.severity_breakdown?.total ?? summary?.total_findings ?? 0}`,
      '',
      '## 🚨 P0 - Merge Blockers',
      ...(prioritized.p0_blockers && prioritized.p0_blockers.length > 0
        ? prioritized.p0_blockers.map(b => `- **Line ${b.line} [${b.rule_id}]:** ${b.title}\n  *Fix:* ${b.recommendation}`)
        : ['- None detected.']),
      '',
      '## ⚡ P1 - Important Refactoring',
      ...(prioritized.p1_important && prioritized.p1_important.length > 0
        ? prioritized.p1_important.map(imp => `- **Line ${imp.line} [${imp.rule_id}]:** ${imp.title}\n  *Fix:* ${imp.recommendation}`)
        : ['- None detected.']),
      '',
      '## 📝 Merge Readiness Checklist',
      ...(checklist && checklist.length > 0
        ? checklist.map(item => `- [ ] ${item}`)
        : ['- [x] All automated checks pass'])
    ].join('\n');
  };

  const handleCopyMarkdown = async () => {
    const md = getMarkdownContent();
    const success = await copyToClipboard(md);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    }
  };

  const handleCopyCode = async (code, idx) => {
    if (!code) return;
    const success = await copyToClipboard(code);
    if (success) {
      setCopiedCodeIdx(idx);
      setTimeout(() => setCopiedCodeIdx(null), 2500);
    }
  };

  const handleDownloadMarkdown = () => {
    const md = getMarkdownContent();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const baseName = (filename || 'code_audit').replace(/\.[^/.]+$/, '');
    link.href = url;
    link.download = `${baseName}_PULL_REQUEST_REVIEW.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2500);
  };

  const completedCount = checklist.filter((_, idx) => !!checkedItems[idx]).length;
  const checklistProgress = checklist.length > 0 ? Math.round((completedCount / checklist.length) * 100) : 100;
  const isAllChecked = checklist.length > 0 && completedCount === checklist.length;

  const handleToggleChecklist = (idx) => {
    setCheckedItems((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const handleCheckAll = () => {
    const allChecked = {};
    checklist.forEach((_, idx) => {
      allChecked[idx] = true;
    });
    setCheckedItems(allChecked);
  };

  const handleClearAll = () => {
    setCheckedItems({});
  };

  const getVerdictStyle = (decision) => {
    switch (decision) {
      case 'APPROVED':
        return {
          background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.18), rgba(5, 150, 105, 0.1))',
          border: '1px solid rgba(16, 185, 129, 0.45)',
          color: '#34d399'
        };
      case 'CHANGES_REQUESTED':
        return {
          background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.18), rgba(185, 28, 28, 0.1))',
          border: '1px solid rgba(239, 68, 68, 0.45)',
          color: '#f87171'
        };
      default:
        return {
          background: 'linear-gradient(135deg, rgba(245, 158, 11, 0.18), rgba(180, 83, 9, 0.1))',
          border: '1px solid rgba(245, 158, 11, 0.45)',
          color: '#fbbf24'
        };
    }
  };

  const getHealthColor = (score) => {
    if (score >= 80) return '#34d399';
    if (score >= 60) return '#fbbf24';
    return '#f87171';
  };

  const formatSecurityPosture = (posture) => {
    if (!posture) {
      return { grade: 'A', label: 'Clean', color: '#34d399', badgeClass: 'badge-low', desc: 'No vulnerabilities detected' };
    }
    const clean = String(posture).trim();
    const grade = clean.charAt(0).toUpperCase();
    if (grade === 'A') {
      return { grade: 'A', label: 'Compliant', color: '#34d399', badgeClass: 'badge-low', desc: 'OWASP Top 10 Compliant' };
    }
    if (grade === 'B') {
      return { grade: 'B', label: 'Moderate', color: '#fbbf24', badgeClass: 'badge-medium', desc: 'Medium-severity findings' };
    }
    if (grade === 'C') {
      return { grade: 'C', label: 'High Risk', color: '#fb923c', badgeClass: 'badge-high', desc: 'High-severity findings' };
    }
    if (grade === 'D') {
      return { grade: 'D', label: 'Severe', color: '#f87171', badgeClass: 'badge-critical', desc: 'Multiple high-risk findings' };
    }
    if (grade === 'F') {
      return { grade: 'F', label: 'Critical Risk', color: '#f87171', badgeClass: 'badge-critical', desc: 'Blocker vulnerabilities found' };
    }
    return { grade: grade || '?', label: 'Audited', color: '#38bdf8', badgeClass: 'badge-info', desc: clean };
  };

  return (
    <div className="modal-backdrop" onClick={onClose} style={{ zIndex: 1200 }}>
      <div
        className="glass-panel modal-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '95%',
          maxWidth: '1060px',
          maxHeight: 'min(90vh, 880px)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}
      >
        {/* Header */}
        <div className="modal-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '1.45rem' }}>📋</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff', letterSpacing: '-0.01em' }}>
                Pull Request Code Review &amp; Audit Summary
              </h2>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Compiled by PR Summary Agent &bull; Target: <code>{filename || 'inspected_file'}</code> ({language?.toUpperCase()})
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleDownloadMarkdown}
              style={{ fontSize: '0.8rem', padding: '6px 14px' }}
              title="Download structured markdown report"
            >
              {downloaded ? '✅ Downloaded .md' : '📥 Download .md'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleCopyMarkdown}
              style={{ fontSize: '0.8rem', padding: '6px 14px' }}
            >
              {copied ? '✅ Copied to Clipboard!' : '📋 Copy PR Markdown'}
            </button>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                color: '#94a3b8',
                fontSize: '1.1rem',
                cursor: 'pointer',
                padding: '6px 12px',
                lineHeight: 1
              }}
              title="Close (Esc)"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="modal-body" style={{ gap: '18px' }}>
          {/* Verdict Banner */}
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              boxShadow: '0 4px 18px rgba(0, 0, 0, 0.25)',
              ...getVerdictStyle(verdict.decision)
            }}
          >
            <div style={{ flex: 1, paddingRight: '20px' }}>
              <div style={{ fontWeight: '800', fontSize: '1.05rem', letterSpacing: '0.02em', display: 'flex', alignItems: 'center', gap: '8px' }}>
                {verdict.label}
              </div>
              <div style={{ fontSize: '0.86rem', marginTop: '4px', opacity: 0.95, lineHeight: 1.45 }}>
                {verdict.reason}
              </div>
            </div>

            {/* Health Score Pill */}
            <div
              style={{
                textAlign: 'center',
                minWidth: '120px',
                padding: '8px 16px',
                borderRadius: '10px',
                background: 'rgba(0, 0, 0, 0.35)',
                border: '1px solid rgba(255, 255, 255, 0.08)'
              }}
            >
              <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94a3b8' }}>
                Health Score
              </div>
              <div style={{ fontSize: '1.6rem', fontWeight: '800', color: getHealthColor(healthScore), lineHeight: 1.1, marginTop: '2px' }}>
                {healthScore}<span style={{ fontSize: '0.85rem', opacity: 0.65 }}>/100</span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
            {[
              { id: 'overview', label: '📊 Executive Overview & Metrics' },
              { id: 'fixes', label: `🎯 Prioritized Fixes (${(prioritized.p0_blockers?.length || 0) + (prioritized.p1_important?.length || 0)})` },
              { id: 'markdown', label: '📝 GitHub PR Comment Markdown' }
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                className={`btn ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '7px 16px', fontSize: '0.82rem' }}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Executive Overview & Metrics */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Metric Cards Row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px' }}>
                <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '14px 16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Overall Health</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: getHealthColor(healthScore), marginTop: '4px' }}>
                    {healthScore}/100
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>Composite weighted audit</div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '14px 16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Quality Score</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#38bdf8', marginTop: '4px' }}>
                    {qualityScore}/100
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>Maintainability &amp; complexity</div>
                </div>

                <div
                  style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '14px 16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}
                  title={`Security Posture: ${securityPosture}`}
                >
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Security Posture
                  </div>
                  {(() => {
                    const postureInfo = formatSecurityPosture(securityPosture);
                    return (
                      <>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                          <span style={{ fontSize: '1.4rem', fontWeight: '800', color: postureInfo.color }}>
                            Grade {postureInfo.grade}
                          </span>
                          <span className={`badge ${postureInfo.badgeClass}`} style={{ fontSize: '0.7rem', padding: '2px 8px' }}>
                            {postureInfo.label}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {postureInfo.desc}
                        </div>
                      </>
                    );
                  })()}
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '14px 16px', borderRadius: '10px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Total Findings</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: '800', color: '#ffffff', marginTop: '4px' }}>
                    {prSummary.severity_breakdown?.total ?? summary?.total_findings ?? 0}
                  </div>
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                    {summary?.security_findings_count ?? 0} Sec &bull; {summary?.code_quality_findings_count ?? 0} Qual
                  </div>
                </div>
              </div>

              {/* 2-Column Section: Severity Breakdown (Left) & Merge Readiness Checklist (Right) */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '14px' }}>
                {/* Severity Breakdown */}
                <div style={{ background: 'rgba(0, 0, 0, 0.3)', borderRadius: '10px', padding: '16px 18px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column' }}>
                  <h4 style={{ fontSize: '0.92rem', fontWeight: '700', color: '#ffffff', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    🛡️ Severity Breakdown
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', flex: 1 }}>
                    <div
                      onClick={() => { setActiveTab('fixes'); setFixFilter('p0'); }}
                      style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', cursor: 'pointer', transition: 'all 0.2s ease' }}
                      title="Click to view P0 Blockers in Prioritized Fixes"
                    >
                      <div style={{ fontSize: '0.72rem', color: '#f87171', fontWeight: '700', textTransform: 'uppercase' }}>CRITICAL (Blockers)</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: '800', color: '#f87171', marginTop: '2px' }}>
                        {prSummary.severity_breakdown?.critical || 0}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#fca5a5', opacity: 0.8 }}>Must fix before merge &rarr;</div>
                    </div>

                    <div
                      onClick={() => { setActiveTab('fixes'); setFixFilter('p0'); }}
                      style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(249, 115, 22, 0.1)', border: '1px solid rgba(249, 115, 22, 0.3)', cursor: 'pointer', transition: 'all 0.2s ease' }}
                      title="Click to view High severity findings"
                    >
                      <div style={{ fontSize: '0.72rem', color: '#fb923c', fontWeight: '700', textTransform: 'uppercase' }}>HIGH (Required)</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: '800', color: '#fb923c', marginTop: '2px' }}>
                        {prSummary.severity_breakdown?.high || 0}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#fed7aa', opacity: 0.8 }}>High security risk &rarr;</div>
                    </div>

                    <div
                      onClick={() => { setActiveTab('fixes'); setFixFilter('p1'); }}
                      style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', cursor: 'pointer', transition: 'all 0.2s ease' }}
                      title="Click to view Medium issues in Prioritized Fixes"
                    >
                      <div style={{ fontSize: '0.72rem', color: '#fbbf24', fontWeight: '700', textTransform: 'uppercase' }}>MEDIUM (Recommended)</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: '800', color: '#fbbf24', marginTop: '2px' }}>
                        {prSummary.severity_breakdown?.medium || 0}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#fde68a', opacity: 0.8 }}>Refactoring advised &rarr;</div>
                    </div>

                    <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
                      <div style={{ fontSize: '0.72rem', color: '#60a5fa', fontWeight: '700', textTransform: 'uppercase' }}>LOW / INFO (Hygiene)</div>
                      <div style={{ fontSize: '1.35rem', fontWeight: '800', color: '#60a5fa', marginTop: '2px' }}>
                        {(prSummary.severity_breakdown?.low || 0) + (prSummary.severity_breakdown?.informational || 0)}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#bfdbfe', opacity: 0.8 }}>Code quality &amp; style</div>
                    </div>
                  </div>
                </div>

                {/* Merge Readiness Checklist */}
                <div style={{ background: 'rgba(0, 0, 0, 0.3)', borderRadius: '10px', padding: '16px 18px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <h4 style={{ fontSize: '0.92rem', fontWeight: '700', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      📝 Merge Readiness Checklist
                    </h4>
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.74rem', color: checklistProgress === 100 ? '#34d399' : 'var(--accent-cyan)', fontWeight: '700' }}>
                        {completedCount}/{checklist.length} ({checklistProgress}%)
                      </span>
                      {checklist.length > 0 && (
                        <button
                          type="button"
                          onClick={isAllChecked ? handleClearAll : handleCheckAll}
                          style={{
                            background: 'transparent',
                            border: '1px solid rgba(255, 255, 255, 0.15)',
                            borderRadius: '4px',
                            color: '#94a3b8',
                            fontSize: '0.7rem',
                            padding: '1px 6px',
                            cursor: 'pointer'
                          }}
                        >
                          {isAllChecked ? 'Clear' : 'Check All'}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div style={{ height: '6px', width: '100%', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '3px', overflow: 'hidden', marginBottom: '10px' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${checklistProgress}%`,
                        background: checklistProgress === 100 ? '#10b981' : 'linear-gradient(90deg, #06b6d4, #10b981)',
                        transition: 'width 0.3s ease'
                      }}
                    />
                  </div>

                  {isAllChecked && checklist.length > 0 && (
                    <div style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', borderRadius: '6px', padding: '6px 10px', color: '#34d399', fontSize: '0.76rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span>🎉</span> <span><strong>Ready for merge!</strong> All action items have been marked resolved.</span>
                    </div>
                  )}

                  {checklist.length === 0 ? (
                    <div style={{ padding: '16px', textAlign: 'center', color: '#34d399', fontSize: '0.86rem' }}>
                      ✅ All automated checks passed! No outstanding blockers for this pull request.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1, overflowY: 'auto', maxHeight: '180px', paddingRight: '4px' }}>
                      {checklist.map((item, idx) => (
                        <label
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '10px',
                            fontSize: '0.83rem',
                            color: checkedItems[idx] ? '#94a3b8' : '#e2e8f0',
                            textDecoration: checkedItems[idx] ? 'line-through' : 'none',
                            background: checkedItems[idx] ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255, 255, 255, 0.03)',
                            padding: '8px 12px',
                            borderRadius: '6px',
                            border: checkedItems[idx] ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(255, 255, 255, 0.05)',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={!!checkedItems[idx]}
                            onChange={() => handleToggleChecklist(idx)}
                            style={{ accentColor: '#10b981', marginTop: '2px', cursor: 'pointer' }}
                          />
                          <span style={{ lineHeight: 1.4 }}>{item}</span>
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Prioritized Fixes */}
          {activeTab === 'fixes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Fix Filter Tabs */}
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: '600', marginRight: '4px' }}>Filter:</span>
                <button
                  type="button"
                  className={`btn ${fixFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '0.76rem', padding: '4px 12px' }}
                  onClick={() => setFixFilter('all')}
                >
                  All ({(prioritized.p0_blockers?.length || 0) + (prioritized.p1_important?.length || 0)})
                </button>
                <button
                  type="button"
                  className={`btn ${fixFilter === 'p0' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '0.76rem', padding: '4px 12px' }}
                  onClick={() => setFixFilter('p0')}
                >
                  🚨 P0 Blockers ({prioritized.p0_blockers?.length || 0})
                </button>
                <button
                  type="button"
                  className={`btn ${fixFilter === 'p1' ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '0.76rem', padding: '4px 12px' }}
                  onClick={() => setFixFilter('p1')}
                >
                  ⚡ P1 Important ({prioritized.p1_important?.length || 0})
                </button>
              </div>

              {/* P0 Blockers */}
              {(fixFilter === 'all' || fixFilter === 'p0') && (
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#f87171', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    🚨 P0 - Merge Blockers ({prioritized.p0_blockers?.length || 0})
                  </h4>
                  {prioritized.p0_blockers?.length === 0 ? (
                    <p style={{ fontSize: '0.84rem', color: '#34d399', marginTop: '6px', background: 'rgba(16, 185, 129, 0.1)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                      ✅ No P0 blockers detected. Code is free of critical and high vulnerabilities.
                    </p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '8px' }}>
                      {prioritized.p0_blockers.map((b, idx) => (
                        <div key={idx} style={{ background: 'rgba(239, 68, 68, 0.08)', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '14px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                            <span style={{ fontWeight: '700', color: '#fca5a5', fontSize: '0.88rem' }}>
                              Line {b.line}: {b.title}
                            </span>
                            <span className="badge badge-critical">{b.rule_id}</span>
                          </div>
                          <p style={{ fontSize: '0.84rem', color: '#e2e8f0', marginTop: '6px', lineHeight: 1.45 }}>
                            <strong>Fix Recommendation:</strong> {b.recommendation}
                          </p>
                          {b.corrected_code && (
                            <div style={{ marginTop: '10px', position: 'relative' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#070b14', padding: '6px 12px', borderTopLeftRadius: '6px', borderTopRightRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.08)', borderBottom: 'none' }}>
                                <span style={{ fontSize: '0.72rem', color: '#34d399', fontWeight: '600' }}>🛠️ Suggested Code Fix</span>
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                  {onApplyFix && (
                                    <button
                                      type="button"
                                      onClick={() => {
                                        onApplyFix(b, b.corrected_code);
                                        setAppliedFixIdx(`p0-${idx}`);
                                        setTimeout(() => setAppliedFixIdx(null), 2500);
                                      }}
                                      style={{
                                        background: 'rgba(6, 182, 212, 0.15)',
                                        border: '1px solid rgba(6, 182, 212, 0.4)',
                                        color: 'var(--accent-cyan)',
                                        cursor: 'pointer',
                                        fontSize: '0.72rem',
                                        borderRadius: '4px',
                                        padding: '2px 8px',
                                        fontWeight: '600'
                                      }}
                                    >
                                      {appliedFixIdx === `p0-${idx}` ? '⚡ Applied!' : '⚡ Apply to Editor'}
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    onClick={() => handleCopyCode(b.corrected_code, `p0-${idx}`)}
                                    style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.72rem' }}
                                  >
                                    {copiedCodeIdx === `p0-${idx}` ? '✅ Copied' : '📋 Copy Fix'}
                                  </button>
                                </div>
                              </div>
                              <pre style={{ margin: 0, background: '#090e1a', padding: '10px 12px', borderBottomLeftRadius: '6px', borderBottomRightRadius: '6px', fontSize: '0.8rem', color: '#34d399', overflowX: 'auto', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                                {b.corrected_code}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* P1 Important */}
              {(fixFilter === 'all' || fixFilter === 'p1') && (
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    ⚡ P1 - Important Refactoring &amp; Hardening ({prioritized.p1_important?.length || 0})
                  </h4>
                  {prioritized.p1_important?.length === 0 ? (
                    <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      ✅ No P1 issues detected.
                    </p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                      {prioritized.p1_important.map((imp, idx) => (
                        <div key={idx} style={{ background: 'rgba(245, 158, 11, 0.08)', borderRadius: '8px', border: '1px solid rgba(245, 158, 11, 0.25)', padding: '12px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: '600', color: '#fde68a', fontSize: '0.85rem' }}>
                              Line {imp.line}: {imp.title}
                            </span>
                            <span className="badge badge-medium">{imp.rule_id}</span>
                          </div>
                          <p style={{ fontSize: '0.82rem', color: '#cbd5e1', marginTop: '4px', lineHeight: 1.45 }}>
                            {imp.recommendation}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Tab 3: GitHub PR Comment Markdown */}
          {activeTab === 'markdown' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  Rendered GitHub PR comment format. Copy and paste directly into pull requests or CI comments:
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleCopyMarkdown}
                  style={{ fontSize: '0.78rem', padding: '5px 12px' }}
                >
                  {copied ? '✅ Copied!' : '📋 Copy Markdown'}
                </button>
              </div>
              <pre
                style={{
                  background: '#090e1a',
                  padding: '16px',
                  borderRadius: '10px',
                  fontSize: '0.82rem',
                  color: '#cbd5e1',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  border: '1px solid var(--border-subtle)',
                  fontFamily: 'var(--font-mono)',
                  lineHeight: '1.5',
                  maxHeight: '380px'
                }}
              >
                {prSummary.markdown || getMarkdownContent()}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Enclosed Footer */}
        <div className="modal-footer">
          {onOpenAssistant && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                onClose();
                onOpenAssistant(null);
              }}
              style={{ fontSize: '0.82rem', padding: '7px 14px', background: 'rgba(6, 182, 212, 0.1)', borderColor: 'rgba(6, 182, 212, 0.3)', color: 'var(--accent-cyan)' }}
            >
              🤖 Remediate with AI Assistant
            </button>
          )}
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            style={{ fontSize: '0.82rem', padding: '7px 16px' }}
          >
            Close
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleDownloadMarkdown}
            style={{ fontSize: '0.82rem', padding: '7px 16px' }}
            title="Download structured markdown report"
          >
            {downloaded ? '✅ Downloaded .md' : '📥 Download .md'}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleCopyMarkdown}
            style={{ fontSize: '0.82rem', padding: '7px 16px' }}
          >
            {copied ? '✅ Markdown Copied' : '📋 Copy PR Markdown'}
          </button>
        </div>
      </div>
    </div>
  );
}
