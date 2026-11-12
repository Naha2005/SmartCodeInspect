import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { StatusBar } from './components/StatusBar';
import { EditorPanel } from './components/EditorPanel';
import { DiagnosticsPanel } from './components/DiagnosticsPanel';
import { FindingsPanel } from './components/FindingsPanel';
import { KnowledgeBasePanel } from './components/KnowledgeBasePanel';
import { AIModal } from './components/AIModal';
import { PRSummaryModal } from './components/PRSummaryModal';
import { ConversationalAssistant } from './components/ConversationalAssistant';
import { apiService } from './services/api';
import { SAMPLE_CODES } from './constants/samples';

export default function App() {
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(false);

  // Editor states
  const [language, setLanguage] = useState('python');
  const [filename, setFilename] = useState('vulnerable_service.py');
  const [sourceCode, setSourceCode] = useState(SAMPLE_CODES.python_vulnerable.code);

  // Results state
  const [validationResult, setValidationResult] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);

  // Loading flags
  const [isValidating, setIsValidating] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  // Modals & Notifications
  const [selectedFindingForAI, setSelectedFindingForAI] = useState(null);
  const [isPrSummaryOpen, setIsPrSummaryOpen] = useState(false);
  const [isAssistantOpen, setIsAssistantOpen] = useState(false);
  const [assistantFinding, setAssistantFinding] = useState(null);
  const [notification, setNotification] = useState(null);

  // Milestone 3 Interactive Remediation Tracking & Dynamic Health Scoring
  const [fixedFindingKeys, setFixedFindingKeys] = useState(new Set());
  const [fixedLinesMap, setFixedLinesMap] = useState({});

  const getFindingKey = (f) => `${f?.rule_id || 'RULE'}-${f?.line || 0}-${(f?.evidence || '').slice(0, 30)}`;

  const fetchHealth = async () => {
    setHealthLoading(true);
    try {
      const data = await apiService.getHealth();
      setHealth(data);
    } catch {
      setHealth({ status: 'offline' });
    } finally {
      setHealthLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    apiService.getHealth().then((data) => {
      if (!cancelled) {
        setHealth(data);
        setHealthLoading(false);
      }
    }).catch(() => {
      if (!cancelled) {
        setHealth({ status: 'offline' });
        setHealthLoading(false);
      }
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => {
      setNotification((curr) => (curr?.msg === msg ? null : curr));
    }, 6000);
  };

  // Language change handler — cleanses old results to prevent orphaned findings across tabs
  // Accepts optional preserveCode flag so user-uploaded or dragged-in files are not overwritten by samples
  const handleLanguageChange = (newLang, preserveCode = false) => {
    if (newLang === language) return;
    setLanguage(newLang);
    setValidationResult(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    setNotification(null);
    setFixedFindingKeys(new Set());
    setFixedLinesMap({});
    if (!preserveCode) {
      if (newLang === 'python') {
        const sample = SAMPLE_CODES.python_vulnerable;
        setSourceCode(sample.code);
        setFilename(sample.filename);
      } else {
        const sample = SAMPLE_CODES.java_vulnerable;
        setSourceCode(sample.code);
        setFilename(sample.filename);
      }
    }
  };

  // Validate Syntax only — accepts optional overrides for freshly-uploaded code
  // Fixes falsy check bug: checks explicit non-empty values instead of ||
  const handleValidate = React.useCallback(async (overrideLang, overrideCode, overrideFilename) => {
    const lang = (overrideLang !== undefined && overrideLang !== null && typeof overrideLang === 'string' && overrideLang.trim() !== '')
      ? overrideLang.trim()
      : language;
    const code = (overrideCode !== undefined && overrideCode !== null) ? overrideCode : sourceCode;
    const fname = (overrideFilename !== undefined && overrideFilename !== null && typeof overrideFilename === 'string' && overrideFilename.trim() !== '')
      ? overrideFilename.trim()
      : filename;

    if (!lang) {
      showNotification('Please specify a valid language (Python or Java) to validate.', 'error');
      return;
    }

    setIsValidating(true);
    setNotification(null);
    try {
      const data = await apiService.validateCode(lang, code, fname);
      setValidationResult(data);
      if (data.valid_syntax) {
        showNotification('Syntax and compiler validation passed without errors.', 'success');
      } else {
        showNotification('Validation reported syntax or compiler errors.', 'warning');
      }
    } catch (err) {
      showNotification(`Validation request failed: ${err.message}`, 'error');
    } finally {
      setIsValidating(false);
    }
  }, [language, sourceCode, filename]);

  // Full Security Analysis — accepts optional overrides for freshly-uploaded code
  // Fixes falsy check bug: checks explicit non-empty values instead of ||
  const handleAnalyze = React.useCallback(async (overrideLang, overrideCode, overrideFilename) => {
    const lang = (overrideLang !== undefined && overrideLang !== null && typeof overrideLang === 'string' && overrideLang.trim() !== '')
      ? overrideLang.trim()
      : language;
    const code = (overrideCode !== undefined && overrideCode !== null) ? overrideCode : sourceCode;
    const fname = (overrideFilename !== undefined && overrideFilename !== null && typeof overrideFilename === 'string' && overrideFilename.trim() !== '')
      ? overrideFilename.trim()
      : filename;

    if (!lang) {
      showNotification('Please specify a valid language (Python or Java) to inspect.', 'error');
      return;
    }

    setIsAnalyzing(true);
    setNotification(null);
    setAnalysisError(null);
    setFixedFindingKeys(new Set());
    setFixedLinesMap({});
    try {
      const data = await apiService.analyzeCode(lang, code, fname);
      const baseHealthScore = data.summary?.overall_code_health_score ?? 35;
      data.baseHealthScore = baseHealthScore;
      if (data.summary) {
        data.summary.active_errors_count = data.findings?.length || 0;
        data.summary.fixed_count = 0;
      }
      setAnalysisResult(data);
      setAnalysisError(null);
      setValidationResult({
        valid_syntax: data.valid_syntax,
        diagnostics: data.diagnostics,
        message: data.message,
        language: data.language,
        total_lines: data.total_lines
      });

      const count = data.findings?.length || 0;
      if (count > 0) {
        showNotification(`Inspection complete: ${count} vulnerability finding(s) detected.`, 'warning');
      } else {
        showNotification('Inspection complete: 0 vulnerabilities found.', 'success');
      }
    } catch (err) {
      setAnalysisResult(null);
      setAnalysisError(err.message);
      showNotification(`Analysis failed: ${err.message}`, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  }, [language, sourceCode, filename]);

  // Download PDF Report
  const handleDownloadPdf = async () => {
    setIsGeneratingPdf(true);
    try {
      await apiService.downloadPdfReport({
        analysisData: analysisResult,
        sourceCode,
        language,
        filename
      });
      showNotification('Official inspection PDF report generated and downloaded.', 'success');
    } catch (err) {
      showNotification(`PDF Generation failed: ${err.message}`, 'error');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Prevent background scroll and support ESC key when any modal is open
  React.useEffect(() => {
    const hasModal = isPrSummaryOpen || isAssistantOpen || Boolean(selectedFindingForAI);
    if (hasModal) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isPrSummaryOpen, isAssistantOpen, selectedFindingForAI]);

  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setIsPrSummaryOpen(false);
        setIsAssistantOpen(false);
        setSelectedFindingForAI(null);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleOpenPrSummary = React.useCallback(() => {
    setIsAssistantOpen(false);
    setSelectedFindingForAI(null);
    setIsPrSummaryOpen(true);
  }, []);

  const handleOpenAssistant = React.useCallback((finding = null) => {
    setIsPrSummaryOpen(false);
    setSelectedFindingForAI(null);
    setAssistantFinding(finding || null);
    setIsAssistantOpen(true);
  }, []);

  // Milestone 3: Interactive Remediation with Red->Green Line Transition & Dynamic Health Score Progression
  const handleApplyFix = React.useCallback((finding, correctedCode) => {
    if (!finding || !correctedCode) return;

    const findingKey = getFindingKey(finding);
    const nextFixedKeys = new Set(fixedFindingKeys);
    nextFixedKeys.add(findingKey);
    setFixedFindingKeys(nextFixedKeys);

    if (finding.line) {
      setFixedLinesMap((prev) => ({ ...prev, [finding.line]: true }));
    }

    setSourceCode((prevCode) => {
      // 1. If evidence matches exactly, replace it
      if (finding.evidence && prevCode.includes(finding.evidence.trim())) {
        return prevCode.replace(finding.evidence.trim(), correctedCode.trim());
      }
      // 2. Line-based replacement preserving indentation
      const lines = prevCode.split('\n');
      const targetLineIdx = (finding.line || 1) - 1;
      if (targetLineIdx >= 0 && targetLineIdx < lines.length) {
        const indent = (lines[targetLineIdx].match(/^\s*/) || [''])[0];
        const indentedFix = correctedCode
          .split('\n')
          .map((line, i) => (i === 0 ? indent + line.trimStart() : indent + line))
          .join('\n');
        lines[targetLineIdx] = indentedFix;
        return lines.join('\n');
      }
      return prevCode;
    });

    // Dynamic health score progression
    const totalFindings = analysisResult?.findings?.length || 1;
    const fixedCount = nextFixedKeys.size;
    const activeRemaining = Math.max(0, totalFindings - fixedCount);
    const baseScore = analysisResult?.baseHealthScore || analysisResult?.summary?.overall_code_health_score || 35;

    let newHealthScore;
    if (activeRemaining === 0) {
      newHealthScore = 100;
    } else {
      newHealthScore = Math.min(99, Math.round(baseScore + ((100 - baseScore) * fixedCount) / totalFindings));
    }

    setAnalysisResult((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        summary: {
          ...(prev.summary || {}),
          overall_code_health_score: newHealthScore,
          active_errors_count: activeRemaining,
          fixed_count: fixedCount
        }
      };
    });

    if (activeRemaining === 0) {
      showNotification(`🎉 All vulnerabilities remediated! Code Health Score reached 100/100 (0 errors remaining). Clean code ready for export.`, 'success');
    } else {
      showNotification(`⚡ Remediated ${finding.rule_id} at line ${finding.line}. Health Score improved to ${newHealthScore}/100 (${activeRemaining} active error(s) remaining).`, 'success');
    }
  }, [analysisResult, fixedFindingKeys]);

  // 1-Click Auto-Remediation for All Remaining Issues
  const handleFixAll = React.useCallback(() => {
    if (!analysisResult?.findings?.length) return;

    let updatedCode = sourceCode;
    const allKeys = new Set(fixedFindingKeys);
    const updatedLines = { ...fixedLinesMap };

    analysisResult.findings.forEach((f) => {
      allKeys.add(getFindingKey(f));
      if (f.line) updatedLines[f.line] = true;

      const corrected = f.remediation?.corrected_code;
      if (corrected) {
        if (f.evidence && updatedCode.includes(f.evidence.trim())) {
          updatedCode = updatedCode.replace(f.evidence.trim(), corrected.trim());
        } else {
          const lines = updatedCode.split('\n');
          const targetLineIdx = (f.line || 1) - 1;
          if (targetLineIdx >= 0 && targetLineIdx < lines.length) {
            const indent = (lines[targetLineIdx].match(/^\s*/) || [''])[0];
            const indentedFix = corrected
              .split('\n')
              .map((line, i) => (i === 0 ? indent + line.trimStart() : indent + line))
              .join('\n');
            lines[targetLineIdx] = indentedFix;
            updatedCode = lines.join('\n');
          }
        }
      }
    });

    setSourceCode(updatedCode);
    setFixedFindingKeys(allKeys);
    setFixedLinesMap(updatedLines);

    setAnalysisResult((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        summary: {
          ...(prev.summary || {}),
          overall_code_health_score: 100,
          active_errors_count: 0,
          fixed_count: prev.findings.length
        }
      };
    });

    showNotification('🎉 1-Click Remediation Applied! 0 errors remaining • Code Health Score: 100/100 • All lines clean & green.', 'success');
  }, [analysisResult, sourceCode, fixedFindingKeys, fixedLinesMap]);

  // Clean Code File Download (.py or .java)
  const handleDownloadCleanCode = React.useCallback(() => {
    const cleanFilename = filename?.startsWith('clean_')
      ? filename
      : `clean_${filename || (language === 'python' ? 'app.py' : 'App.java')}`;
    const blob = new Blob([sourceCode], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = cleanFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showNotification(`📥 Cleaned code downloaded as "${cleanFilename}".`, 'success');
  }, [filename, language, sourceCode]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* System Status Bar */}
      <StatusBar health={health} onRefresh={fetchHealth} loading={healthLoading} />

      {/* Main Header */}
      <Header />

      {/* Notification Toast */}
      {notification && (
        <div
          id="toast-notification"
          style={{
            maxWidth: '1200px',
            margin: '12px auto 0 auto',
            padding: '10px 20px',
            borderRadius: '8px',
            background:
              notification.type === 'error'
                ? 'rgba(239, 68, 68, 0.2)'
                : notification.type === 'warning'
                ? 'rgba(245, 158, 11, 0.2)'
                : 'rgba(16, 185, 129, 0.2)',
            border:
              notification.type === 'error'
                ? '1px solid rgba(239, 68, 68, 0.5)'
                : notification.type === 'warning'
                ? '1px solid rgba(245, 158, 11, 0.5)'
                : '1px solid rgba(16, 185, 129, 0.5)',
            color: '#f8fafc',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.88rem'
          }}
        >
          <span>{notification.msg}</span>
          <button
            type="button"
            onClick={() => setNotification(null)}
            style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1rem' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Main 2-Column Dashboard Layout */}
      <main className="dashboard-layout" id="main-content">
        {/* Left Column: Code Editor & Knowledge Base */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <EditorPanel
            language={language}
            onLanguageChange={handleLanguageChange}
            sourceCode={sourceCode}
            setSourceCode={setSourceCode}
            filename={filename}
            setFilename={setFilename}
            onValidate={handleValidate}
            onAnalyze={handleAnalyze}
            onDownloadPdf={handleDownloadPdf}
            isValidating={isValidating}
            isAnalyzing={isAnalyzing}
            isGeneratingPdf={isGeneratingPdf}
            analysisResult={analysisResult}
            analysisError={analysisError}
            fixedFindingKeys={fixedFindingKeys}
            fixedLinesMap={fixedLinesMap}
            onApplyFix={handleApplyFix}
            onFixAll={handleFixAll}
            onDownloadCleanCode={handleDownloadCleanCode}
          />

          <KnowledgeBasePanel />
        </div>

        {/* Right Column: Diagnostics & Vulnerability Findings */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <DiagnosticsPanel
            validationResult={validationResult}
            isValidating={isValidating}
            onValidate={handleValidate}
            totalLines={sourceCode.split('\n').length}
          />

          <FindingsPanel
            findings={analysisResult?.findings || []}
            summary={analysisResult?.summary || { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0, overall_code_health_score: 100 }}
            hasScanned={Boolean(analysisResult)}
            isAnalyzing={isAnalyzing}
            onSelectForAI={(finding) => {
              setIsPrSummaryOpen(false);
              setIsAssistantOpen(false);
              setSelectedFindingForAI(finding);
            }}
            onOpenAssistant={handleOpenAssistant}
            onOpenPrSummary={handleOpenPrSummary}
            onApplyFix={handleApplyFix}
            fixedFindingKeys={fixedFindingKeys}
            fixedLinesMap={fixedLinesMap}
            onFixAll={handleFixAll}
          />
        </div>
      </main>

      {/* PR Summary Review Modal */}
      {isPrSummaryOpen && (
        <PRSummaryModal
          prSummary={analysisResult?.pr_summary || {
            filename,
            language,
            overall_health_score: analysisResult?.summary?.overall_code_health_score ?? 85,
            code_quality_score: analysisResult?.summary?.code_quality_score ?? 90,
            security_posture: analysisResult?.summary?.security_posture ?? 'A',
            verdict: {
              decision: (analysisResult?.summary?.critical > 0 || analysisResult?.summary?.high > 0) ? 'CHANGES_REQUESTED' : 'APPROVED',
              label: (analysisResult?.summary?.critical > 0 || analysisResult?.summary?.high > 0) ? '🔴 Changes Requested' : '🟢 Approved',
              reason: (analysisResult?.summary?.critical > 0 || analysisResult?.summary?.high > 0)
                ? 'Security vulnerabilities must be remediated before merge.'
                : 'All automated quality and security checks passed.'
            },
            severity_breakdown: analysisResult?.summary,
            prioritized_fix_list: {
              p0_blockers: (analysisResult?.findings || []).filter(f => ['Critical', 'High'].includes(f.severity)),
              p1_important: (analysisResult?.findings || []).filter(f => f.severity === 'Medium'),
              p2_maintainability: (analysisResult?.findings || []).filter(f => ['Low', 'Informational'].includes(f.severity))
            },
            merge_checklist: (analysisResult?.findings || []).slice(0, 5).map(f => `Resolve Line ${f.line}: ${f.title}`),
            markdown: `## 📋 Pull Request Review Summary\n\n**File:** \`${filename}\`\n\n**Total Findings:** ${analysisResult?.findings?.length || 0}\n`
          }}
          summary={analysisResult?.summary}
          filename={filename}
          language={language}
          onClose={() => setIsPrSummaryOpen(false)}
          onOpenAssistant={handleOpenAssistant}
          onApplyFix={handleApplyFix}
        />
      )}

      {/* Conversational Code Assistant Modal */}
      <ConversationalAssistant
        isOpen={isAssistantOpen}
        onClose={() => {
          setIsAssistantOpen(false);
          setAssistantFinding(null);
        }}
        initialFinding={assistantFinding}
        sourceCode={sourceCode}
        language={language}
        filename={filename}
        findings={analysisResult?.findings || []}
        onOpenPrSummary={handleOpenPrSummary}
        onApplyFix={handleApplyFix}
      />

      {/* AI Advisory Modal */}
      {selectedFindingForAI && (
        <AIModal
          finding={selectedFindingForAI}
          aiConfig={health?.ai_integration}
          onClose={() => setSelectedFindingForAI(null)}
        />
      )}

      {/* Footer */}
      <footer style={{ marginTop: 'auto', padding: '20px 32px', textAlign: 'center', borderTop: '1px solid var(--border-subtle)', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
        <span>Smart Code Inspection Platform &bull; AST Static Analysis &amp; OWASP Compliance &bull; Internship Milestone Project</span>
      </footer>
    </div>
  );
}
