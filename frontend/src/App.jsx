import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { StatusBar } from './components/StatusBar';
import { EditorPanel } from './components/EditorPanel';
import { DiagnosticsPanel } from './components/DiagnosticsPanel';
import { FindingsPanel } from './components/FindingsPanel';
import { KnowledgeBasePanel } from './components/KnowledgeBasePanel';
import { AIModal } from './components/AIModal';
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
  const [notification, setNotification] = useState(null);

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
  const handleLanguageChange = (newLang) => {
    if (newLang === language) return;
    setLanguage(newLang);
    setValidationResult(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    setNotification(null);
    if (newLang === 'python') {
      const sample = SAMPLE_CODES.python_vulnerable;
      setSourceCode(sample.code);
      setFilename(sample.filename);
    } else {
      const sample = SAMPLE_CODES.java_vulnerable;
      setSourceCode(sample.code);
      setFilename(sample.filename);
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
    try {
      const data = await apiService.analyzeCode(lang, code, fname);
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
            summary={analysisResult?.summary || { total_findings: 0, critical: 0, high: 0, medium: 0, low: 0 }}
            hasScanned={Boolean(analysisResult)}
            isAnalyzing={isAnalyzing}
            onSelectForAI={(finding) => setSelectedFindingForAI(finding)}
          />
        </div>
      </main>

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
