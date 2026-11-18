import React, { useRef, useState, useEffect } from 'react';
import { SAMPLE_CODES } from '../constants/samples';
import { copyToClipboard } from '../utils/clipboard';

export function EditorPanel({
  language,
  setLanguage,
  onLanguageChange,
  sourceCode,
  setSourceCode,
  filename,
  setFilename,
  onValidate,
  onAnalyze,
  onDownloadPdf,
  isValidating,
  isAnalyzing,
  isGeneratingPdf,
  analysisResult,
  analysisError,
  validationResult,
  fixedFindingKeys = new Set(),
  fixedLinesMap = {},
  onApplyFix,
  onFixAll,
  onDownloadCleanCode,
  fixedSyntaxDiagnosticKeys = new Set(),
  fixedSyntaxLinesMap = {},
  onFixDiagnostic
}) {
  const fileInputRef = useRef(null);
  const dragCounter = useRef(0);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadInfo, setUploadInfo] = useState(null);
  const [showUploadedContent, setShowUploadedContent] = useState(true);
  const [copiedContent, setCopiedContent] = useState(false);
  const [viewMode, setViewMode] = useState('inspector');
  const [copiedWholeCode, setCopiedWholeCode] = useState(false);
  const [selectedSampleKey, setSelectedSampleKey] = useState(
    language === 'python' ? 'python_vulnerable' : 'java_vulnerable'
  );

  // Synchronize sample dropdown with active language and code
  useEffect(() => {
    if (language === 'python') {
      if (sourceCode === SAMPLE_CODES.python_valid.code) setSelectedSampleKey('python_valid');
      else if (sourceCode === SAMPLE_CODES.python_moderate?.code) setSelectedSampleKey('python_moderate');
      else if (sourceCode === SAMPLE_CODES.python_vulnerable.code) setSelectedSampleKey('python_vulnerable');
      else setSelectedSampleKey('');
    } else if (language === 'java') {
      if (sourceCode === SAMPLE_CODES.java_valid.code) setSelectedSampleKey('java_valid');
      else if (sourceCode === SAMPLE_CODES.java_moderate?.code) setSelectedSampleKey('java_moderate');
      else if (sourceCode === SAMPLE_CODES.java_vulnerable.code) setSelectedSampleKey('java_vulnerable');
      else setSelectedSampleKey('');
    }
  }, [language, sourceCode]);

  // Global window dragover/drop prevention to prevent browser navigating away on accidental outside drops
  useEffect(() => {
    const preventDefaults = (e) => {
      e.preventDefault();
    };
    window.addEventListener('dragover', preventDefaults, false);
    window.addEventListener('drop', preventDefaults, false);
    return () => {
      window.removeEventListener('dragover', preventDefaults, false);
      window.removeEventListener('drop', preventDefaults, false);
    };
  }, []);

  // Maintain fresh onAnalyze closure using ref pattern to eliminate race conditions
  const onAnalyzeRef = useRef(onAnalyze);
  useEffect(() => {
    onAnalyzeRef.current = onAnalyze;
  }, [onAnalyze]);

  const handleLanguageChange = (newLang) => {
    if (onLanguageChange) {
      onLanguageChange(newLang, false);
    }
    if (setLanguage) {
      setLanguage(newLang);
    }
    setUploadInfo(null);
    if (newLang === 'python') {
      setSelectedSampleKey('python_vulnerable');
      setFilename(SAMPLE_CODES.python_vulnerable.filename);
      setSourceCode(SAMPLE_CODES.python_vulnerable.code);
    } else {
      setSelectedSampleKey('java_vulnerable');
      setFilename(SAMPLE_CODES.java_vulnerable.filename);
      setSourceCode(SAMPLE_CODES.java_vulnerable.code);
    }
  };

  const handleSampleSelect = (e) => {
    const key = e.target.value;
    setSelectedSampleKey(key);
    if (!key || !SAMPLE_CODES[key]) return;
    const sample = SAMPLE_CODES[key];
    if (sample.language !== language) {
      if (onLanguageChange) {
        onLanguageChange(sample.language, true);
      }
      if (setLanguage) {
        setLanguage(sample.language);
      }
    }
    setFilename(sample.filename);
    setSourceCode(sample.code);
    setUploadInfo(null);
  };

  const handleTextareaChange = (e) => {
    const newCode = e.target.value;
    setSourceCode(newCode);

    // Smart auto-detection on paste or typing
    if (newCode.trim().length > 15) {
      const isJavaSnippet = /\b(public\s+(?:class|interface|enum|record)|import\s+java\.|System\.out\.print|package\s+[a-z0-9_.]+;)\b/.test(newCode);
      const isPythonSnippet = /\b(def\s+[a-zA-Z_]\w*\s*\(|import\s+os\b|import\s+sys\b|if\s+__name__\s*==|elif\s+|from\s+[a-zA-Z_]\w*\s+import)\b/.test(newCode);

      if (isJavaSnippet && !isPythonSnippet && language !== 'java') {
        if (onLanguageChange) onLanguageChange('java', true);
        if (setLanguage) setLanguage('java');
        if (!filename || filename.endsWith('.py')) {
          setFilename('LegacyPortalService.java');
        }
      } else if (isPythonSnippet && !isJavaSnippet && language !== 'python') {
        if (onLanguageChange) onLanguageChange('python', true);
        if (setLanguage) setLanguage('python');
        if (!filename || filename.endsWith('.java')) {
          setFilename('vulnerable_service.py');
        }
      }
    }
  };

  /** Smart language detector by extension and code structure heuristics */
  const detectLanguageFromFile = (fname, code) => {
    const ext = fname?.split('.').pop()?.toLowerCase();
    if (['py', 'pyw', 'python', 'py3'].includes(ext)) {
      return 'python';
    }
    if (['java', 'jav'].includes(ext)) {
      return 'java';
    }
    // Content-based heuristic if extension is generic (.txt, code file, or extensionless)
    if (code) {
      if (/\b(public\s+(?:class|interface|enum|record)|import\s+java\.|System\.out\.print|package\s+[a-z0-9_.]+;)\b/.test(code)) {
        return 'java';
      }
      if (/\b(def\s+[a-zA-Z_]\w*\s*\(|import\s+os\b|import\s+sys\b|if\s+__name__\s*==|elif\s+|from\s+[a-zA-Z_]\w*\s+import)\b/.test(code)) {
        return 'python';
      }
    }
    return language || 'python';
  };

  /** Core file processing — used by both click-upload and drag-and-drop */
  const processFile = (file) => {
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const code = event.target?.result || '';
      const detectedLang = detectLanguageFromFile(file.name, code);
      const lines = code.split('\n').length;

      if (detectedLang !== language) {
        if (onLanguageChange) onLanguageChange(detectedLang, true);
        else if (setLanguage) setLanguage(detectedLang);
      }

      setFilename(file.name);
      setSourceCode(code);

      // Store comprehensive uploaded file information for the uploaded file view
      setUploadInfo({
        filename: file.name,
        detectedLang,
        sizeKb: (file.size / 1024).toFixed(1),
        lineCount: lines,
        content: code,
        uploadedAt: new Date().toLocaleTimeString()
      });
      setShowUploadedContent(true);

      // Immediately trigger analysis using the fresh closure ref pattern (no race condition)
      if (code.trim() && onAnalyzeRef.current) {
        onAnalyzeRef.current(detectedLang, code, file.name);
      }
    };
    reader.readAsText(file);
  };

  const handleFileInputChange = (e) => {
    processFile(e.target.files?.[0]);
    // reset so the same file can be re-uploaded
    e.target.value = '';
  };

  /* ── Drag-and-Drop handlers ── */
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current += 1;
    if (e.dataTransfer?.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    } else if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      if (e.dataTransfer) {
        e.dataTransfer.dropEffect = 'copy';
      }
    } catch {
      // ignore
    }
    if (!isDragging) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setIsDragging(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current = 0;
    setIsDragging(false);

    let file = null;
    if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
      file = e.dataTransfer.files[0];
    } else if (e.dataTransfer?.items && e.dataTransfer.items.length > 0) {
      const item = e.dataTransfer.items[0];
      if (item.kind === 'file') {
        file = item.getAsFile();
      }
    }

    if (!file) return;
    processFile(file);
  };

  const handleCopyUploadedContent = async () => {
    if (!uploadInfo?.content) return;
    const success = await copyToClipboard(uploadInfo.content);
    if (success) {
      setCopiedContent(true);
      setTimeout(() => setCopiedContent(false), 2000);
    }
  };

  const linesCount = sourceCode.split('\n').length;
  const charsCount = sourceCode.length;

  const langBadge = language === 'python'
    ? { label: '🐍 Python', color: '#3b82f6' }
    : { label: '☕ Java', color: '#f97316' };

  // Calculate dynamic scan status for uploadInfo banner
  const getUploadScanStatus = () => {
    if (isAnalyzing) {
      return {
        label: '⚡ Auto-scanning in progress…',
        color: '#38bdf8',
        bg: 'rgba(56, 189, 248, 0.15)',
        border: 'rgba(56, 189, 248, 0.3)'
      };
    }
    if (analysisError) {
      return {
        label: `❌ Scan Failed: ${analysisError}`,
        color: '#f87171',
        bg: 'rgba(239, 68, 68, 0.15)',
        border: 'rgba(239, 68, 68, 0.3)'
      };
    }
    if (analysisResult) {
      const count = analysisResult.findings?.length || 0;
      return {
        label: count === 0 ? '✅ Inspection Passed (0 Findings)' : `⚠️ Inspection Complete (${count} Finding${count === 1 ? '' : 's'})`,
        color: count === 0 ? '#34d399' : '#fbbf24',
        bg: count === 0 ? 'rgba(52, 211, 153, 0.15)' : 'rgba(251, 191, 36, 0.15)',
        border: count === 0 ? 'rgba(52, 211, 153, 0.3)' : 'rgba(251, 191, 36, 0.3)'
      };
    }
    return {
      label: '⚡ Ready for Scan',
      color: '#94a3b8',
      bg: 'rgba(148, 163, 184, 0.15)',
      border: 'rgba(148, 163, 184, 0.3)'
    };
  };

  const scanStatus = getUploadScanStatus();

  const handleCopyWholeCode = () => {
    copyToClipboard(sourceCode);
    setCopiedWholeCode(true);
    setTimeout(() => setCopiedWholeCode(false), 2500);
  };

  const handleDownloadCode = () => {
    if (onDownloadCleanCode) {
      onDownloadCleanCode();
      return;
    }
    const cleanFilename = filename?.startsWith('clean_')
      ? filename
      : `clean_${filename || (language === 'python' ? 'script.py' : 'App.java')}`;
    const blob = new Blob([sourceCode], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = cleanFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const codeLines = sourceCode.split('\n');
  const totalFindingsCount = analysisResult?.findings?.length || 0;
  const activeErrorsCount = analysisResult?.summary?.active_errors_count ?? (
    analysisResult?.findings?.filter((f) => {
      const key = `${f.rule_id || 'RULE'}-${f.line || 0}-${(f.evidence || '').slice(0, 30)}`;
      return !fixedFindingKeys?.has(key) && !fixedLinesMap?.[f.line];
    }).length || 0
  );
  const fixedCount = Math.max(0, totalFindingsCount - activeErrorsCount);

  // Active syntax diagnostics count
  const allSyntaxDiags = validationResult?.diagnostics || [];
  const activeSyntaxDiags = allSyntaxDiags.filter((d) => {
    const k = `syntax-${d.line}-${d.message}`;
    return !fixedSyntaxDiagnosticKeys?.has(k) && !fixedSyntaxLinesMap?.[d.line];
  });
  const activeSyntaxCount = activeSyntaxDiags.length;

  const currentHealthScore = analysisResult?.summary?.overall_code_health_score ?? (
    (activeErrorsCount === 0 && activeSyntaxCount === 0 && (totalFindingsCount > 0 || allSyntaxDiags.length > 0))
      ? 100
      : (activeSyntaxCount > 0 ? 80 : (activeErrorsCount === 0 ? 100 : 85))
  );

  const hasAnyInspectableLines = totalFindingsCount > 0 || allSyntaxDiags.length > 0;

  return (
    <div
      className="glass-panel"
      style={{
        padding: '24px',
        position: 'relative',
        transition: 'border-color 0.2s, box-shadow 0.2s',
        borderColor: isDragging ? 'var(--accent-cyan)' : undefined,
        boxShadow: isDragging ? '0 0 24px rgba(6, 182, 212, 0.25)' : undefined
      }}
      id="code-editor-panel"
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Top Toolbar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        {/* Language Tabs */}
        <div style={{ display: 'flex', gap: '6px', background: 'rgba(255, 255, 255, 0.04)', padding: '4px', borderRadius: '8px' }}>
          <button
            id="tab-lang-python"
            type="button"
            className={`btn ${language === 'python' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '6px 16px', fontSize: '0.82rem' }}
            onClick={() => handleLanguageChange('python')}
          >
            🐍 Python (AST)
          </button>
          <button
            id="tab-lang-java"
            type="button"
            className={`btn ${language === 'java' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '6px 16px', fontSize: '0.82rem' }}
            onClick={() => handleLanguageChange('java')}
          >
            ☕ Java (javac)
          </button>
        </div>

        {/* Sample Code Dropdown + Upload */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <select
            id="select-sample-code"
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '0.82rem', background: '#0f172a', color: '#e2e8f0', borderColor: 'var(--border-subtle)' }}
            onChange={handleSampleSelect}
            value={selectedSampleKey}
          >
            <option value="" disabled>Load Complexity Sample...</option>
            <optgroup label="🐍 Python Samples (3 Tiers)">
              <option value="python_valid">🟢 Low: Secure Calculator (Clean)</option>
              <option value="python_moderate">🟡 Moderate: Data Pipeline (Code Smells)</option>
              <option value="python_vulnerable">🔴 High: Vulnerable Service (OWASP Flaws)</option>
            </optgroup>
            <optgroup label="☕ Java Samples (3 Tiers)">
              <option value="java_valid">🟢 Low: Secure Banking (Clean)</option>
              <option value="java_moderate">🟡 Moderate: Order Manager (Code Smells)</option>
              <option value="java_vulnerable">🔴 High: Legacy Portal (OWASP Flaws)</option>
            </optgroup>
          </select>

          {/* Hidden file input */}
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            accept=".py,.java,.pyw,.python,.jav,.txt"
            style={{ display: 'none' }}
            id="file-upload-input"
          />
          <button
            id="btn-upload-file"
            type="button"
            className="btn btn-secondary"
            style={{ padding: '6px 14px', fontSize: '0.82rem' }}
            onClick={() => fileInputRef.current?.click()}
          >
            📁 Upload Source
          </button>
        </div>
      </div>

      {/* Uploaded File View & Status Banner — comprehensive file details and preview */}
      {uploadInfo && (
        <div
          id="uploaded-file-view-container"
          style={{
            marginBottom: '16px',
            background: 'rgba(15, 23, 42, 0.85)',
            border: '1px solid rgba(6, 182, 212, 0.35)',
            borderRadius: '10px',
            overflow: 'hidden',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)'
          }}
        >
          {/* Header strip */}
          <div
            style={{
              padding: '10px 14px',
              background: 'rgba(6, 182, 212, 0.08)',
              borderBottom: '1px solid rgba(6, 182, 212, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '10px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '1.1rem' }}>📄</span>
              <div>
                <span style={{ color: 'var(--accent-cyan)', fontWeight: '700', fontSize: '0.85rem' }}>
                  Uploaded File:
                </span>{' '}
                <span style={{ color: '#f8fafc', fontFamily: 'var(--font-mono)', fontWeight: '600', fontSize: '0.85rem' }}>
                  {uploadInfo.filename}
                </span>
              </div>

              <span
                style={{
                  background: uploadInfo.detectedLang === 'python' ? 'rgba(59,130,246,0.18)' : 'rgba(249,115,22,0.18)',
                  color: uploadInfo.detectedLang === 'python' ? '#60a5fa' : '#fb923c',
                  border: `1px solid ${uploadInfo.detectedLang === 'python' ? 'rgba(59,130,246,0.35)' : 'rgba(249,115,22,0.35)'}`,
                  borderRadius: '4px',
                  padding: '1px 8px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  fontWeight: '700',
                  textTransform: 'uppercase'
                }}
              >
                {uploadInfo.detectedLang === 'python' ? '🐍 Python' : '☕ Java'}
              </span>

              <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>
                {uploadInfo.sizeKb} KB &bull; {uploadInfo.lineCount} lines &bull; Loaded {uploadInfo.uploadedAt}
              </span>
            </div>

            {/* Scan status indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                style={{
                  padding: '2px 10px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: '600',
                  color: scanStatus.color,
                  background: scanStatus.bg,
                  border: `1px solid ${scanStatus.border}`
                }}
              >
                {scanStatus.label}
              </span>

              <button
                type="button"
                onClick={() => setShowUploadedContent(!showUploadedContent)}
                className="btn btn-secondary"
                style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                title="Toggle file content view"
              >
                {showUploadedContent ? '👁️ Hide File View' : '👁️ Show File View'}
              </button>

              <button
                type="button"
                onClick={handleCopyUploadedContent}
                className="btn btn-secondary"
                style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                title="Copy uploaded file content"
              >
                {copiedContent ? '✓ Copied' : '📋 Copy'}
              </button>

              <button
                type="button"
                onClick={() => {
                  if (onAnalyzeRef.current) {
                    onAnalyzeRef.current(uploadInfo.detectedLang, sourceCode, uploadInfo.filename);
                  }
                }}
                className="btn btn-primary"
                style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                title="Re-run security scan on this uploaded file"
                disabled={isAnalyzing}
              >
                ⚡ Re-scan
              </button>

              <button
                type="button"
                onClick={() => setUploadInfo(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: '#94a3b8',
                  cursor: 'pointer',
                  fontSize: '0.95rem',
                  padding: '2px 6px'
                }}
                aria-label="Dismiss uploaded file view"
                title="Dismiss"
              >
                ✕
              </button>
            </div>
          </div>

          {/* Uploaded File Content Display with Line Numbers */}
          {showUploadedContent && (
            <div
              id="uploaded-file-content-view"
              style={{
                maxHeight: '260px',
                overflowY: 'auto',
                background: 'rgba(5, 10, 20, 0.95)',
                padding: '12px 16px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.82rem',
                lineHeight: '1.5'
              }}
            >
              <div style={{ color: 'var(--text-dim)', fontSize: '0.72rem', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Uploaded File Source Preview ({uploadInfo.filename})
              </div>
              <pre style={{ margin: 0, color: '#e2e8f0', whiteSpace: 'pre', overflowX: 'auto' }}>
                {uploadInfo.content.split('\n').map((lineText, idx) => (
                  <div key={idx} style={{ display: 'flex', minHeight: '1.3em' }}>
                    <span
                      style={{
                        width: '40px',
                        flexShrink: 0,
                        color: 'var(--text-dim)',
                        userSelect: 'none',
                        textAlign: 'right',
                        paddingRight: '12px',
                        borderRight: '1px solid rgba(255, 255, 255, 0.08)'
                      }}
                    >
                      {idx + 1}
                    </span>
                    <span style={{ paddingLeft: '12px', color: '#cbd5e1' }}>
                      {lineText || ' '}
                    </span>
                  </div>
                ))}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Target Filename input */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Target File:</span>
        <input
          id="input-filename"
          type="text"
          value={filename}
          onChange={(e) => setFilename(e.target.value)}
          placeholder="e.g. VulnerableService.java"
          style={{
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            color: '#38bdf8',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.82rem',
            padding: '4px 10px',
            flex: 1
          }}
        />
        {/* Active language indicator */}
        <span
          style={{
            padding: '3px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: '700',
            fontFamily: 'var(--font-mono)',
            background: language === 'python' ? 'rgba(59,130,246,0.12)' : 'rgba(249,115,22,0.12)',
            color: language === 'python' ? '#60a5fa' : '#fb923c',
            border: `1px solid ${language === 'python' ? 'rgba(59,130,246,0.25)' : 'rgba(249,115,22,0.25)'}`,
            whiteSpace: 'nowrap'
          }}
        >
          {langBadge.label}
        </span>
      </div>

      {/* Dynamic Health Score & Error Line Banner (Milestone 3) */}
      {hasAnyInspectableLines && (
        <div
          id="editor-status-banner"
          style={{
            marginBottom: '12px',
            padding: '10px 14px',
            borderRadius: '8px',
            background: (activeErrorsCount === 0 && activeSyntaxCount === 0)
              ? 'rgba(34, 197, 94, 0.12)'
              : (activeErrorsCount === 0 && activeSyntaxCount > 0)
              ? 'rgba(234, 179, 8, 0.12)'
              : 'rgba(239, 68, 68, 0.12)',
            border: (activeErrorsCount === 0 && activeSyntaxCount === 0)
              ? '1px solid rgba(34, 197, 94, 0.35)'
              : (activeErrorsCount === 0 && activeSyntaxCount > 0)
              ? '1px solid rgba(234, 179, 8, 0.35)'
              : '1px solid rgba(239, 68, 68, 0.35)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.25rem' }}>
              {(activeErrorsCount === 0 && activeSyntaxCount === 0) ? '🎉' : (activeErrorsCount === 0 ? '⚠️' : '🛡️')}
            </span>
            <div>
              <div
                style={{
                  fontWeight: '700',
                  fontSize: '0.88rem',
                  color: (activeErrorsCount === 0 && activeSyntaxCount === 0)
                    ? '#4ade80'
                    : (activeErrorsCount === 0 ? '#fde047' : '#f87171')
                }}
              >
                {(activeErrorsCount === 0 && activeSyntaxCount === 0)
                  ? '0 Errors Remaining • 100% Clean Code Verified!'
                  : (activeErrorsCount === 0 && activeSyntaxCount > 0)
                  ? `0 Vulnerabilities Remaining • ${activeSyntaxCount} Syntax Issue(s) Need Attention (in Yellow)`
                  : `${activeErrorsCount} Active Vulnerability Line(s) in Red${activeSyntaxCount > 0 ? ` • ${activeSyntaxCount} Syntax Issue(s) in Yellow` : ''} • ${fixedCount} Fixed in Green`}
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                {(activeErrorsCount === 0 && activeSyntaxCount === 0)
                  ? 'All vulnerabilities and syntax issues successfully remediated. Code is safe for production merge and export.'
                  : (activeErrorsCount === 0 && activeSyntaxCount > 0)
                  ? 'Resolve highlighted syntax/compiler deprecation issues using "⚡ Fix Syntax" to achieve a 100/100 score.'
                  : 'Click "⚡ Fix Line" on red rows or "⚡ Fix Syntax" on yellow rows to remediate code issues.'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontWeight: '800',
                fontSize: '0.82rem',
                fontFamily: 'var(--font-mono)',
                background: (activeErrorsCount === 0 && activeSyntaxCount === 0) ? 'rgba(34, 197, 94, 0.2)' : 'rgba(251, 191, 36, 0.2)',
                color: (activeErrorsCount === 0 && activeSyntaxCount === 0) ? '#4ade80' : '#fbbf24',
                border: (activeErrorsCount === 0 && activeSyntaxCount === 0) ? '1px solid rgba(34, 197, 94, 0.4)' : '1px solid rgba(251, 191, 36, 0.4)'
              }}
            >
              Score: {currentHealthScore}/100
            </span>

            {(activeErrorsCount > 0 || activeSyntaxCount > 0) && onFixAll && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={onFixAll}
                style={{ padding: '4px 12px', fontSize: '0.78rem' }}
                title="Automatically apply all recommended remediations and syntax fixes at once"
              >
                ⚡ Fix All ({activeErrorsCount + activeSyntaxCount})
              </button>
            )}
          </div>
        </div>
      )}

      {/* Code Editor — also a drag-and-drop drop zone */}
      <div
        className="editor-wrapper"
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          outline: isDragging ? '2px dashed var(--accent-cyan)' : undefined,
          boxShadow: isDragging ? '0 0 0 4px rgba(6,182,212,0.25)' : undefined,
          transition: 'outline 0.15s, box-shadow 0.15s',
          position: 'relative'
        }}
      >
        <div className="editor-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span>{filename}</span>
            {hasAnyInspectableLines && (
              <div style={{ display: 'flex', gap: '4px', marginLeft: '6px' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('inspector')}
                  style={{
                    background: viewMode === 'inspector' ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.08)',
                    color: viewMode === 'inspector' ? '#0f172a' : '#cbd5e1',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '2px 8px',
                    fontSize: '0.72rem',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  🔍 Security Line Inspector
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('raw')}
                  style={{
                    background: viewMode === 'raw' ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.08)',
                    color: viewMode === 'raw' ? '#0f172a' : '#cbd5e1',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '2px 8px',
                    fontSize: '0.72rem',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  ✏️ Raw Editor
                </button>
              </div>
            )}
          </div>
          <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
            <span>{linesCount} lines</span>
            <span>{charsCount} chars</span>
            <span>{language.toUpperCase()}</span>
          </div>
        </div>

        {/* Drag overlay */}
        {isDragging && (
          <div
            id="drag-drop-overlay"
            style={{
              position: 'absolute',
              inset: 0,
              zIndex: 30,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'rgba(10, 15, 30, 0.94)',
              border: '2px dashed var(--accent-cyan)',
              borderRadius: 'var(--radius-md)',
              pointerEvents: 'none',
              backdropFilter: 'blur(6px)'
            }}
          >
            <span style={{ fontSize: '3.2rem' }}>📂</span>
            <p style={{ color: 'var(--accent-cyan)', fontWeight: '800', marginTop: '10px', fontSize: '1.15rem' }}>
              Drop Python (.py) or Java (.java) file here
            </p>
            <span style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '4px' }}>
              Source will be immediately loaded and analyzed
            </span>
          </div>
        )}

        {/* Interactive Line-by-Line Code Inspector with Red, Green, Yellow, Blue Highlights */}
        {viewMode === 'inspector' && hasAnyInspectableLines ? (
          <div className="code-inspector-container" id="code-line-inspector">
            {codeLines.map((lineText, idx) => {
              const lineNum = idx + 1;
              const lineFindings = (analysisResult?.findings || []).filter((f) => f.line === lineNum);
              const isFinding = lineFindings.length > 0;
              const isFindingFixed = isFinding && (
                fixedLinesMap?.[lineNum] ||
                lineFindings.every((f) => {
                  const key = `${f.rule_id || 'RULE'}-${f.line || 0}-${(f.evidence || '').slice(0, 30)}`;
                  return fixedFindingKeys?.has(key);
                })
              );
              const isActiveFinding = isFinding && !isFindingFixed;

              // Check syntax diagnostics for this line
              const lineSyntaxDiags = allSyntaxDiags.filter((d) => d.line === lineNum);
              const isSyntax = lineSyntaxDiags.length > 0;
              const isSyntaxFixed = isSyntax && (
                fixedSyntaxLinesMap?.[lineNum] ||
                lineSyntaxDiags.every((d) => fixedSyntaxDiagnosticKeys?.has(`syntax-${d.line}-${d.message}`))
              );
              const isActiveSyntax = isSyntax && !isSyntaxFixed;

              let rowClass = 'code-line-row';
              let gutterSymbol = '';
              if (isActiveFinding) {
                rowClass += ' code-line-error';
                gutterSymbol = '🔴 ';
              } else if (isActiveSyntax) {
                rowClass += ' code-line-syntax-error';
                gutterSymbol = '🟡 ';
              } else if (isFindingFixed) {
                rowClass += ' code-line-fixed';
                gutterSymbol = '🟢 ';
              } else if (isSyntaxFixed) {
                rowClass += ' code-line-syntax-fixed';
                gutterSymbol = '🔵 ';
              }

              return (
                <div key={lineNum} className={rowClass}>
                  <div className="code-line-gutter">
                    {gutterSymbol}{lineNum}
                  </div>
                  <div className="code-line-content">
                    <span className="code-line-text">{lineText || ' '}</span>

                    {/* Active Finding (Red) */}
                    {isActiveFinding && (
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexShrink: 0 }}>
                        <span className="code-line-badge-error" title={`${lineFindings[0]?.rule_id}: ${lineFindings[0]?.title}`}>
                          🔴 Vulnerable Line
                        </span>
                        {onApplyFix && (
                          <button
                            type="button"
                            className="btn-fix-inline"
                            onClick={() => onApplyFix(lineFindings[0], lineFindings[0]?.remediation?.corrected_code)}
                            title="Apply recommended fix to this line"
                          >
                            ⚡ Fix Line
                          </button>
                        )}
                      </div>
                    )}

                    {/* Active Syntax Error/Warning (Yellow) */}
                    {!isActiveFinding && isActiveSyntax && (
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexShrink: 0 }}>
                        <span className="code-line-badge-syntax-error" title={lineSyntaxDiags[0]?.message}>
                          🟡 Syntax Issue
                        </span>
                        {onFixDiagnostic && (
                          <button
                            type="button"
                            className="btn-fix-syntax-inline"
                            onClick={() => onFixDiagnostic(lineSyntaxDiags[0])}
                            title="Apply fix for this syntax/compiler issue"
                          >
                            ⚡ Fix Syntax
                          </button>
                        )}
                      </div>
                    )}

                    {/* Remediated Finding (Green) */}
                    {isFindingFixed && !isActiveSyntax && (
                      <span className="code-line-badge-fixed">
                        ✅ Corrected &amp; Clean
                      </span>
                    )}

                    {/* Remediated Syntax (Blue) */}
                    {!isFinding && isSyntaxFixed && (
                      <span className="code-line-badge-syntax-fixed">
                        🔵 Syntax Validated &amp; Fixed
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}

        <textarea
          id="code-editor-textarea"
          className="code-textarea"
          value={sourceCode}
          onChange={handleTextareaChange}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          placeholder="Paste or write your Python / Java code here, or drag-and-drop a .py / .java file onto this editor…"
          spellCheck="false"
          style={{
            display: viewMode === 'inspector' && hasAnyInspectableLines ? 'none' : 'block'
          }}
        />
      </div>

      {/* Action Buttons Toolbar */}
      <div style={{ display: 'flex', gap: '10px', marginTop: '18px', flexWrap: 'wrap', alignItems: 'center' }}>
        <button
          id="btn-validate"
          type="button"
          className="btn btn-secondary"
          onClick={() => onValidate()}
          disabled={isValidating || isAnalyzing || isGeneratingPdf || !sourceCode.trim()}
        >
          {isValidating ? 'Validating Syntax...' : '🔍 Validate Syntax'}
        </button>

        <button
          id="btn-analyze"
          type="button"
          className="btn btn-primary"
          onClick={() => onAnalyze()}
          disabled={isAnalyzing || isValidating || isGeneratingPdf || !sourceCode.trim()}
          style={{ minWidth: '170px' }}
        >
          {isAnalyzing ? 'Inspecting AST & Rules...' : '⚡ Inspect & Analyze'}
        </button>

        <button
          id="btn-download-pdf"
          type="button"
          className="btn btn-secondary"
          onClick={onDownloadPdf}
          disabled={isGeneratingPdf || isAnalyzing || isValidating || !sourceCode.trim()}
        >
          {isGeneratingPdf ? 'Generating PDF...' : '📄 Export PDF Report'}
        </button>

        {/* Clean Code Export & Copy */}
        <button
          id="btn-download-clean-code"
          type="button"
          className="btn btn-success"
          onClick={handleDownloadCode}
          disabled={!sourceCode.trim()}
          title={`Download clean source code as .${language === 'python' ? 'py' : 'java'}`}
        >
          📥 Download Clean Code (.{language === 'python' ? 'py' : 'java'})
        </button>

        <button
          id="btn-copy-whole-code"
          type="button"
          className="btn btn-secondary"
          onClick={handleCopyWholeCode}
          disabled={!sourceCode.trim()}
          title="Copy entire editor contents to clipboard"
        >
          {copiedWholeCode ? '✅ Whole Code Copied!' : '📋 Copy Whole Code'}
        </button>
      </div>

      {/* Color Legend for Code Inspector (Milestone 3 Error Highlighting) */}
      <div className="inspector-color-legend" id="inspector-color-legend">
        <span style={{ fontWeight: '700', color: '#f8fafc', marginRight: '4px' }}>🎨 Color Legend:</span>
        <span className="legend-item">
          <span className="legend-dot" style={{ background: '#ef4444' }}></span>
          <span style={{ color: '#fca5a5' }}>🔴 Red: Active Vulnerability</span>
        </span>
        <span className="legend-item">
          <span className="legend-dot" style={{ background: '#22c55e' }}></span>
          <span style={{ color: '#86efac' }}>🟢 Green: Remediated Vulnerability</span>
        </span>
        <span className="legend-item">
          <span className="legend-dot" style={{ background: '#eab308' }}></span>
          <span style={{ color: '#fde047' }}>🟡 Yellow: Syntax / Compiler Error</span>
        </span>
        <span className="legend-item">
          <span className="legend-dot" style={{ background: '#3b82f6' }}></span>
          <span style={{ color: '#93c5fd' }}>🔵 Blue: Corrected Syntax</span>
        </span>
      </div>

      {/* Drag-and-drop hint */}
      <p style={{ marginTop: '10px', fontSize: '0.76rem', color: 'var(--text-dim)', textAlign: 'center' }}>
        💡 Drag &amp; drop a <code style={{ color: 'var(--text-muted)' }}>.py</code> or <code style={{ color: 'var(--text-muted)' }}>.java</code> file onto the editor — language is auto-detected and scanned immediately
      </p>
    </div>
  );
}

