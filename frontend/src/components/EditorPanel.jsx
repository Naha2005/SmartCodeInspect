import React, { useRef, useState, useEffect } from 'react';
import { SAMPLE_CODES } from '../constants/samples';

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
  analysisError
}) {
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadInfo, setUploadInfo] = useState(null);
  const [showUploadedContent, setShowUploadedContent] = useState(true);
  const [copiedContent, setCopiedContent] = useState(false);

  // Maintain fresh onAnalyze closure using ref pattern to eliminate race conditions
  const onAnalyzeRef = useRef(onAnalyze);
  useEffect(() => {
    onAnalyzeRef.current = onAnalyze;
  }, [onAnalyze]);

  const changeLanguage = (newLang) => {
    if (onLanguageChange) {
      onLanguageChange(newLang);
    } else if (setLanguage) {
      setLanguage(newLang);
    }
    setUploadInfo(null);
  };

  const handleLanguageChange = (newLang) => {
    changeLanguage(newLang);
    if (!onLanguageChange) {
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

  const handleSampleSelect = (e) => {
    const key = e.target.value;
    if (!key || !SAMPLE_CODES[key]) return;
    const sample = SAMPLE_CODES[key];
    if (onLanguageChange) {
      onLanguageChange(sample.language);
    } else if (setLanguage) {
      setLanguage(sample.language);
    }
    setFilename(sample.filename);
    setSourceCode(sample.code);
    setUploadInfo(null);
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
        if (onLanguageChange) onLanguageChange(detectedLang);
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
  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    processFile(file);
  };

  const handleCopyUploadedContent = () => {
    if (!uploadInfo?.content) return;
    navigator.clipboard.writeText(uploadInfo.content);
    setCopiedContent(true);
    setTimeout(() => setCopiedContent(false), 2000);
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

  return (
    <div className="glass-panel" style={{ padding: '24px' }} id="code-editor-panel">
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
            defaultValue=""
          >
            <option value="" disabled>Load Sample Code...</option>
            <option value="python_vulnerable">⚠️ Vulnerable Python (OWASP Flaws)</option>
            <option value="python_valid">✅ Valid Python (Secure Code)</option>
            <option value="java_vulnerable">⚠️ Vulnerable Java (OWASP Flaws)</option>
            <option value="java_valid">✅ Valid Java (Secure Code)</option>
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

      {/* Code Editor — also a drag-and-drop drop zone */}
      <div
        className="editor-wrapper"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          outline: isDragging ? '2px dashed var(--accent-cyan)' : undefined,
          boxShadow: isDragging ? '0 0 0 4px rgba(6,182,212,0.15)' : undefined,
          transition: 'outline 0.15s, box-shadow 0.15s',
          position: 'relative'
        }}
      >
        <div className="editor-header">
          <span>{filename}</span>
          <div style={{ display: 'flex', gap: '14px' }}>
            <span>{linesCount} lines</span>
            <span>{charsCount} chars</span>
            <span>{language.toUpperCase()}</span>
          </div>
        </div>

        {/* Drag overlay */}
        {isDragging && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              zIndex: 10,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'rgba(6, 182, 212, 0.08)',
              pointerEvents: 'none'
            }}
          >
            <span style={{ fontSize: '2.5rem' }}>📂</span>
            <p style={{ color: 'var(--accent-cyan)', fontWeight: '700', marginTop: '8px', fontSize: '1rem' }}>
              Drop .py or .java file to load &amp; scan
            </p>
          </div>
        )}

        <textarea
          id="code-editor-textarea"
          className="code-textarea"
          value={sourceCode}
          onChange={(e) => setSourceCode(e.target.value)}
          placeholder="Paste or write your Python / Java code here, or drag-and-drop a .py / .java file onto this editor…"
          spellCheck="false"
        />
      </div>

      {/* Action Buttons Toolbar */}
      <div style={{ display: 'flex', gap: '12px', marginTop: '18px', flexWrap: 'wrap' }}>
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
          style={{ minWidth: '180px' }}
        >
          {isAnalyzing ? 'Inspecting AST & Rules...' : '⚡ Inspect & Analyze'}
        </button>

        <button
          id="btn-download-pdf"
          type="button"
          className="btn btn-success"
          onClick={onDownloadPdf}
          disabled={isGeneratingPdf || isAnalyzing || isValidating || !sourceCode.trim()}
        >
          {isGeneratingPdf ? 'Generating PDF...' : '📄 Export PDF Report'}
        </button>
      </div>

      {/* Drag-and-drop hint */}
      <p style={{ marginTop: '10px', fontSize: '0.76rem', color: 'var(--text-dim)', textAlign: 'center' }}>
        💡 Drag &amp; drop a <code style={{ color: 'var(--text-muted)' }}>.py</code> or <code style={{ color: 'var(--text-muted)' }}>.java</code> file onto the editor — language is auto-detected and scanned immediately
      </p>
    </div>
  );
}

