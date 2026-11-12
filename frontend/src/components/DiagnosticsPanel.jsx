import React from 'react';

export function DiagnosticsPanel({
  validationResult,
  isValidating,
  onValidate,
  onFixDiagnostic,
  fixedSyntaxDiagnosticKeys = new Set(),
  fixedSyntaxLinesMap = {}
}) {
  // Active validating state
  if (isValidating) {
    return (
      <div
        className="glass-panel"
        id="diagnostics-panel"
        style={{
          padding: '24px',
          borderLeft: '4px solid var(--accent-cyan)',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.3rem', animation: 'spin 1.5s linear infinite' }}>⏳</span>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#ffffff' }}>
                Validating Syntax &amp; AST Structure…
              </h3>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Running parser and compiler checks to verify code integrity
              </p>
            </div>
          </div>
          <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.15)', color: 'var(--accent-cyan)', border: '1px solid rgba(6, 182, 212, 0.3)' }}>
            VALIDATING…
          </span>
        </div>
      </div>
    );
  }

  // Waiting / Standby state before any validation has been triggered
  if (!validationResult) {
    return (
      <div
        className="glass-panel"
        id="diagnostics-panel"
        style={{
          padding: '24px',
          borderLeft: '4px solid rgba(148, 163, 184, 0.4)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.25rem' }}>⏳</span>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#ffffff' }}>
                Syntax &amp; Compiler Diagnostics
              </h3>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                Awaiting code validation or security inspection
              </p>
            </div>
          </div>
          <span className="badge" style={{ background: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' }}>
            STANDBY
          </span>
        </div>

        <div
          style={{
            background: 'rgba(0, 0, 0, 0.25)',
            border: '1px dashed var(--border-subtle)',
            borderRadius: '8px',
            padding: '16px',
            textAlign: 'center'
          }}
        >
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '12px' }}>
            No syntax diagnostics recorded yet. Run <strong>Validate Syntax</strong> or <strong>Inspect &amp; Analyze</strong> to evaluate parser and compiler tokens.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', flexWrap: 'wrap', fontSize: '0.78rem', color: 'var(--text-dim)', marginBottom: '14px' }}>
            <span>🐍 Python <code>ast.parse()</code></span>
            <span>&bull;</span>
            <span>☕ Java <code>javac</code> Compiler</span>
            <span>&bull;</span>
            <span>⚡ Exact Line &amp; Column Locator</span>
          </div>

          {onValidate && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ fontSize: '0.8rem', padding: '6px 14px' }}
              onClick={() => onValidate()}
            >
              🔍 Validate Current Code
            </button>
          )}
        </div>
      </div>
    );
  }

  const isValid = validationResult.valid_syntax;
  const diagnostics = validationResult.diagnostics || [];
  const message = validationResult.message || '';

  return (
    <div
      className="glass-panel"
      id="diagnostics-panel"
      style={{
        padding: '20px',
        borderLeft: `4px solid ${isValid ? 'var(--accent-emerald)' : 'var(--sev-critical)'}`
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '1.2rem' }}>{isValid ? '✅' : '❌'}</span>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', color: '#ffffff' }}>
              {isValid ? 'Syntax & Compiler Validation Passed' : 'Syntax / Compilation Diagnostics Reported'}
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>{message}</p>
          </div>
        </div>

        <div className={`badge ${isValid ? 'badge-low' : 'badge-critical'}`}>
          {isValid ? 'VALID CODE' : `${diagnostics.length} DIAGNOSTIC(S)`}
        </div>
      </div>

      {diagnostics.length > 0 && (
        <div style={{ marginTop: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {diagnostics.map((diag, idx) => {
            const diagKey = `syntax-${diag.line}-${diag.message}`;
            const isDiagFixed = fixedSyntaxDiagnosticKeys?.has(diagKey) || fixedSyntaxLinesMap?.[diag.line];

            return (
              <div
                key={idx}
                style={{
                  background: isDiagFixed ? 'rgba(59, 130, 246, 0.08)' : 'rgba(0, 0, 0, 0.4)',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: isDiagFixed ? '1px solid rgba(59, 130, 246, 0.35)' : '1px solid var(--border-subtle)',
                  fontSize: '0.85rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', alignItems: 'center' }}>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <span className={`badge ${diag.severity === 'error' ? 'badge-critical' : 'badge-medium'}`}>
                      {diag.severity?.toUpperCase() || 'ERROR'}
                    </span>
                    {isDiagFixed && (
                      <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.25)', color: '#93c5fd', border: '1px solid rgba(59, 130, 246, 0.4)', fontWeight: '700' }}>
                        🔵 Corrected &amp; Validated
                      </span>
                    )}
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Line {diag.line}{diag.column ? `, Col ${diag.column}` : ''}
                  </span>
                </div>
                <p style={{ color: isDiagFixed ? '#93c5fd' : '#f87171', margin: '4px 0', fontFamily: 'var(--font-mono)' }}>
                  {diag.message}
                </p>
                {diag.evidence && (
                  <pre className="code-evidence-box" style={{ margin: '4px 0 0 0' }}>
                    {diag.evidence}
                  </pre>
                )}
                {!isDiagFixed && onFixDiagnostic && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => onFixDiagnostic(diag)}
                      style={{
                        padding: '4px 12px',
                        fontSize: '0.75rem',
                        background: 'rgba(234, 179, 8, 0.18)',
                        borderColor: 'rgba(234, 179, 8, 0.4)',
                        color: '#fde047',
                        fontWeight: '700'
                      }}
                      title="Apply auto-remediation fix for this syntax/compiler issue"
                    >
                      ⚡ Fix Syntax Issue
                    </button>
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

