import React from 'react';

export function DiagnosticsPanel({ validationResult, isValidating, onValidate }) {
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
          {diagnostics.map((diag, idx) => (
            <div
              key={idx}
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                padding: '10px 14px',
                borderRadius: '6px',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.85rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span className={`badge ${diag.severity === 'error' ? 'badge-critical' : 'badge-medium'}`}>
                  {diag.severity?.toUpperCase() || 'ERROR'}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Line {diag.line}{diag.column ? `, Col ${diag.column}` : ''}
                </span>
              </div>
              <p style={{ color: '#f87171', margin: '4px 0', fontFamily: 'var(--font-mono)' }}>
                {diag.message}
              </p>
              {diag.evidence && (
                <pre className="code-evidence-box" style={{ margin: '4px 0 0 0' }}>
                  {diag.evidence}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

