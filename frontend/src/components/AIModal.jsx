import React, { useState } from 'react';
import { apiService } from '../services/api';

export function AIModal({ finding, onClose, aiConfig }) {
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);
  const [confirmedDisclosure, setConfirmedDisclosure] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.explainWithAI(finding);
      setResponse(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      id="ai-advisory-modal"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '20px'
      }}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '720px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          background: '#0d1527',
          border: '1px solid rgba(139, 92, 246, 0.4)',
          boxShadow: '0 0 30px rgba(139, 92, 246, 0.25)',
          borderRadius: '12px',
          overflow: 'hidden'
        }}
      >
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '1.2rem' }}>✨</span>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '700', color: '#ffffff' }}>
              AI Security Advisory Consultation
            </h3>
          </div>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '4px 10px', fontSize: '0.8rem' }}
            onClick={onClose}
            id="btn-close-ai-modal"
          >
            ✕
          </button>
        </div>

        {/* Modal Content */}
        <div style={{ padding: '20px', overflowY: 'auto', flex: 1 }}>
          <div style={{ marginBottom: '14px', background: 'rgba(255, 255, 255, 0.03)', padding: '12px', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Target Finding:</div>
            <div style={{ fontSize: '0.95rem', fontWeight: '700', color: '#38bdf8', marginTop: '2px' }}>
              {finding?.title} ({finding?.rule_id})
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginTop: '2px' }}>
              Severity: {finding?.severity} | Line: {finding?.line}
            </div>
          </div>

          {!confirmedDisclosure && !response && (
            <div style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '8px', padding: '16px', marginBottom: '16px' }}>
              <div style={{ fontWeight: '700', color: '#f59e0b', fontSize: '0.9rem', marginBottom: '6px' }}>
                🔒 Privacy & External AI Disclosure
              </div>
              <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: '1.5' }}>
                Requesting an AI explanation will send this finding description, rule ID, and sanitized evidence context to the configured server-side AI provider ({aiConfig?.provider || 'offline advisory mode'}).
                Your credentials are never sent or stored.
              </p>
              <div style={{ marginTop: '14px', display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className="btn btn-ai"
                  id="btn-confirm-ai-disclosure"
                  onClick={() => {
                    setConfirmedDisclosure(true);
                    handleGenerate();
                  }}
                  disabled={loading}
                >
                  Confirm & Request AI Advice
                </button>
                <button type="button" className="btn btn-secondary" onClick={onClose}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {loading && (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
              <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>⚙️</div>
              <p>Consulting cybersecurity knowledge base and generating remediation advice...</p>
            </div>
          )}

          {error && (
            <div style={{ padding: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '0.85rem', marginBottom: '14px' }}>
              <b>Error:</b> {error}
            </div>
          )}

          {response && (
            <div>
              {/* Security Advisory Disclaimer Banner */}
              <div style={{ background: 'rgba(139, 92, 246, 0.12)', border: '1px solid rgba(139, 92, 246, 0.3)', borderRadius: '6px', padding: '10px 14px', fontSize: '0.8rem', color: '#c4b5fd', marginBottom: '14px' }}>
                <b>Educational Disclaimer:</b> {response.disclaimer || 'Generated advisory recommendations; not verified security evidence.'}
              </div>

              {/* Mode and Provider info */}
              <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
                <span className="badge badge-info">Provider: {response.provider}</span>
                <span className="badge badge-low">Model: {response.model}</span>
              </div>

              {/* Response body */}
              <div
                id="ai-explanation-content"
                style={{
                  background: 'rgba(0, 0, 0, 0.35)',
                  padding: '16px',
                  borderRadius: '8px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.88rem',
                  lineHeight: '1.6',
                  color: '#e2e8f0',
                  whiteSpace: 'pre-wrap'
                }}
              >
                {response.explanation}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
