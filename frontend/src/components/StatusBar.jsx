import React from 'react';

export function StatusBar({ health, onRefresh, loading }) {
  const isHealthy = health?.status === 'healthy';
  const javaAvailable = health?.java_compiler?.available;
  const kbReady = health?.knowledge_base?.status === 'ready';
  const aiConfigured = health?.ai_integration?.configured;

  return (
    <div className="status-bar-container" id="system-status-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        {/* Backend API status */}
        <div className="status-pill" id="pill-backend-status">
          <span className={`status-dot ${isHealthy ? 'active' : 'danger'}`}></span>
          <span>API: {isHealthy ? 'Operational (Online)' : 'Backend Offline'}</span>
        </div>

        {/* Java Compiler status */}
        <div className="status-pill" id="pill-java-compiler">
          <span className={`status-dot ${javaAvailable ? 'active' : 'warn'}`}></span>
          <span>
            javac: {javaAvailable ? (health?.java_compiler?.version?.split('\n')[0] || 'Ready') : 'Compiler Unavailable'}
          </span>
        </div>

        {/* Knowledge Base status */}
        <div className="status-pill" id="pill-knowledge-base">
          <span className={`status-dot ${kbReady ? 'active' : 'warn'}`}></span>
          <span>
            OWASP Vector Index: {kbReady ? `${health?.knowledge_base?.chunks_count} Chunks Loaded` : 'Unindexed'}
          </span>
        </div>

        {/* AI Integration status */}
        <div className="status-pill" id="pill-ai-status">
          <span className={`status-dot ${aiConfigured ? 'active' : 'warn'}`}></span>
          <span>
            AI: {aiConfigured ? `${health?.ai_integration?.provider?.toUpperCase()} (${health?.ai_integration?.model})` : 'Offline Advisory'}
          </span>
        </div>
      </div>

      <button
        id="btn-refresh-status"
        type="button"
        className="btn btn-secondary"
        style={{ padding: '4px 12px', fontSize: '0.78rem' }}
        onClick={onRefresh}
        disabled={loading}
      >
        {loading ? 'Refreshing...' : '↻ Ping Services'}
      </button>
    </div>
  );
}
