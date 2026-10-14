import React from 'react';

export function Header() {
  return (
    <header className="app-header" id="main-header">
      <div className="app-brand">
        <div className="brand-icon">
          <span>🛡️</span>
        </div>
        <div>
          <h1 className="brand-title">Smart Code Inspection Platform</h1>
          <p className="brand-subtitle">Vulnerability Detection System & OWASP Compliance Engine</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
        <div className="badge badge-info" style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
          <span>11 Deterministic Rules</span>
        </div>
        <div className="badge badge-low" style={{ fontSize: '0.8rem', padding: '6px 12px' }}>
          <span>6 OWASP Standards</span>
        </div>
        <div className="badge" style={{ background: 'rgba(255, 255, 255, 0.05)', color: '#cbd5e1', fontSize: '0.8rem', padding: '6px 12px' }}>
          <span>Python & Java AST</span>
        </div>
      </div>
    </header>
  );
}
