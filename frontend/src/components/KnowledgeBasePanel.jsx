import React, { useState } from 'react';
import { apiService } from '../services/api';

export function KnowledgeBasePanel() {
  const [query, setQuery] = useState('SQL injection prepared statements');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [error, setError] = useState(null);

  const handleSearch = async (e) => {
    e?.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const data = await apiService.searchKnowledge(query.trim(), 4);
      setResults(data.results || []);
      setHasSearched(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px' }} id="knowledge-base-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff' }}>
            OWASP Knowledge Retrieval
          </h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Vector Space Cosine Retrieval from official OWASP standards & cheat sheets
          </p>
        </div>

        <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.1)', color: 'var(--accent-cyan)' }}>
          Vector Space Model
        </span>
      </div>

      {/* Search Input Bar */}
      <form onSubmit={handleSearch} style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
        <input
          id="input-knowledge-query"
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search OWASP standards (e.g. command injection, deserialization, XSS)..."
          style={{
            flex: 1,
            padding: '10px 14px',
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            color: '#f1f5f9',
            fontSize: '0.88rem',
            outline: 'none'
          }}
        />
        <button
          id="btn-search-knowledge"
          type="submit"
          className="btn btn-primary"
          disabled={loading || !query.trim()}
          style={{ minWidth: '110px' }}
        >
          {loading ? 'Searching...' : '🔎 Query'}
        </button>
      </form>

      {error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171', fontSize: '0.82rem', marginBottom: '12px' }}>
          {error}
        </div>
      )}

      {/* Results List */}
      {hasSearched && results.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
          No OWASP guidance matched this query with sufficient similarity score.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {results.map((res, idx) => (
            <div
              key={res.chunk_id || idx}
              style={{
                background: 'rgba(10, 15, 28, 0.7)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '14px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontWeight: '600', color: '#38bdf8', fontSize: '0.9rem' }}>
                  {res.title}
                </span>
                <span className="badge badge-low" style={{ fontSize: '0.72rem' }}>
                  Similarity: {res.similarity_score}
                </span>
              </div>

              <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginBottom: '6px' }}>
                Section: {res.section} | Category: {res.category}
              </div>

              <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: '1.5', whiteSpace: 'pre-wrap' }}>
                {res.text}
              </p>

              {res.url && (
                <div style={{ marginTop: '8px' }}>
                  <a
                    href={res.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: 'var(--accent-cyan)', fontSize: '0.78rem', textDecoration: 'none' }}
                  >
                    🔗 Official Source: {res.url}
                  </a>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
