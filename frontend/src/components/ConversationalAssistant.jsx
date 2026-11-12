import React, { useState, useEffect, useRef } from 'react';
import { apiService } from '../services/api';
import { copyToClipboard } from '../utils/clipboard';

export function ConversationalAssistant({
  isOpen,
  onClose,
  initialFinding,
  sourceCode,
  language,
  filename,
  findings = [],
  onOpenPrSummary,
  onApplyFix
}) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: (
        'Hello! I am your **Conversational Code Assistant**, grounded in the authentic **OWASP 2026 Knowledge Base**.\n\n' +
        'You can ask me follow-up questions about your code, explain flagged vulnerabilities, request refactored code snippets, or query secure coding standards.'
      ),
      citations: []
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [appliedCodeIdx, setAppliedCodeIdx] = useState(null);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const extractFirstCodeBlock = (text) => {
    if (!text) return null;
    const match = text.match(/```(?:[a-zA-Z0-9_-]+)?\n([\s\S]*?)```/);
    return match ? match[1].trim() : null;
  };

  const scrollToBottom = () => {
    if (typeof messagesEndRef.current?.scrollIntoView === 'function') {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen]);

  // When initialFinding changes and assistant opens, add a greeting tailored to the finding
  useEffect(() => {
    if (initialFinding && isOpen) {
      const prompt = `I noticed finding **${initialFinding.rule_id}**: *"${initialFinding.title}"* at Line ${initialFinding.line}. How can I help you remediate this issue?`;
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: prompt,
          citations: initialFinding.owasp_references ? initialFinding.owasp_references.map(url => ({
            title: initialFinding.title,
            section: 'Finding Context',
            url,
            score: 0.95
          })) : []
        }
      ]);
    }
  }, [initialFinding, isOpen]);

  if (!isOpen) return null;

  const handleSendMessage = async (textToSend) => {
    const query = (textToSend || inputValue).trim();
    if (!query || isLoading) return;

    const userMessage = { role: 'user', content: query };
    const newHistory = [...messages, userMessage];
    setMessages(newHistory);
    setInputValue('');
    setIsLoading(true);

    try {
      const responseData = await apiService.chatWithAssistant(
        query,
        newHistory.map((m) => ({ role: m.role, content: m.content })),
        {
          language,
          filename,
          source_code: sourceCode ? sourceCode.substring(0, 1500) : '',
          findings: findings.slice(0, 8),
          selected_finding: initialFinding
        }
      );

      const assistantMessage = {
        role: 'assistant',
        content: responseData.response || 'I have analyzed your query based on OWASP secure coding guidelines.',
        citations: responseData.citations || [],
        provider: responseData.provider,
        model: responseData.model
      };

      setMessages((curr) => [...curr, assistantMessage]);
    } catch (err) {
      setMessages((curr) => [
        ...curr,
        {
          role: 'assistant',
          content: `⚠️ Failed to get response: ${err.message}. Please check that the backend is running.`,
          citations: []
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleCopyMessage = async (text, idx) => {
    if (!text) return;
    const success = await copyToClipboard(text);
    if (success) {
      setCopiedIndex(idx);
      setTimeout(() => setCopiedIndex(null), 2500);
    }
  };

  const starterCards = [
    {
      icon: '🚨',
      title: 'Explain P0 Blocker Findings',
      desc: 'Deep-dive into Critical vulnerabilities, exploit paths, and immediate threats.',
      prompt: 'Explain P0 blocker security vulnerabilities in this code and how attackers can exploit them.'
    },
    {
      icon: '💉',
      title: 'Fix SQL Injection Flaws',
      desc: 'Generate parameterized query refactorings and safe prepared statement patterns.',
      prompt: 'How do I fix SQL injection in this code? Show corrected code examples with placeholders.'
    },
    {
      icon: '🔑',
      title: 'Secrets Management Best Practices',
      desc: 'Migrate hardcoded credentials into secure environment variables and vault stores.',
      prompt: 'What are secrets management best practices for this application to avoid hardcoded credentials?'
    },
    {
      icon: '🧹',
      title: 'Refactor Code Smells & Complexity',
      desc: 'Reduce cyclomatic complexity, decompose long methods, and enhance maintainability.',
      prompt: 'Show refactoring to clean up code smells, complexity issues, and maintainability concerns.'
    }
  ];

  const quickPrompts = [
    'Explain P0 blocker security vulnerabilities',
    'How do I fix SQL injection in this code?',
    'What are secrets management best practices?',
    'Show refactoring to clean up code smells'
  ];

  const hasOnlyInitialMessage = messages.length <= 1;

  return (
    <div className="modal-backdrop" onClick={onClose} style={{ zIndex: 1200 }}>
      <div
        className="glass-panel modal-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '92%',
          maxWidth: '980px',
          height: 'min(86vh, 820px)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}
      >
        {/* Header */}
        <div className="modal-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '1.45rem' }}>🤖</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: '800', color: '#ffffff', letterSpacing: '-0.01em' }}>
                Conversational Code Assistant
              </h2>
              <span
                className="badge"
                style={{
                  background: 'rgba(6, 182, 212, 0.15)',
                  color: 'var(--accent-cyan)',
                  border: '1px solid rgba(6, 182, 212, 0.35)',
                  fontSize: '0.72rem'
                }}
              >
                RAG Grounded &bull; OWASP 2026
              </span>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Target: <code>{filename || 'active_file'}</code> ({language?.toUpperCase() || 'PYTHON'}) &bull; Grounded in OWASP Knowledge Base
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setMessages([{
                role: 'assistant',
                content: 'Chat history reset. How can I help you with your code?',
                citations: []
              }])}
              style={{ fontSize: '0.76rem', padding: '5px 12px' }}
              title="Reset conversation"
            >
              🔄 Clear
            </button>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                color: '#94a3b8',
                fontSize: '1.1rem',
                cursor: 'pointer',
                padding: '6px 12px',
                lineHeight: 1
              }}
              title="Close (Esc)"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Finding Context Banner if active */}
        {initialFinding && (
          <div
            style={{
              padding: '12px 24px',
              background: 'linear-gradient(90deg, rgba(6, 182, 212, 0.12), rgba(99, 102, 241, 0.12))',
              borderBottom: '1px solid rgba(6, 182, 212, 0.25)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              fontSize: '0.82rem',
              flexShrink: 0
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <span style={{ fontWeight: '700', color: 'var(--accent-cyan)' }}>🎯 Focusing on Finding:</span>{' '}
                <span style={{ color: '#ffffff', fontWeight: '600' }}>{initialFinding.rule_id} &bull; Line {initialFinding.line}</span> &mdash; {initialFinding.title}
              </div>
              <span className="badge badge-critical" style={{ fontSize: '0.7rem' }}>
                {initialFinding.severity}
              </span>
            </div>

            {initialFinding.evidence && (
              <div
                style={{
                  background: 'rgba(0, 0, 0, 0.35)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '6px',
                  padding: '6px 10px',
                  fontSize: '0.78rem',
                  color: '#f87171',
                  fontFamily: 'var(--font-mono)',
                  overflowX: 'auto'
                }}
              >
                <code>- [Line {initialFinding.line}] {initialFinding.evidence}</code>
              </div>
            )}

            {/* Quick Action Prompt Chips for focused finding */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: '600' }}>Quick Actions:</span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => handleSendMessage(`Explain the root cause and exploitation vector of ${initialFinding.rule_id} (${initialFinding.title}) at line ${initialFinding.line}.`)}
                style={{ fontSize: '0.72rem', padding: '3px 10px', borderRadius: '12px' }}
              >
                ⚡ Explain Root Cause
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => handleSendMessage(`Provide the exact corrected code snippet to safely refactor ${initialFinding.rule_id} at line ${initialFinding.line}.`)}
                style={{ fontSize: '0.72rem', padding: '3px 10px', borderRadius: '12px' }}
              >
                🛡️ Generate Remediation Fix
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => handleSendMessage(`Generate a unit test in ${language || 'Python'} that validates ${initialFinding.rule_id} is securely fixed.`)}
                style={{ fontSize: '0.72rem', padding: '3px 10px', borderRadius: '12px' }}
              >
                🧪 Generate Unit Test
              </button>
            </div>
          </div>
        )}

        {/* Scrollable Message List / Interactive Dashboard */}
        <div
          className="modal-body"
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '20px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px'
          }}
        >
          {/* Messages */}
          {messages.map((msg, idx) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  gap: '12px',
                  alignSelf: isUser ? 'flex-end' : 'flex-start',
                  maxWidth: isUser ? '82%' : '90%'
                }}
              >
                {!isUser && (
                  <div
                    style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '50%',
                      background: 'linear-gradient(135deg, #06b6d4, #6366f1)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '1rem',
                      flexShrink: 0,
                      marginTop: '2px',
                      boxShadow: '0 0 12px rgba(6, 182, 212, 0.35)'
                    }}
                  >
                    🛡️
                  </div>
                )}

                <div
                  style={{
                    background: isUser
                      ? 'linear-gradient(135deg, #0284c7, #0369a1)'
                      : 'rgba(15, 23, 42, 0.95)',
                    border: isUser ? 'none' : '1px solid var(--border-subtle)',
                    padding: '14px 18px',
                    borderRadius: isUser ? '16px 16px 2px 16px' : '16px 16px 16px 2px',
                    color: '#f8fafc',
                    fontSize: '0.88rem',
                    lineHeight: '1.55',
                    position: 'relative',
                    boxShadow: '0 4px 16px rgba(0, 0, 0, 0.25)'
                  }}
                >
                  {/* Message Content */}
                  <div style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>
                    {msg.content}
                  </div>

                  {/* Grounding Citations */}
                  {!isUser && msg.citations && msg.citations.length > 0 && (
                    <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', fontSize: '0.78rem' }}>
                      <div style={{ color: 'var(--text-dim)', fontWeight: '700', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        📚 OWASP Grounding Citations:
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {msg.citations.map((c, cIdx) => (
                          <a
                            key={cIdx}
                            href={c.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              background: 'rgba(255, 255, 255, 0.05)',
                              padding: '3px 10px',
                              borderRadius: '6px',
                              color: 'var(--accent-cyan)',
                              textDecoration: 'none',
                              border: '1px solid rgba(6, 182, 212, 0.3)',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              transition: 'all 0.2s ease'
                            }}
                          >
                            🔗 {c.title} {c.section ? `(${c.section})` : ''}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Extracted Code Block Actions */}
                  {!isUser && (() => {
                    const codeSnippet = extractFirstCodeBlock(msg.content);
                    if (!codeSnippet) return null;
                    return (
                      <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <button
                          type="button"
                          onClick={() => handleCopyMessage(codeSnippet, `code-${idx}`)}
                          style={{
                            background: 'rgba(56, 189, 248, 0.12)',
                            border: '1px solid rgba(56, 189, 248, 0.3)',
                            borderRadius: '4px',
                            color: '#7dd3fc',
                            fontSize: '0.74rem',
                            padding: '3px 8px',
                            cursor: 'pointer',
                            fontWeight: '600'
                          }}
                        >
                          {copiedIndex === `code-${idx}` ? '✅ Copied Code' : '📋 Copy Code Snippet'}
                        </button>
                        {onApplyFix && initialFinding && (
                          <button
                            type="button"
                            onClick={() => {
                              onApplyFix(initialFinding, codeSnippet);
                              setAppliedCodeIdx(idx);
                              setTimeout(() => setAppliedCodeIdx(null), 2500);
                            }}
                            style={{
                              background: 'rgba(6, 182, 212, 0.15)',
                              border: '1px solid rgba(6, 182, 212, 0.4)',
                              borderRadius: '4px',
                              color: 'var(--accent-cyan)',
                              fontSize: '0.74rem',
                              padding: '3px 8px',
                              cursor: 'pointer',
                              fontWeight: '600'
                            }}
                          >
                            {appliedCodeIdx === idx ? '⚡ Applied to Editor!' : '⚡ Apply to Editor'}
                          </button>
                        )}
                      </div>
                    );
                  })()}

                  {/* Copy message button */}
                  {!isUser && (
                    <button
                      type="button"
                      onClick={() => handleCopyMessage(msg.content, idx)}
                      style={{
                        position: 'absolute',
                        top: '10px',
                        right: '10px',
                        background: 'rgba(255, 255, 255, 0.06)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '4px',
                        color: 'var(--text-dim)',
                        cursor: 'pointer',
                        fontSize: '0.72rem',
                        padding: '2px 6px'
                      }}
                      title="Copy response"
                    >
                      {copiedIndex === idx ? '✅ Copied' : '📋 Copy'}
                    </button>
                  )}
                </div>
              </div>
            );
          })}

          {/* When conversation is starting, show the 2x2 Suggested Prompt Cards so there is NO EMPTY SPACE */}
          {hasOnlyInitialMessage && (
            <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ fontSize: '0.82rem', fontWeight: '700', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                💡 Suggested Explorations &amp; Fast Remediations
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '10px' }}>
                {starterCards.map((card, cIdx) => (
                  <button
                    key={cIdx}
                    type="button"
                    onClick={() => handleSendMessage(card.prompt)}
                    style={{
                      textAlign: 'left',
                      background: 'rgba(255, 255, 255, 0.03)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      borderRadius: '10px',
                      padding: '12px 16px',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '12px'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.4)';
                      e.currentTarget.style.background = 'rgba(6, 182, 212, 0.06)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                      e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                    }}
                  >
                    <span style={{ fontSize: '1.4rem' }}>{card.icon}</span>
                    <div>
                      <div style={{ fontWeight: '700', fontSize: '0.88rem', color: '#f1f5f9' }}>
                        {card.title}
                      </div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px', lineHeight: 1.4 }}>
                        {card.desc}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {isLoading && (
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', color: 'var(--accent-cyan)', fontSize: '0.85rem', padding: '8px 0' }}>
              <span style={{ fontSize: '1.2rem', animation: 'spin 1.5s linear infinite' }}>⚡</span>
              <span>Grounding in OWASP Knowledge Base &amp; synthesizing expert remediation...</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Modal Enclosed Footer: Quick Chips + Input Bar */}
        <div
          className="modal-footer"
          style={{
            flexDirection: 'column',
            alignItems: 'stretch',
            gap: '10px',
            padding: '14px 24px',
            background: 'rgba(9, 14, 26, 0.98)'
          }}
        >
          {/* Quick prompt chips */}
          <div style={{ display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '2px' }}>
            {(messages.length > 1
              ? [
                  'Show unit test for this fix',
                  'Explain edge cases & security risks',
                  'What is the OWASP standard for this?',
                  ...quickPrompts
                ]
              : quickPrompts
            ).map((prompt, pIdx) => (
              <button
                key={pIdx}
                type="button"
                className="btn btn-secondary"
                onClick={() => handleSendMessage(prompt)}
                style={{
                  fontSize: '0.74rem',
                  padding: '4px 12px',
                  whiteSpace: 'nowrap',
                  borderRadius: '16px',
                  background: 'rgba(255, 255, 255, 0.04)',
                  borderColor: 'rgba(255, 255, 255, 0.08)'
                }}
              >
                💡 {prompt}
              </button>
            ))}
          </div>

          {/* Input & Send Button */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <textarea
              ref={inputRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about vulnerabilities, remediation, clean code, or OWASP guidelines (Enter to send)..."
              rows={2}
              style={{
                flex: 1,
                background: '#070b14',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                padding: '10px 14px',
                color: '#ffffff',
                fontFamily: 'var(--font-sans)',
                fontSize: '0.88rem',
                resize: 'none',
                outline: 'none',
                lineHeight: 1.4
              }}
            />
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => handleSendMessage()}
              disabled={isLoading || !inputValue.trim()}
              style={{ padding: '0 22px', height: '52px', minWidth: '96px', fontWeight: '700' }}
            >
              {isLoading ? '...' : 'Send 🚀'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
