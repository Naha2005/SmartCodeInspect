import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { PRSummaryModal } from './components/PRSummaryModal';
import { ConversationalAssistant } from './components/ConversationalAssistant';
import { FindingsPanel } from './components/FindingsPanel';
import { EditorPanel } from './components/EditorPanel';
import { apiService } from './services/api';

vi.mock('./services/api', () => ({
  apiService: {
    chatWithAssistant: vi.fn(),
    remediateFinding: vi.fn(),
    generatePrSummary: vi.fn(),
  }
}));

describe('AI Code Review, Remediation & Conversational Assistant Suite', () => {
  it('renders PRSummaryModal with verdict, health score, and prioritized action items', async () => {
    const mockPrSummary = {
      filename: 'test_service.py',
      language: 'python',
      overall_health_score: 55,
      code_quality_score: 80,
      security_posture: 'F (Critical Vulnerabilities Detected)',
      verdict: {
        decision: 'CHANGES_REQUESTED',
        label: '🔴 Changes Requested',
        reason: 'Critical vulnerabilities detected. Blocked from merge.'
      },
      severity_breakdown: { critical: 1, high: 1, medium: 0, low: 0, total: 2 },
      prioritized_fix_list: {
        p0_blockers: [
          {
            line: 12,
            rule_id: 'SEC-PY-001',
            title: 'eval() execution',
            recommendation: 'Use ast.literal_eval()',
            corrected_code: 'import ast\nast.literal_eval(val)'
          }
        ],
        p1_important: [],
        p2_maintainability: []
      },
      merge_checklist: ['Resolve Line 12: eval() execution'],
      markdown: '## 📋 PR Review Markdown'
    };

    const onClose = vi.fn();
    render(
      <PRSummaryModal
        prSummary={mockPrSummary}
        filename="test_service.py"
        language="python"
        onClose={onClose}
      />
    );

    expect(screen.getByText(/Pull Request Code Review & Audit Summary/i)).toBeInTheDocument();
    expect(screen.getByText(/🔴 Changes Requested/i)).toBeInTheDocument();
    expect(screen.getAllByText(/55/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Resolve Line 12: eval\(\) execution/i)).toBeInTheDocument();

    // Verify Copy PR Markdown button functions
    const copyBtns = screen.getAllByRole('button', { name: /Copy PR Markdown/i });
    expect(copyBtns.length).toBeGreaterThan(0);
    fireEvent.click(copyBtns[0]);
    await waitFor(() => {
      expect(screen.getAllByText(/Copied/i).length).toBeGreaterThan(0);
    });
  });

  it('renders ConversationalAssistant and handles user query with RAG citations', async () => {
    apiService.chatWithAssistant.mockResolvedValueOnce({
      success: true,
      response: 'Use parameterized queries with ? placeholders to prevent SQL injection.',
      citations: [
        {
          title: 'OWASP SQL Injection Prevention Cheat Sheet',
          section: 'Prepared Statements',
          url: 'https://cheatsheetseries.owasp.org',
          score: 0.95
        }
      ],
      provider: 'offline_rag'
    });

    const onClose = vi.fn();
    render(
      <ConversationalAssistant
        isOpen={true}
        onClose={onClose}
        sourceCode="cursor.execute('SELECT * FROM users')"
        language="python"
        filename="db.py"
      />
    );

    expect(screen.getByRole('heading', { name: /Conversational Code Assistant/i })).toBeInTheDocument();

    const input = screen.getByPlaceholderText(/Ask about vulnerabilities/i);
    fireEvent.change(input, { target: { value: 'How to fix SQL injection?' } });

    const sendBtn = screen.getByRole('button', { name: /Send/i });
    fireEvent.click(sendBtn);

    await waitFor(() => {
      expect(apiService.chatWithAssistant).toHaveBeenCalledTimes(1);
      expect(screen.getByText(/Use parameterized queries with \? placeholders/i)).toBeInTheDocument();
      expect(screen.getByText(/OWASP SQL Injection Prevention Cheat Sheet/i)).toBeInTheDocument();
    });

    // Verify Copy message button on assistant response
    const copyMsgBtns = screen.getAllByTitle(/Copy response/i);
    expect(copyMsgBtns.length).toBeGreaterThan(0);
    fireEvent.click(copyMsgBtns[copyMsgBtns.length - 1]);
    await waitFor(() => {
      expect(copyMsgBtns[copyMsgBtns.length - 1]).toHaveTextContent('✅');
    });
  });

  it('renders FindingsPanel with per-finding remediation and overall code health score', async () => {
    const mockFindings = [
      {
        rule_id: 'SEC-PY-003',
        title: 'SQL Injection via String Formatting',
        severity: 'High',
        severity_score: 8.5,
        line: 14,
        evidence: "cursor.execute(f'SELECT * FROM users WHERE name={name}')",
        risk_explanation: 'Allows attacker to execute arbitrary SQL commands.',
        mitigation: 'Use parameterized queries.',
        remediation: {
          title: 'Use Parameterized Queries with SQLite Placeholders',
          recommendation: 'Replace string formatting with ? placeholders.',
          corrected_code: 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
          best_practices: ['Use parameterized queries', 'Never concatenate SQL strings']
        }
      }
    ];

    const mockSummary = {
      total_findings: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      overall_code_health_score: 75,
      code_quality_score: 88,
      security_posture: 'C (High Findings)'
    };

    render(
      <FindingsPanel
        findings={mockFindings}
        summary={mockSummary}
        hasScanned={true}
        isAnalyzing={false}
      />
    );

    expect(screen.getByText(/Findings & Remediation Portal/i)).toBeInTheDocument();
    expect(screen.getByText(/Health: 75\/100/i)).toBeInTheDocument();
    expect(screen.getByText(/SQL Injection via String Formatting/i)).toBeInTheDocument();
    expect(screen.getByText(/Remediation Agent: Use Parameterized Queries with SQLite Placeholders/i)).toBeInTheDocument();
    expect(screen.getByText(/cursor\.execute\("SELECT \* FROM users WHERE name = \?", \(name,\)\)/i)).toBeInTheDocument();

    // Verify Copy Fix button functions
    const copyFixBtn = screen.getByRole('button', { name: /Copy Fix/i });
    fireEvent.click(copyFixBtn);
    await waitFor(() => {
      expect(screen.getByText(/Copied!/i)).toBeInTheDocument();
    });
  });

  it('handles drag-and-drop file upload on EditorPanel and triggers analysis callback', async () => {
    const onAnalyze = vi.fn();
    const setSourceCode = vi.fn();
    const setFilename = vi.fn();
    const onLanguageChange = vi.fn();

    const { container } = render(
      <EditorPanel
        language="python"
        sourceCode="def existing(): pass"
        setSourceCode={setSourceCode}
        filename="existing.py"
        setFilename={setFilename}
        onLanguageChange={onLanguageChange}
        onValidate={vi.fn()}
        onAnalyze={onAnalyze}
        onDownloadPdf={vi.fn()}
        isValidating={false}
        isAnalyzing={false}
        isGeneratingPdf={false}
      />
    );

    const editorPanel = container.querySelector('#code-editor-panel');
    expect(editorPanel).toBeInTheDocument();

    // Trigger drag enter and over
    fireEvent.dragEnter(editorPanel, {
      dataTransfer: {
        items: [{ kind: 'file', type: 'text/x-python' }],
        types: ['Files']
      }
    });

    fireEvent.dragOver(editorPanel, {
      dataTransfer: {
        dropEffect: 'copy',
        types: ['Files']
      }
    });

    // Create a mock dropped file
    const droppedFile = new File(['import os\nos.system("ls")\n'], 'dropped_script.py', {
      type: 'text/x-python'
    });

    fireEvent.drop(editorPanel, {
      dataTransfer: {
        files: [droppedFile],
        types: ['Files']
      }
    });

    await waitFor(() => {
      expect(setFilename).toHaveBeenCalledWith('dropped_script.py');
      expect(setSourceCode).toHaveBeenCalledWith('import os\nos.system("ls")\n');
      expect(onAnalyze).toHaveBeenCalledWith('python', 'import os\nos.system("ls")\n', 'dropped_script.py');
    });
  });

  it('handles interactive merge checklist toggle, progress bar, and markdown download in PRSummaryModal', async () => {
    const mockPrSummary = {
      filename: 'auth.py',
      language: 'python',
      overall_health_score: 60,
      code_quality_score: 85,
      security_posture: 'F',
      verdict: {
        decision: 'CHANGES_REQUESTED',
        label: '🔴 Changes Requested',
        reason: 'Blocker findings found'
      },
      severity_breakdown: { critical: 1, high: 0, medium: 1, low: 0, total: 2 },
      prioritized_fix_list: {
        p0_blockers: [
          {
            line: 10,
            rule_id: 'SEC-PY-004',
            title: 'Hardcoded Secret',
            recommendation: 'Use os.getenv()',
            corrected_code: 'import os\nAPI_KEY = os.getenv("API_KEY")'
          }
        ],
        p1_important: [
          {
            line: 25,
            rule_id: 'DESIGN-PY-001',
            title: 'Mutable default',
            recommendation: 'Use None'
          }
        ]
      },
      merge_checklist: ['Item 1: Resolve secret', 'Item 2: Fix default']
    };

    const onApplyFix = vi.fn();
    render(
      <PRSummaryModal
        prSummary={mockPrSummary}
        filename="auth.py"
        language="python"
        onClose={vi.fn()}
        onApplyFix={onApplyFix}
      />
    );

    // Initial progress shows 0/2 (0%)
    expect(screen.getByText(/0\/2 \(0%\)/i)).toBeInTheDocument();

    // Check first item
    const checkboxes = screen.getAllByRole('checkbox');
    expect(checkboxes.length).toBe(2);
    fireEvent.click(checkboxes[0]);

    // Progress updates to 1/2 (50%)
    expect(screen.getByText(/1\/2 \(50%\)/i)).toBeInTheDocument();

    // Switch to Prioritized Fixes tab and test P0 filter & Apply to Editor
    const fixesTab = screen.getByRole('button', { name: /Prioritized Fixes/i });
    fireEvent.click(fixesTab);

    expect(screen.getByText(/Hardcoded Secret/i)).toBeInTheDocument();
    const applyBtn = screen.getByRole('button', { name: /Apply to Editor/i });
    fireEvent.click(applyBtn);
    expect(onApplyFix).toHaveBeenCalledTimes(1);
    expect(onApplyFix).toHaveBeenCalledWith(
      expect.objectContaining({ rule_id: 'SEC-PY-004' }),
      expect.stringContaining('API_KEY = os.getenv')
    );
  });

  it('supports unified diff toggle and search filtering in FindingsPanel', async () => {
    const mockFindings = [
      {
        rule_id: 'SEC-PY-001',
        title: 'Dangerous eval()',
        severity: 'Critical',
        line: 5,
        evidence: 'eval(user_input)',
        remediation: {
          title: 'Use literal_eval',
          recommendation: 'Replace eval',
          corrected_code: 'ast.literal_eval(user_input)'
        }
      },
      {
        rule_id: 'SMELL-PY-002',
        title: 'Wildcard import',
        severity: 'Low',
        line: 1,
        evidence: 'from math import *'
      }
    ];

    const onApplyFix = vi.fn();
    render(
      <FindingsPanel
        findings={mockFindings}
        summary={{ total_findings: 2, critical: 1, low: 1 }}
        hasScanned={true}
        onApplyFix={onApplyFix}
      />
    );

    // Verify search filter
    const searchInput = screen.getByPlaceholderText(/Search findings by rule/i);
    fireEvent.change(searchInput, { target: { value: 'Wildcard' } });
    expect(screen.getByText(/Wildcard import/i)).toBeInTheDocument();
    expect(screen.queryByText(/Dangerous eval\(\)/i)).not.toBeInTheDocument();

    // Clear search
    fireEvent.change(searchInput, { target: { value: '' } });
    expect(screen.getByText(/Dangerous eval\(\)/i)).toBeInTheDocument();

    // Test Unified Diff toggle on first finding
    const diffToggle = screen.getByRole('button', { name: /Unified Diff/i });
    fireEvent.click(diffToggle);
    expect(screen.getByText(/- \[Line 5\]/i)).toBeInTheDocument();
    expect(screen.getByText(/\+ \[Remediated\]/i)).toBeInTheDocument();
    expect(screen.getByText(/ast\.literal_eval\(user_input\)/i)).toBeInTheDocument();

    // Test Apply to Editor button
    const applyBtn = screen.getByRole('button', { name: /Apply to Editor/i });
    fireEvent.click(applyBtn);
    expect(onApplyFix).toHaveBeenCalledWith(
      expect.objectContaining({ rule_id: 'SEC-PY-001' }),
      'ast.literal_eval(user_input)'
    );
  });

  it('renders code evidence snippet and quick action prompts for focused finding in ConversationalAssistant', async () => {
    const mockFinding = {
      rule_id: 'SEC-PY-003',
      title: 'SQL Injection via format',
      line: 14,
      severity: 'High',
      evidence: "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
    };

    render(
      <ConversationalAssistant
        isOpen={true}
        onClose={vi.fn()}
        initialFinding={mockFinding}
        sourceCode="cursor.execute(...)"
        language="python"
        filename="db.py"
      />
    );

    // Context banner with line and evidence
    expect(screen.getByText(/Focusing on Finding:/i)).toBeInTheDocument();
    expect(screen.getByText(/SEC-PY-003 • Line 14/i)).toBeInTheDocument();
    expect(screen.getByText(/- \[Line 14\] cursor\.execute\(f'SELECT \* FROM users WHERE id=\{uid\}'\)/i)).toBeInTheDocument();

    // Quick action buttons
    expect(screen.getByRole('button', { name: /Explain Root Cause/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Generate Remediation Fix/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Generate Unit Test/i })).toBeInTheDocument();
  });
});

