import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from './App';
import { apiService } from './services/api';

vi.mock('./services/api', () => ({
  apiService: {
    getHealth: vi.fn(),
    validateCode: vi.fn(),
    analyzeCode: vi.fn(),
    searchKnowledge: vi.fn(),
    explainWithAI: vi.fn(),
    downloadPdfReport: vi.fn(),
  }
}));

describe('Smart Code Inspection Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiService.getHealth.mockResolvedValue({
      status: 'healthy',
      service: 'Smart Code Inspection Platform API',
      java_compiler: { available: true, version: 'javac 25.0.4.1' },
      knowledge_base: { status: 'ready', chunks_count: 56 },
      ai_integration: { configured: false, provider: 'none', advisory_mode: 'offline' }
    });
  });

  it('renders application header, status bar, and inspection action buttons', async () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: /Smart Code Inspection Platform/i, level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/Vulnerability Detection System/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Validate Syntax/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Inspect & Analyze/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export PDF Report/i })).toBeInTheDocument();


    await waitFor(() => {
      expect(apiService.getHealth).toHaveBeenCalledTimes(1);
    });
  });

  it('allows language switching between Python and Java', async () => {
    render(<App />);

    await act(async () => {
      const javaTab = screen.getByRole('button', { name: /Java \(javac\)/i });
      fireEvent.click(javaTab);
    });

    expect(screen.getByDisplayValue(/LegacyPortalService\.java/i)).toBeInTheDocument();

    await act(async () => {
      const pythonTab = screen.getByRole('button', { name: /Python \(AST\)/i });
      fireEvent.click(pythonTab);
    });

    expect(screen.getByDisplayValue(/vulnerable_service\.py/i)).toBeInTheDocument();
  });

  it('triggers syntax validation and displays compiler diagnostics', async () => {
    apiService.validateCode.mockResolvedValueOnce({
      valid_syntax: false,
      language: 'python',
      message: 'Syntax validation failed with errors.',
      diagnostics: [
        { severity: 'error', line: 12, column: 5, message: 'invalid syntax: unexpected EOF', evidence: 'def broken(' }
      ]
    });

    render(<App />);

    const validateBtn = screen.getByRole('button', { name: /Validate Syntax/i });
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(apiService.validateCode).toHaveBeenCalled();
      expect(screen.getByText(/Syntax \/ Compilation Diagnostics Reported/i)).toBeInTheDocument();
      expect(screen.getByText(/invalid syntax: unexpected EOF/i)).toBeInTheDocument();
    });
  });

  it('triggers security inspection and presents vulnerability findings', async () => {
    apiService.analyzeCode.mockResolvedValueOnce({
      valid_syntax: true,
      language: 'python',
      filename: 'vulnerable_service.py',
      total_lines: 30,
      total_bytes: 600,
      message: 'Inspection complete.',
      diagnostics: [],
      summary: {
        total_findings: 1,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0
      },
      findings: [
        {
          rule_id: 'SEC-PY-001',
          title: 'Unsafe Dynamic Code Execution via eval()',
          severity: 'Critical',
          owasp_category: 'A03:2021-Injection',
          line: 14,
          evidence: 'eval(user_param)',
          risk_explanation: 'Arbitrary code execution flaw.',
          mitigation: 'Use ast.literal_eval() instead.',
          owasp_references: ['https://owasp.org/www-project-top-ten/']
        }
      ]
    });

    render(<App />);

    const analyzeBtn = screen.getByRole('button', { name: /Inspect & Analyze/i });
    fireEvent.click(analyzeBtn);

    await waitFor(() => {
      expect(apiService.analyzeCode).toHaveBeenCalled();
      expect(screen.getByText(/Unsafe Dynamic Code Execution via eval\(\)/i)).toBeInTheDocument();
      expect(screen.getByText(/SEC-PY-001/i)).toBeInTheDocument();
      expect(screen.getByText(/A03:2021-Injection/i)).toBeInTheDocument();
      expect(screen.getByText(/Arbitrary code execution flaw/i)).toBeInTheDocument();
    });
  });

  it('triggers knowledge base retrieval and displays passages with similarity scores', async () => {
    apiService.searchKnowledge.mockResolvedValueOnce({
      query: 'SQL injection',
      total_results: 1,
      results: [
        {
          chunk_id: 'sql_1',
          title: 'OWASP SQL Injection Prevention Cheat Sheet',
          category: 'Cheat Sheet',
          section: 'Primary Defenses',
          similarity_score: 0.3842,
          text: 'Defense Option 1: Prepared Statements (with Parameterized Queries)...',
          url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        }
      ]
    });

    render(<App />);

    const searchBtn = screen.getByRole('button', { name: /Query/i });
    fireEvent.click(searchBtn);

    await waitFor(() => {
      expect(apiService.searchKnowledge).toHaveBeenCalled();
      expect(screen.getByText(/OWASP SQL Injection Prevention Cheat Sheet/i)).toBeInTheDocument();
      expect(screen.getByText(/Similarity: 0.3842/i)).toBeInTheDocument();
      expect(screen.getByText(/Prepared Statements/i)).toBeInTheDocument();
    });
  });

  it('triggers PDF report export', async () => {
    apiService.downloadPdfReport.mockResolvedValueOnce(true);

    render(<App />);

    const pdfBtn = screen.getByRole('button', { name: /Export PDF Report/i });
    fireEvent.click(pdfBtn);

    await waitFor(() => {
      expect(apiService.downloadPdfReport).toHaveBeenCalled();
    });
  });

  it('gracefully degrades when backend is offline', async () => {
    apiService.getHealth.mockResolvedValueOnce({
      status: 'offline',
      java_compiler: { available: false },
      knowledge_base: { status: 'offline' },
      ai_integration: { configured: false }
    });

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Backend Offline/i)).toBeInTheDocument();
    });
  });
});
