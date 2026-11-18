const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '');

/**
 * Perform a fetch with built-in JSON error parsing and timeouts
 */
async function fetchWithTimeout(resource, options = {}, timeout = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    if (error.name === 'AbortError') {
      throw new Error('Request timed out. Please verify that the backend service is running on port 5000.');
    }
    if (error.message === 'Failed to fetch' || error.name === 'TypeError') {
      throw new Error('Backend service is offline or unreachable. Please ensure the Python Flask backend is running on http://127.0.0.1:5000.');
    }
    throw error;
  }
}

export const apiService = {
  async getHealth() {
    try {
      const res = await fetchWithTimeout(`${API_BASE}/health`, { method: 'GET' }, 5000);
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      return {
        status: 'offline',
        error: err.message,
        java_compiler: { available: false, version: 'Unknown' },
        knowledge_base: { status: 'offline', chunks_count: 0 },
        ai_integration: { configured: false, provider: 'none', advisory_mode: 'offline' }
      };
    }
  },

  async validateCode(language, sourceCode, filename) {
    const res = await fetchWithTimeout(`${API_BASE}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language, source_code: sourceCode, filename })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Validation failed with status ${res.status}`);
    }
    return data;
  },

  async analyzeCode(language, sourceCode, filename) {
    const res = await fetchWithTimeout(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language, source_code: sourceCode, filename })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Analysis failed with status ${res.status}`);
    }
    return data;
  },

  async searchKnowledge(query, topK = 4) {
    const res = await fetchWithTimeout(`${API_BASE}/knowledge/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, top_k: topK })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Knowledge search failed with status ${res.status}`);
    }
    return data;
  },

  async explainWithAI(finding, owaspPassages = []) {
    const res = await fetchWithTimeout(`${API_BASE}/ai/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding, owasp_passages: owaspPassages })
    }, 25000);
    const data = await res.json();
    if (!res.ok && !data.explanation) {
      throw new Error(data.error || `AI explanation request failed with status ${res.status}`);
    }
    return data;
  },

  async chatWithAssistant(query, history = [], context = {}) {
    const res = await fetchWithTimeout(`${API_BASE}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, history, context })
    }, 25000);
    const data = await res.json();
    if (!res.ok && !data.response) {
      throw new Error(data.error || `Assistant chat request failed with status ${res.status}`);
    }
    return data;
  },

  async remediateFinding(finding, sourceCode = null, language = null) {
    const res = await fetchWithTimeout(`${API_BASE}/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding, source_code: sourceCode, language })
    }, 15000);
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `Remediation request failed with status ${res.status}`);
    }
    return data;
  },

  async generatePrSummary(findings = [], summary = {}, metadata = {}) {
    const res = await fetchWithTimeout(`${API_BASE}/pr-summary`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings, summary, metadata })
    }, 15000);
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `PR summary request failed with status ${res.status}`);
    }
    return data;
  },

  async downloadPdfReport({ analysisData, sourceCode, language, filename }) {
    const payload = {};
    if (analysisData && typeof analysisData === 'object') {
      payload.analysis_data = analysisData;
      payload.filename = filename || analysisData.filename || 'inspected_source';
      if (sourceCode) payload.source_code = sourceCode;
      if (language) payload.language = language;
    } else if (sourceCode && language) {
      payload.source_code = sourceCode;
      payload.language = language;
      payload.filename = filename || 'inspected_source';
    } else {
      throw new Error('No analysis data or source code provided for report generation.');
    }

    const res = await fetchWithTimeout(`${API_BASE}/reports/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, 20000);

    if (!res.ok) {
      const errText = await res.text();
      try {
        const jsonErr = JSON.parse(errText);
        throw new Error(jsonErr.error || 'Failed to download PDF report');
      } catch {
        throw new Error(errText || 'Failed to download PDF report');
      }
    }

    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    const safeName = (filename || 'code_inspection_report').replace(/\.[^/.]+$/, '');
    a.download = `${safeName}_security_report.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
    return true;
  },

  async downloadSarifReport({ analysisData, sourceCode, language, filename }) {
    const payload = {};
    if (analysisData && typeof analysisData === 'object') {
      payload.analysis_data = analysisData;
      payload.filename = filename || analysisData.filename || 'inspected_source';
      if (sourceCode) payload.source_code = sourceCode;
      if (language) payload.language = language;
    } else if (sourceCode && language) {
      payload.source_code = sourceCode;
      payload.language = language;
      payload.filename = filename || 'inspected_source';
    } else {
      throw new Error('No analysis data or source code provided for report generation.');
    }

    const res = await fetchWithTimeout(`${API_BASE}/reports/sarif`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, 20000);

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(errText || 'Failed to download SARIF report');
    }

    const sarifData = await res.json();
    const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: 'application/json' });
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    const safeName = (filename || 'code_inspection_report').replace(/\.[^/.]+$/, '');
    a.download = `${safeName}.sarif`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
    return true;
  }
};

export const api = apiService;
export default apiService;
