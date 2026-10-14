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

  async downloadPdfReport({ analysisData, sourceCode, language, filename }) {
    const payload = {};
    if (sourceCode && language) {
      payload.source_code = sourceCode;
      payload.language = language;
      payload.filename = filename || 'inspected_source';
    } else if (analysisData) {
      payload.analysis_data = analysisData;
      payload.filename = filename || analysisData.filename || 'inspected_source';
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
  }
};
