import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { RadarChart } from './components/RadarChart';

describe('6-Dimensional Code Quality Radar Chart Component', () => {
  it('renders RadarChart title and all 6 dimensions in idle state', () => {
    render(<RadarChart hasScanned={false} />);

    expect(screen.getByText(/6-Dimensional Code Quality Radar/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Code Quality/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Security/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Complexity/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Maintainability/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Best Practices/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Input Validation/i).length).toBeGreaterThan(0);
  });

  it('renders dynamic scores accurately when radarScores is provided', () => {
    const radarScores = {
      'Code Quality': 95,
      'Security': 60,
      'Complexity': 80,
      'Maintainability': 90,
      'Best Practices': 70,
      'Input Validation': 50,
    };
    const dimensionDetails = {
      'Security': { score: 60, findings_count: 2, total_deduction: 40, status: 'Needs Improvement', contributing_findings: [] },
    };

    render(
      <RadarChart
        radarScores={radarScores}
        dimensionDetails={dimensionDetails}
        hasScanned={true}
        overallHealth={74}
      />
    );

    expect(screen.getByText('74/100')).toBeInTheDocument();
    expect(screen.getByText('Finding-Driven')).toBeInTheDocument();
    // Check score indicators on chart
    expect(screen.getByText('60/100')).toBeInTheDocument();
    expect(screen.getByText('95/100')).toBeInTheDocument();
    expect(screen.getByText('50/100')).toBeInTheDocument();
  });

  it('displays loading spinner overlay when isAnalyzing is true', () => {
    render(<RadarChart isAnalyzing={true} />);
    expect(screen.getByText(/Calculating Radar Dimensions.../i)).toBeInTheDocument();
  });

  it('falls back to computing radar scores from raw findings when radarScores is omitted', () => {
    const findings = [
      { rule_id: 'SEC-PY-001', message: 'SQL injection defect', severity: 'Critical' },
      { rule_id: 'SMELL-PY-001', message: 'Long method smell', severity: 'Low' },
    ];

    render(<RadarChart findings={findings} hasScanned={true} />);

    // Scores must be finding-driven and rendered
    expect(screen.getByText(/Finding-Driven/i)).toBeInTheDocument();
  });

  it('allows clicking a dimension to inspect detailed breakdown and return to overview', () => {
    const dimensionDetails = {
      'Security': {
        score: 65,
        findings_count: 1,
        total_deduction: 35,
        status: 'Needs Improvement',
        contributing_findings: [
          { rule_id: 'SEC-PY-001', line: 12, deduction: 35, message: 'Unsanitized user SQL query' }
        ]
      }
    };

    render(
      <RadarChart
        radarScores={{ 'Security': 65 }}
        dimensionDetails={dimensionDetails}
        hasScanned={true}
      />
    );

    // Click on Security dimension card in overview grid
    const securityCard = screen.getAllByText('Security')[0];
    fireEvent.click(securityCard);

    // Verify detail view opens
    expect(screen.getByText(/Dimension: Security/i)).toBeInTheDocument();
    expect(screen.getByText(/Unsanitized user SQL query/i)).toBeInTheDocument();

    // Click View All to return to overview
    const viewAllBtn = screen.getByRole('button', { name: /View All/i });
    fireEvent.click(viewAllBtn);
    expect(screen.getByText(/Six-Dimension Overview/i)).toBeInTheDocument();
  });

  it('collapses and expands cleanly upon clicking collapse button', () => {
    render(<RadarChart hasScanned={true} />);

    const collapseBtn = screen.getByRole('button', { name: /▲ Collapse/i });
    fireEvent.click(collapseBtn);

    expect(screen.getByRole('button', { name: /▼ Expand/i })).toBeInTheDocument();
    // Chart SVG is collapsed
    expect(screen.queryByText(/Six-Dimension Overview/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /▼ Expand/i }));
    expect(screen.getByText(/Six-Dimension Overview/i)).toBeInTheDocument();
  });

  it('dynamically adapts radar to 100/100 across all 6 dimensions when all issues are resolved', () => {
    const perfectRadarScores = {
      'Code Quality': 100,
      'Security': 100,
      'Complexity': 100,
      'Maintainability': 100,
      'Best Practices': 100,
      'Input Validation': 100,
    };

    render(
      <RadarChart
        radarScores={perfectRadarScores}
        findings={[]}
        hasScanned={true}
        overallHealth={100}
      />
    );

    expect(screen.getAllByText('100/100').length).toBeGreaterThanOrEqual(6);
    expect(screen.getAllByText('Clean (0 issues)').length).toBe(6);
  });
});
