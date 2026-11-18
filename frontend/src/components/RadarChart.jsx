import React, { useState } from 'react';

const DIMENSIONS = [
  { key: 'Code Quality', label: 'Code Quality', angle: -90, color: '#38bdf8' },
  { key: 'Security', label: 'Security', angle: -30, color: '#f43f5e' },
  { key: 'Complexity', label: 'Complexity', angle: 30, color: '#a855f7' },
  { key: 'Maintainability', label: 'Maintainability', angle: 90, color: '#10b981' },
  { key: 'Best Practices', label: 'Best Practices', angle: 150, color: '#f59e0b' },
  { key: 'Input Validation', label: 'Input Validation', angle: 210, color: '#06b6d4' },
];

export const RadarChart = React.memo(function RadarChart({
  findings = [],
  radarScores = {},
  dimensionDetails = {},
  hasScanned = false,
  isAnalyzing = false,
  overallHealth = 100,
}) {
  const [activeDim, setActiveDim] = useState(null);
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Client-side fallback computation if backend radarScores is not provided
  const effectiveRadarScores = { ...radarScores };
  const effectiveDimensionDetails = { ...dimensionDetails };

  if (hasScanned && Object.keys(effectiveRadarScores).length === 0) {
    DIMENSIONS.forEach((dim) => {
      let deduction = 0;
      let count = 0;
      const matchedFindings = [];

      findings.forEach((f) => {
        const ruleId = String(f.rule_id || f.rule || '').toUpperCase();
        const msg = String(f.message || '').toLowerCase();
        const sev = String(f.severity || '').toUpperCase();
        const weight = sev === 'CRITICAL' ? 35 : sev === 'HIGH' ? 20 : sev === 'MEDIUM' ? 10 : 4;

        let match = false;
        if (dim.key === 'Input Validation' && (ruleId.includes('001') || ruleId.includes('002') || msg.includes('sql') || msg.includes('injection') || msg.includes('input'))) {
          match = true;
        } else if (dim.key === 'Security' && (ruleId.startsWith('SEC-') || f.agent?.includes('Security') || msg.includes('security') || msg.includes('vulnerability'))) {
          match = true;
        } else if (dim.key === 'Complexity' && (ruleId.startsWith('COMPLEX') || msg.includes('nesting') || msg.includes('complexity'))) {
          match = true;
        } else if (dim.key === 'Maintainability' && (ruleId.startsWith('DESIGN') || msg.includes('god') || msg.includes('coupling'))) {
          match = true;
        } else if (dim.key === 'Best Practices' && (ruleId.startsWith('PRACTICE') || ruleId.startsWith('RISK') || msg.includes('leak') || msg.includes('unhandled'))) {
          match = true;
        } else if (dim.key === 'Code Quality' && (ruleId.startsWith('SMELL') || msg.includes('smell') || msg.includes('naming') || msg.includes('print'))) {
          match = true;
        }

        if (match) {
          deduction += weight;
          count += 1;
          matchedFindings.push({
            rule_id: ruleId || 'ISSUE',
            line: f.line || 1,
            deduction: weight,
            message: f.message || '',
          });
        }
      });

      const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));
      effectiveRadarScores[dim.key] = score;
      effectiveDimensionDetails[dim.key] = {
        score,
        findings_count: count,
        total_deduction: deduction,
        status: score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 50 ? 'Needs Improvement' : 'Critical Attention Required',
        contributing_findings: matchedFindings.slice(0, 5),
      };
    });
  }

  // SVG parameters
  const size = 320;
  const center = size / 2;
  const radius = 105;
  const levels = [0.2, 0.4, 0.6, 0.8, 1.0];

  const getCoordinates = (angleDeg, distance) => {
    const angleRad = (angleDeg * Math.PI) / 180;
    return {
      x: center + distance * Math.cos(angleRad),
      y: center + distance * Math.sin(angleRad),
    };
  };

  // Compute points for data polygon
  const dataPoints = DIMENSIONS.map((dim) => {
    const rawScore = effectiveRadarScores[dim.key] ?? (hasScanned ? 100 : 80);
    const clampedScore = Math.max(5, Math.min(100, rawScore));
    const dist = (clampedScore / 100) * radius;
    return {
      ...dim,
      score: rawScore,
      coords: getCoordinates(dim.angle, dist),
      outerCoords: getCoordinates(dim.angle, radius + 22),
    };
  });

  const polygonPath = dataPoints.map((p) => `${p.coords.x},${p.coords.y}`).join(' ');

  const activeDetail = activeDim ? effectiveDimensionDetails[activeDim] : null;

  return (
    <div
      className="card radar-chart-container"
      style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.7) 100%)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        borderRadius: '12px',
        padding: '16px',
        marginBottom: '16px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.35)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* Header with Title and Toggle */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          cursor: 'pointer',
          userSelect: 'none',
        }}
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '1.25rem' }}>🕸️</span>
          <div>
            <h4
              style={{
                margin: 0,
                fontSize: '0.95rem',
                fontWeight: 700,
                color: '#f8fafc',
                letterSpacing: '0.02em',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              6-Dimensional Code Quality Radar
              {hasScanned && (
                <span
                  style={{
                    fontSize: '0.72rem',
                    padding: '2px 8px',
                    borderRadius: '10px',
                    background: 'rgba(56, 189, 248, 0.18)',
                    color: '#38bdf8',
                    border: '1px solid rgba(56, 189, 248, 0.4)',
                  }}
                >
                  Finding-Driven
                </span>
              )}
            </h4>
            <p style={{ margin: '2px 0 0 0', fontSize: '0.72rem', color: '#94a3b8' }}>
              Multi-axis assessment across Quality, Security, Complexity, Maintainability, Practices, & Validation
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {hasScanned && (
            <div
              style={{
                textAlign: 'right',
                padding: '4px 10px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
              }}
            >
              <span style={{ fontSize: '0.68rem', color: '#94a3b8', display: 'block' }}>COMPOSITE</span>
              <span style={{ fontSize: '0.95rem', fontWeight: 800, color: '#34d399' }}>
                {overallHealth}/100
              </span>
            </div>
          )}
          <button
            type="button"
            className="btn btn-secondary"
            style={{
              padding: '4px 8px',
              fontSize: '0.75rem',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
            }}
            onClick={(e) => {
              e.stopPropagation();
              setIsCollapsed(!isCollapsed);
            }}
          >
            {isCollapsed ? '▼ Expand' : '▲ Collapse'}
          </button>
        </div>
      </div>

      {/* Main Body */}
      {!isCollapsed && (
        <div
          style={{
            marginTop: '14px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '16px',
            alignItems: 'center',
          }}
        >
          {/* Radar Chart SVG */}
          <div
            style={{
              position: 'relative',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              minHeight: `${size}px`,
            }}
          >
            {isAnalyzing && (
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'rgba(15, 23, 42, 0.75)',
                  borderRadius: '12px',
                  zIndex: 10,
                  backdropFilter: 'blur(2px)',
                }}
              >
                <div className="spinner" style={{ width: '28px', height: '28px', marginBottom: '8px' }} />
                <span style={{ fontSize: '0.78rem', color: '#38bdf8' }}>Calculating Radar Dimensions...</span>
              </div>
            )}

            <svg
              width={size}
              height={size}
              viewBox={`0 0 ${size} ${size}`}
              style={{ overflow: 'visible', filter: 'drop-shadow(0 4px 12px rgba(0, 0, 0, 0.4))' }}
            >
              {/* Concentric Web Polygons */}
              {levels.map((level) => {
                const points = DIMENSIONS.map((dim) => {
                  const c = getCoordinates(dim.angle, radius * level);
                  return `${c.x},${c.y}`;
                }).join(' ');
                return (
                  <polygon
                    key={level}
                    points={points}
                    fill={level === 1.0 ? 'rgba(30, 41, 59, 0.35)' : 'none'}
                    stroke="rgba(148, 163, 184, 0.15)"
                    strokeWidth={level === 1.0 ? '1.5' : '1'}
                    strokeDasharray={level < 1.0 ? '2,3' : undefined}
                  />
                );
              })}

              {/* Axis Lines from Center */}
              {DIMENSIONS.map((dim) => {
                const end = getCoordinates(dim.angle, radius);
                return (
                  <line
                    key={dim.key}
                    x1={center}
                    y1={center}
                    x2={end.x}
                    y2={end.y}
                    stroke="rgba(148, 163, 184, 0.25)"
                    strokeWidth="1"
                  />
                );
              })}

              {/* Data Polygon Fill & Glow */}
              <polygon
                points={polygonPath}
                fill="url(#radarGradient)"
                stroke="#38bdf8"
                strokeWidth="2.5"
                style={{
                  transition: 'all 0.5s ease',
                  filter: 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.45))',
                }}
              />

              {/* Radial Gradient Definition */}
              <defs>
                <radialGradient id="radarGradient" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="rgba(56, 189, 248, 0.45)" />
                  <stop offset="70%" stopColor="rgba(14, 165, 233, 0.25)" />
                  <stop offset="100%" stopColor="rgba(2, 132, 199, 0.10)" />
                </radialGradient>
              </defs>

              {/* Interactive Data Vertices */}
              {dataPoints.map((pt) => {
                const isHovered = activeDim === pt.key;
                return (
                  <g
                    key={pt.key}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setActiveDim(pt.key)}
                    onClick={() => setActiveDim(activeDim === pt.key ? null : pt.key)}
                  >
                    {/* Pulsing ring on hover */}
                    {isHovered && (
                      <circle
                        cx={pt.coords.x}
                        cy={pt.coords.y}
                        r="10"
                        fill="none"
                        stroke={pt.color}
                        strokeWidth="2"
                        opacity="0.6"
                      />
                    )}
                    <circle
                      cx={pt.coords.x}
                      cy={pt.coords.y}
                      r={isHovered ? '6' : '4.5'}
                      fill={pt.color}
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      style={{ transition: 'all 0.2s ease' }}
                    />
                  </g>
                );
              })}

              {/* Axis Text Labels & Score Badges */}
              {dataPoints.map((pt) => {
                const isHovered = activeDim === pt.key;
                const score = pt.score;
                return (
                  <g
                    key={`label-${pt.key}`}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setActiveDim(pt.key)}
                    onClick={() => setActiveDim(activeDim === pt.key ? null : pt.key)}
                  >
                    <text
                      x={pt.outerCoords.x}
                      y={pt.outerCoords.y - 4}
                      textAnchor="middle"
                      fill={isHovered ? '#38bdf8' : '#cbd5e1'}
                      fontSize={isHovered ? '11px' : '10px'}
                      fontWeight={isHovered ? '700' : '600'}
                      style={{ transition: 'all 0.2s ease' }}
                    >
                      {pt.label}
                    </text>
                    <text
                      x={pt.outerCoords.x}
                      y={pt.outerCoords.y + 10}
                      textAnchor="middle"
                      fill={score >= 80 ? '#34d399' : score >= 60 ? '#fbbf24' : '#f87171'}
                      fontSize="9.5px"
                      fontWeight="700"
                    >
                      {hasScanned ? `${score}/100` : '--'}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Dimension Details & Interactive Breakdown */}
          <div
            style={{
              background: 'rgba(0, 0, 0, 0.25)',
              borderRadius: '10px',
              padding: '14px',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {activeDim ? `Dimension: ${activeDim}` : 'Six-Dimension Overview'}
              </span>
              {activeDim && (
                <button
                  type="button"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#38bdf8',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    textDecoration: 'underline',
                  }}
                  onClick={() => setActiveDim(null)}
                >
                  View All
                </button>
              )}
            </div>

            {/* Selected Dimension Detail View */}
            {activeDim && activeDetail ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px' }}>
                  <span
                    style={{
                      fontSize: '1.6rem',
                      fontWeight: 800,
                      color: activeDetail.score >= 80 ? '#34d399' : activeDetail.score >= 60 ? '#fbbf24' : '#f87171',
                    }}
                  >
                    {activeDetail.score}/100
                  </span>
                  <span
                    style={{
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      padding: '2px 8px',
                      borderRadius: '6px',
                      background: 'rgba(255, 255, 255, 0.08)',
                      color: '#f8fafc',
                    }}
                  >
                    {activeDetail.status}
                  </span>
                </div>

                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  {activeDetail.findings_count === 0 ? (
                    <span style={{ color: '#4ade80' }}>
                      ✓ No defects or security vulnerabilities identified in this dimension.
                    </span>
                  ) : (
                    <span>
                      {activeDetail.findings_count} finding(s) caused a total deduction of{' '}
                      <strong style={{ color: '#f87171' }}>-{activeDetail.total_deduction} pts</strong>.
                    </span>
                  )}
                </div>

                {/* Contributing findings snippets */}
                {activeDetail.contributing_findings && activeDetail.contributing_findings.length > 0 && (
                  <div style={{ marginTop: '6px' }}>
                    <span style={{ fontSize: '0.7rem', color: '#64748b', display: 'block', marginBottom: '4px' }}>
                      TOP CONTRIBUTING FINDINGS:
                    </span>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxHeight: '140px', overflowY: 'auto' }}>
                      {activeDetail.contributing_findings.map((cf, i) => (
                        <div
                          key={i}
                          style={{
                            background: 'rgba(255, 255, 255, 0.04)',
                            padding: '6px 8px',
                            borderRadius: '6px',
                            fontSize: '0.72rem',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                          }}
                        >
                          <div>
                            <span style={{ color: '#38bdf8', fontWeight: 600, marginRight: '6px' }}>
                              [{cf.rule_id}]
                            </span>
                            <span style={{ color: '#cbd5e1' }}>Line {cf.line}: {cf.message?.slice(0, 48)}...</span>
                          </div>
                          <span style={{ color: '#f87171', fontWeight: 700, marginLeft: '8px' }}>
                            -{cf.deduction}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* Overview Grid of all 6 Dimensions */
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                {DIMENSIONS.map((dim) => {
                  const score = effectiveRadarScores[dim.key] ?? (hasScanned ? 100 : '--');
                  const count = effectiveDimensionDetails[dim.key]?.findings_count ?? 0;
                  return (
                    <div
                      key={dim.key}
                      onClick={() => setActiveDim(dim.key)}
                      style={{
                        background: 'rgba(255, 255, 255, 0.04)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: '8px',
                        padding: '8px 10px',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = dim.color;
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.06)';
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>
                          {dim.label}
                        </span>
                        <span
                          style={{
                            fontSize: '0.85rem',
                            fontWeight: 800,
                            color: typeof score === 'number'
                              ? score >= 80 ? '#34d399' : score >= 60 ? '#fbbf24' : '#f87171'
                              : '#64748b',
                          }}
                        >
                          {score}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.65rem', color: '#64748b', marginTop: '2px' }}>
                        {hasScanned ? (count === 0 ? 'Clean (0 issues)' : `${count} issue(s)`) : 'Ready'}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
});

export default RadarChart;
