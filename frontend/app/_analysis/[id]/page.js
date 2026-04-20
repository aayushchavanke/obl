"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { API_BASE_URL as API } from "../../../lib/api";

function formatConfidence(confidence, prediction) {
  const numeric = Number(confidence);
  if (!Number.isFinite(numeric)) return "N/A";
  if (numeric <= 0 && String(prediction || "").toLowerCase().includes("no model")) {
    return "N/A";
  }
  return `${(numeric * 100).toFixed(1)}%`;
}

function normalizeFeature(feature) {
  if (Array.isArray(feature)) {
    const [name, weight] = feature;
    return { name, weight: Number(weight) || 0 };
  }

  if (feature && typeof feature === "object") {
    return {
      name: feature.feature || feature.name || "Unknown Feature",
      weight: Number(feature.importance ?? feature.weight) || 0,
    };
  }

  return { name: "Unknown Feature", weight: 0 };
}

function formatFeatureName(name) {
  return String(name || "Unknown Feature")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function StatBox({ label, value, accent }) {
  return (
    <div>
      <div style={statLabelStyle}>{label}</div>
      <div
        style={{
          ...statValueStyle,
          color: accent ? "var(--accent)" : "var(--text-primary)",
        }}
      >
        {value}
      </div>
    </div>
  );
}

export default function AnalysisPage({ params }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!params?.id) return;

    const runAnalysis = async () => {
      try {
        setLoading(true);
        const analyzeRes = await fetch(`${API}/api/analyze/${params.id}`);
        const analyzeData = await analyzeRes.json();

        if (analyzeData.error) {
          setError(analyzeData.error);
        } else {
          setData(analyzeData);
        }
      } catch (e) {
        setError(e.message);
      }

      setLoading(false);
    };

    runAnalysis();
  }, [params?.id]);

  const topFeatures = (data?.explanations?.[0]?.top_features || [])
    .map(normalizeFeature)
    .filter((feature) => feature.name);
  const insights = data?.explanations?.[0]?.insights || [];
  const suggestions = data?.suggestions || [];
  const predictions = data?.predictions || [];
  const maxWeight = topFeatures.length > 0
    ? Math.max(...topFeatures.map((feature) => feature.weight), 1)
    : 1;

  if (loading) {
    return (
      <div style={containerStyle}>
        <div className="pulse" style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Analyzing with 49 parameters...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={containerStyle}>
        <Link href="/" style={backLink}>Back to Dashboard</Link>
        <div className="card" style={{ marginTop: "1rem", color: "var(--black-badge)" }}>
          Error: {error}
        </div>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      <div style={headerRowStyle}>
        <Link href="/" style={backLink}>Back to Dashboard</Link>
        <div style={headerActionsStyle}>
          <button
            className="btn btn-sm"
            onClick={() => window.open(`${API}/api/report/${params.id}`, "_blank")}
          >
            Download PDF
          </button>
          <h2 style={titleStyle}>Analysis {params.id}</h2>
        </div>
      </div>

      <div className="card" style={{ marginBottom: "1rem" }}>
        <h3 style={cardTitleStyle}>Capture Metadata</h3>
        <div style={statsGridStyle}>
          <StatBox label="Total Packets" value={data?.metadata?.total_packets || 0} />
          <StatBox label="Total Flows" value={data?.total_flows || 0} />
          <StatBox label="Identities Created" value={data?.identities_created || 0} />
          <StatBox label="Status" value={data?.status || "unknown"} accent />
        </div>
      </div>

      {predictions.length > 0 && (
        <div className="card">
          <h3 style={cardTitleStyle}>Flow Classifications</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Flow</th>
                <th>Category</th>
                <th>Threat Type</th>
                <th>Confidence</th>
                <th>VPN</th>
              </tr>
            </thead>
            <tbody>
              {predictions.map((pred, index) => (
                <tr key={`${pred.src_ip || "src"}-${pred.dst_ip || "dst"}-${index}`}>
                  <td style={flowCellStyle}>
                    {pred.src_ip || "?"} to {pred.dst_ip || "?"}
                  </td>
                  <td>
                    <span className={`badge ${pred.is_malicious ? "badge-black" : "badge-white"}`}>
                      {pred.category}
                    </span>
                  </td>
                  <td style={{ color: pred.is_malicious ? "var(--black-badge)" : "var(--text-secondary)" }}>
                    {pred.threat_type}
                  </td>
                  <td style={monoCellStyle}>
                    {formatConfidence(pred.confidence, pred.prediction || pred.threat_type)}
                  </td>
                  <td>
                    {pred.is_vpn ? (
                      <span className="badge badge-blocked">VPN</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(topFeatures.length > 0 || insights.length > 0 || suggestions.length > 0) && (
        <div style={forensicsGridStyle}>
          <div className="card">
            <h3 style={cardTitleStyle}>Most Influential Parameters</h3>
            {topFeatures.length > 0 ? (
              <div style={stackStyle}>
                {topFeatures.slice(0, 10).map((feature, index) => (
                  <div
                    key={`${feature.name}-${index}`}
                    style={featureRowStyle}
                  >
                    <span style={rankStyle}>{index + 1}</span>
                    <span style={featureNameStyle} title={feature.name}>
                      {formatFeatureName(feature.name)}
                    </span>
                    <div style={trackStyle}>
                      <div
                        style={{
                          ...barStyle,
                          width: `${Math.max((feature.weight / maxWeight) * 100, 6)}%`,
                          background: index === 0 ? "var(--accent)" : index < 3 ? "#7c3aed" : "#94a3b8",
                        }}
                      />
                    </div>
                    <span style={weightStyle}>{(feature.weight * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            ) : (
              <p style={emptyTextStyle}>Feature importance data is not available for this analysis.</p>
            )}
          </div>

          <div style={sidebarGridStyle}>
            <div className="card">
              <h3 style={cardTitleStyle}>XAI Insights</h3>
              {insights.length > 0 ? (
                <div style={stackStyle}>
                  {insights.map((insight, index) => (
                    <div key={index} style={insightCardStyle}>
                      <p style={insightTextStyle}>{insight}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={emptyTextStyle}>No XAI insights were generated for this analysis.</p>
              )}
            </div>

            <div className="card">
              <h3 style={cardTitleStyle}>Threats and Suggestions</h3>
              {suggestions.length > 0 ? (
                <div style={stackStyle}>
                  {suggestions.map((suggestion, index) => (
                    <div key={index} style={suggestionRowStyle}>
                      <div style={suggestionIconStyle}>{suggestion.icon || "[i]"}</div>
                      <div>
                        <div style={suggestionTitleStyle}>{suggestion.title || "Suggestion"}</div>
                        <p style={suggestionTextStyle}>{suggestion.text}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={emptyTextStyle}>No follow-up suggestions are available for this analysis.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const containerStyle = {
  minHeight: "100vh",
  padding: "1.5rem 2rem",
  maxWidth: "1400px",
  margin: "0 auto",
};

const headerRowStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "1rem",
  marginBottom: "1.5rem",
  flexWrap: "wrap",
};

const headerActionsStyle = {
  display: "flex",
  alignItems: "center",
  gap: "0.75rem",
  flexWrap: "wrap",
};

const titleStyle = {
  fontSize: "1rem",
  fontFamily: "var(--font-mono)",
  margin: 0,
};

const backLink = {
  color: "var(--text-secondary)",
  textDecoration: "none",
  fontSize: "0.8125rem",
};

const cardTitleStyle = {
  fontSize: "0.875rem",
  marginBottom: "0.75rem",
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
  gap: "1rem",
};

const statLabelStyle = {
  fontSize: "0.6875rem",
  color: "var(--text-muted)",
  marginBottom: 2,
  textTransform: "uppercase",
  letterSpacing: "0.04em",
};

const statValueStyle = {
  fontSize: "1.25rem",
  fontWeight: 600,
  fontFamily: "var(--font-mono)",
};

const flowCellStyle = {
  fontFamily: "var(--font-mono)",
  fontSize: "0.75rem",
};

const monoCellStyle = {
  fontFamily: "var(--font-mono)",
};

const forensicsGridStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1.1fr) minmax(320px, 0.9fr)",
  gap: "1rem",
  marginTop: "1rem",
};

const sidebarGridStyle = {
  display: "grid",
  gap: "1rem",
};

const stackStyle = {
  display: "flex",
  flexDirection: "column",
  gap: "0.75rem",
};

const featureRowStyle = {
  display: "grid",
  gridTemplateColumns: "24px minmax(0, 190px) minmax(120px, 1fr) 64px",
  gap: "0.625rem",
  alignItems: "center",
};

const rankStyle = {
  fontSize: "0.75rem",
  fontFamily: "var(--font-mono)",
  color: "var(--text-muted)",
  textAlign: "right",
};

const featureNameStyle = {
  fontSize: "0.75rem",
  fontFamily: "var(--font-mono)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const trackStyle = {
  height: "8px",
  background: "var(--border-color)",
  borderRadius: "999px",
  overflow: "hidden",
};

const barStyle = {
  height: "100%",
  borderRadius: "999px",
};

const weightStyle = {
  fontSize: "0.75rem",
  fontFamily: "var(--font-mono)",
  textAlign: "right",
  color: "var(--text-secondary)",
};

const insightCardStyle = {
  padding: "0.875rem 1rem",
  border: "1px solid var(--border-color)",
  borderRadius: "10px",
  background: "rgba(124, 58, 237, 0.04)",
};

const insightTextStyle = {
  fontSize: "0.75rem",
  lineHeight: 1.6,
  color: "var(--text-secondary)",
  margin: 0,
};

const suggestionRowStyle = {
  display: "grid",
  gridTemplateColumns: "52px minmax(0, 1fr)",
  gap: "0.75rem",
  alignItems: "start",
};

const suggestionIconStyle = {
  fontSize: "0.75rem",
  fontFamily: "var(--font-mono)",
  color: "var(--accent)",
  background: "rgba(99, 102, 241, 0.08)",
  border: "1px solid var(--border-color)",
  borderRadius: "999px",
  padding: "0.35rem 0.5rem",
  textAlign: "center",
};

const suggestionTitleStyle = {
  fontSize: "0.75rem",
  fontWeight: 600,
  marginBottom: "0.2rem",
};

const suggestionTextStyle = {
  fontSize: "0.75rem",
  color: "var(--text-secondary)",
  lineHeight: 1.6,
  margin: 0,
};

const emptyTextStyle = {
  fontSize: "0.75rem",
  color: "var(--text-muted)",
  lineHeight: 1.6,
  margin: 0,
};
