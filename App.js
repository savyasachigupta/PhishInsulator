import React, { useState } from "react";

function App() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!content.trim()) {
      alert("Please enter URL or email content");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("http://localhost:5000/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ content }),
      });

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const riskColor = (risk) => {
    switch (risk) {
      case "CRITICAL":
        return "red";
      case "HIGH":
        return "orangered";
      case "MEDIUM":
        return "orange";
      case "LOW":
        return "yellowgreen";
      case "MINIMAL":
        return "green";
      default:
        return "gray";
    }
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>PhishInsulator AI - Phishing Detection</h1>
      <textarea
        rows="5"
        style={{ width: "100%" }}
        placeholder="Enter URL or email content to check"
        value={content}
        onChange={(e) => setContent(e.target.value)}
      />
      <br />
      <button onClick={handleAnalyze} disabled={loading} style={{ marginTop: 10 }}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {error && (
        <div style={{ marginTop: 20, color: "red" }}>
          <b>Error: </b> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 20, border: "1px solid #ccc", padding: 20 }}>
          <h2>
            Risk Level:{" "}
            <span style={{ color: riskColor(result.risk_level) }}>
              {result.risk_level}
            </span>
          </h2>
          <p>
            <b>Confidence Score:</b> {(result.final_score * 100).toFixed(1)}%
          </p>
          <p>
            <b>Summary:</b> {result.analysis?.summary || "No summary"}
          </p>
          {result.recommendations && (
            <>
              <h3>Recommendations:</h3>
              <ul>
                {result.recommendations.map((rec, idx) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
