import React, { useState } from "react";

/**
 * Explainability Component
 * -------------------------
 * Purpose:
 *  - Display model explainability details without blocking inference flow
 *  - Render only when explanation data is available
 *
 * Props:
 *  - confidence: number (0–1)
 *  - features: Array<{ name: string, contribution: number }>
 *
 * Usage:
 *  <Explainability confidence={0.87} features={[...]} />
 */

const Explainability = ({ confidence, features }) => {
  const [isOpen, setIsOpen] = useState(false);

  // Graceful fallback if explainability data is missing
  if (!confidence && (!features || features.length === 0)) {
    return null;
  }

  return (
    <div className="explainability-container">
      {/* Toggle button to ensure non-blocking UI */}
      <button
        className="explainability-toggle"
        onClick={() => setIsOpen(!isOpen)}
      >
        {isOpen ? "Hide explanation" : "Why this prediction?"}
      </button>

      {isOpen && (
        <div className="explainability-panel">
          {/* Confidence Section */}
          {confidence && (
            <p>
              <strong>Confidence:</strong> {(confidence * 100).toFixed(2)}%
            </p>
          )}

          {/* Feature Contribution Section */}
          {features && features.length > 0 && (
            <>
              <h4>Top contributing factors</h4>
              <ul>
                {features.slice(0, 5).map((feature, index) => (
                  <li key={index}>
                    {feature.name}: {feature.contribution.toFixed(2)}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default Explainability;
