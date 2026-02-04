import { useEffect, useState } from "react";
import { fetchConfusionMatrix } from "../api/mlApi";

const ConfusionMatrix = () => {
  const [matrix, setMatrix] = useState(null);

  useEffect(() => {
    fetchConfusionMatrix().then(setMatrix);
  }, []);

  if (!matrix) return <p>Loading confusion matrix...</p>;

  return (
    <div className="metric-card">
      <h3>Confusion Matrix</h3>
      <table>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <td key={j} style={{ padding: "6px" }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ConfusionMatrix;
