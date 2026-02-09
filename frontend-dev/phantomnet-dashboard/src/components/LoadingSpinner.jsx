import "./LoadingSpinner.css";

function LoadingSpinner() {
  return (
    <div className="spinner-container">
      <div className="spinner-ring">
        <div className="spinner-core"></div>
      </div>
      <span className="spinner-text">Loading...</span>
    </div>
  );
}

export default LoadingSpinner;