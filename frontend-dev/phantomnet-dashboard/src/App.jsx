import "./styles/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ThemeProvider from "./context/ThemeProvider";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import About from "./pages/About";
import FeatureAnalysis from "./pages/FeatureAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";
import AnomalyDashboard from "./pages/AnomalyDashboard";


function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <div className="page-container">
          <Navbar />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/dashboard/features" element={<FeatureAnalysis />} />
            <Route path="/features" element={<FeatureAnalysis />} />
            <Route path="/events" element={<Events />} />
            <Route path="/about" element={<About />} />
            <Route path="/threat-analysis" element={<ThreatAnalysis />} />
            <Route path="/anomalies" element={<AnomalyDashboard />} />
          </Routes>
        </div>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
