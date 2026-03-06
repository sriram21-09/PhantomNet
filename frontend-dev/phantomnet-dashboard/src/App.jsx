import "./Styles/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ThemeProvider from "./context/ThemeProvider";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import ErrorBoundary from "./components/ErrorBoundary";
import Events from "./pages/Events";
import About from "./pages/About";
import FeatureAnalysis from "./pages/FeatureAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";
import AnomalyDashboard from "./pages/AnomalyDashboard";
import Topology from "./pages/Topology";
import GeoDashboard from "./pages/GeoDashboard";
import AdvancedAnalytics from "./pages/AdvancedAnalytics";
import ThreatHunting from "./pages/ThreatHunting";
import AdvancedDashboard from "./pages/AdvancedDashboard";
import PacketAnalysis from "./components/PacketAnalysis";


function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary>
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
              <Route path="/topology" element={<Topology />} />
              <Route path="/geo-stats" element={<GeoDashboard />} />
              <Route path="/analytics" element={<AdvancedAnalytics />} />
              <Route path="/hunting" element={<ThreatHunting />} />
              <Route path="/advanced-dashboard" element={<AdvancedDashboard />} />
              <Route path="/packet-analysis" element={<PacketAnalysis />} />
            </Routes>
          </div>
        </BrowserRouter>
      </ErrorBoundary>
    </ThemeProvider>
  );
}

export default App;
