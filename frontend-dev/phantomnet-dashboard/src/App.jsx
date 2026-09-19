import "./Styles/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ThemeProvider from "./context/ThemeProvider";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Navbar from "./components/Navbar";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ErrorBoundary from "./components/ErrorBoundary";
import Events from "./pages/Events";
import About from "./pages/About";
import FeatureAnalysis from "./pages/FeatureAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";
import AnomalyDashboard from "./pages/AnomalyDashboard";
import Topology from "./pages/Topology";
import AdvancedAnalytics from "./pages/AdvancedAnalytics";
import ThreatHunting from "./pages/ThreatHunting";
import AdvancedDashboard from "./pages/AdvancedDashboard";
import PacketAnalysis from "./components/PacketAnalysis";
import AdminPanel from "./pages/AdminPanel";
import MLInsights from "./pages/MLInsights";
import Honeypots from "./pages/Honeypots";
import SentinelDashboard from "./pages/SentinelDashboard";
import NotFound from "./pages/NotFound";


function App() {
  return (
    <ThemeProvider>
      <ErrorBoundary>
        <AuthProvider>
          <BrowserRouter>
            <div className="page-container">
              <Navbar />
              <Routes>
                {/* Public Route */}
                <Route path="/login" element={<Login />} />
                <Route path="/about" element={<About />} />

                {/* Protected Routes */}
                <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                <Route path="/dashboard/features" element={<ProtectedRoute><FeatureAnalysis /></ProtectedRoute>} />
                <Route path="/features" element={<ProtectedRoute><FeatureAnalysis /></ProtectedRoute>} />
                <Route path="/events" element={<ProtectedRoute><Events /></ProtectedRoute>} />
                <Route path="/threat-analysis" element={<ProtectedRoute><ThreatAnalysis /></ProtectedRoute>} />
                <Route path="/anomalies" element={<ProtectedRoute><AnomalyDashboard /></ProtectedRoute>} />
                <Route path="/topology" element={<ProtectedRoute><Topology /></ProtectedRoute>} />
                <Route path="/analytics" element={<ProtectedRoute><AdvancedAnalytics /></ProtectedRoute>} />
                <Route path="/hunting" element={<ProtectedRoute><ThreatHunting /></ProtectedRoute>} />
                <Route path="/advanced-dashboard" element={<ProtectedRoute><AdvancedDashboard /></ProtectedRoute>} />
                <Route path="/packet-analysis" element={<ProtectedRoute><PacketAnalysis /></ProtectedRoute>} />
                <Route path="/admin" element={<ProtectedRoute><AdminPanel /></ProtectedRoute>} />
                <Route path="/ml-insights" element={<ProtectedRoute><MLInsights /></ProtectedRoute>} />
                <Route path="/honeypots" element={<ProtectedRoute><Honeypots /></ProtectedRoute>} />
                <Route path="/sentinel" element={<ProtectedRoute><SentinelDashboard /></ProtectedRoute>} />
                
                {/* Fallback */}
                <Route path="*" element={<NotFound />} />
              </Routes>
            </div>
          </BrowserRouter>
        </AuthProvider>
      </ErrorBoundary>
    </ThemeProvider>
  );
}

export default App;
