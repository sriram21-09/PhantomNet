import { BrowserRouter, Routes, Route } from "react-router-dom";
import ThemeProvider from "./context/ThemeProvider";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import About from "./pages/About";
import FeatureAnalysis from "./pages/FeatureAnalysis";
import ThreatAnalysis from "./pages/ThreatAnalysis";


function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Navbar />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/dashboard/features" element={<FeatureAnalysis />} />
          <Route path="/events" element={<Events />} />
          <Route path="/about" element={<About />} />
          <Route path="/threat-analysis" element={<ThreatAnalysis />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
