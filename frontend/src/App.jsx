import { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, AreaChart, Area
} from 'recharts';
import { Shield, Activity, AlertTriangle, Radio, Globe, Server, Lock, Ban } from 'lucide-react';
import './App.css';

function App() {
  const [traffic, setTraffic] = useState([]);
  const [stats, setStats] = useState({
    total_attacks: 0,
    unique_ips: 0,
    hourly_trend: []
  });
  const [blockedIPs, setBlockedIPs] = useState(new Set());

  // Fetch Live Traffic
  useEffect(() => {
    const fetchTraffic = async () => {
      try {
        const res = await axios.get('http://127.0.0.1:8000/analyze-traffic');
        setTraffic(res.data.data);
      } catch (error) {
        console.error("Error fetching traffic:", error);
      }
    };

    const fetchStats = async () => {
      try {
        const res = await axios.get('http://127.0.0.1:8000/dashboard/stats');
        setStats(res.data.data);
      } catch (error) {
        console.error("Error fetching stats:", error);
      }
    };

    fetchTraffic();
    fetchStats();
    const trafficInterval = setInterval(fetchTraffic, 2000);
    const statsInterval = setInterval(fetchStats, 10000);

    return () => {
      clearInterval(trafficInterval);
      clearInterval(statsInterval);
    };
  }, []);

  // --- THE KILL SWITCH FUNCTION ---
  const handleBlock = async (ip) => {
    if (ip === '127.0.0.1' || ip === 'localhost') {
        alert("⚠️ Safety Protocol: Cannot block localhost!");
        return;
    }

    if (!confirm(`⚠️ WARNING: Are you sure you want to PERMANENTLY block ${ip}?`)) return;

    try {
        const response = await axios.post(`http://127.0.0.1:8000/active-defense/block/${ip}`);
        if (response.data.status === 'success') {
            alert(`✅ TARGET NEUTRALIZED: ${ip} has been blocked.`);
            setBlockedIPs(prev => new Set(prev).add(ip));
        } else {
            alert(`❌ ERROR: ${response.data.message}`);
        }
    } catch (error) {
        alert("❌ CONNECTION ERROR: Ensure Backend is running as Administrator.");
        console.error(error);
    }
  };

  return (
    <div className="dashboard-container">
      {/* Header */}
      <header className="header">
        <div>
          <h1 className="title">PhantomNet AI</h1>
          <p style={{ color: '#94a3b8' }}>Active Defense System</p>
        </div>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 20px', border: '1px solid #10b981' }}>
          <Radio className="animate-pulse" color="#10b981" size={20} />
          <span style={{ fontWeight: 'bold', color: '#10b981' }}>SYSTEM ARMED</span>
        </div>
      </header>

      {/* Stats Grid */}
      <div className="stats-grid">
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span style={{ color: '#94a3b8' }}>Total Attacks</span>
            <AlertTriangle color="#ef4444" size={20} />
          </div>
          <h2 style={{ fontSize: '2rem', margin: 0 }}>{stats.total_attacks}</h2>
        </div>
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span style={{ color: '#94a3b8' }}>Unique Threats</span>
            <Globe color="#f59e0b" size={20} />
          </div>
          <h2 style={{ fontSize: '2rem', margin: 0 }}>{stats.unique_ips}</h2>
        </div>
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span style={{ color: '#94a3b8' }}>Live Packets</span>
            <Activity color="#3b82f6" size={20} />
          </div>
          <h2 style={{ fontSize: '2rem', margin: 0 }}>{traffic.length}</h2>
        </div>
      </div>

      {/* Graphs */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginBottom: '30px' }}>
        <div className="card" style={{ height: '350px' }}>
          <h3 style={{ marginBottom: '20px' }}>Threat Frequency</h3>
          <ResponsiveContainer width="100%" height="85%">
            <AreaChart data={stats.hourly_trend}>
              <defs>
                <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d2d3b" />
              <XAxis dataKey="hour" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ backgroundColor: '#13131f', border: '1px solid #2d2d3b', color: '#fff' }} />
              <Area type="monotone" dataKey="count" stroke="#ef4444" fillOpacity={1} fill="url(#colorCount)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        
        {/* Protocol List */}
        <div className="card">
            <h3>Vectors</h3>
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {stats.attacks_by_type && Object.entries(stats.attacks_by_type).map(([proto, count]) => (
                <li key={proto} style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0', borderBottom: '1px solid #2d2d3b' }}>
                  <span style={{ fontWeight: 'bold', color: '#e0e0e0' }}>{proto}</span>
                  <span className="badge badge-suspicious">{count}</span>
                </li>
              ))}
            </ul>
        </div>
      </div>

      {/* Live Feed with KILL SWITCH */}
      <div className="card table-container">
        <h3>Live Threat Feed</h3>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Target</th>
              <th>Protocol</th>
              <th>Active Defense</th>
            </tr>
          </thead>
          <tbody>
            {traffic.slice(0, 10).map((packet, index) => (
              <tr key={index}>
                <td><span className={`badge badge-${packet.ai_analysis.prediction.toLowerCase()}`}>{packet.ai_analysis.prediction}</span></td>
                <td style={{ fontFamily: 'monospace' }}>{packet.packet_info.src}</td>
                <td style={{ fontFamily: 'monospace' }}>{packet.packet_info.dst}</td>
                <td>{packet.packet_info.proto}</td>
                <td>
                    {blockedIPs.has(packet.packet_info.src) ? (
                        <button disabled className="btn-blocked">
                            <Lock size={14} /> NEUTRALIZED
                        </button>
                    ) : (
                        <button 
                            className="btn-kill"
                            onClick={() => handleBlock(packet.packet_info.src)}
                        >
                            <Ban size={14} /> BLOCK IP
                        </button>
                    )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;