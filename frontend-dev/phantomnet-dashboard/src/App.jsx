import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid
} from 'recharts';

function App() {
  const [events, setEvents] = useState([]);
  const [chartData, setChartData] = useState([]);

  // --- declare helper before useEffect so it's available when called ---
  const processChartData = (data) => {
    const counts = {};
    data.forEach(event => {
      const type = event.honeypot_type || "Unknown";
      counts[type] = (counts[type] || 0) + 1;
    });

    const formatted = Object.keys(counts).map(key => ({
      name: key,
      attacks: counts[key]
    }));

    setChartData(formatted); // NOTE: use the correct setter name
  };

  useEffect(() => {
    // Fetch data from Backend
    axios.get('http://127.0.0.1:8000/events/')
      .then(response => {
        setEvents(response.data);
        processChartData(response.data);
      })
      .catch(error => console.error("Error:", error));
  }, []); // run once on mount

  return (
    <div style={{ padding: "40px", fontFamily: "Arial, sans-serif", backgroundColor: "#f4f6f8", minHeight: "100vh" }}>
      {/* Header */}
      <header style={{ marginBottom: "30px", textAlign: "center" }}>
        <h1 style={{ color: "#2c3e50" }}>🔐 PhantomNet Live Dashboard</h1>
        <p style={{ color: "green", fontWeight: "bold" }}>● System Online & Monitoring</p>
      </header>

      {/* Graph Section */}
      <div style={{ backgroundColor: "white", padding: "20px", borderRadius: "10px", marginBottom: "20px" }}>
        <h3 style={{ marginBottom: "20px" }}>📊 Attack Frequency</h3>
        <div style={{ height: "300px", width: "100%" }}>
          <ResponsiveContainer>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="attacks" fill="#8884d8" barSize={50} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* List Section */}
      <div style={{ backgroundColor: "white", padding: "20px", borderRadius: "10px" }}>
        <h3>📝 Recent Attack Logs ({events.length})</h3>
        <ul style={{ listStyle: "none", padding: 0 }}>
          {events.map(event => (
            <li key={event.id} style={{ padding: "10px", borderBottom: "1px solid #eee" }}>
              <span style={{ color: "#d9534f", fontWeight: "bold", marginRight: "10px" }}>
                [{event.honeypot_type || 'Unknown'}]
              </span>
              <span>{event.source_ip}</span>
              <span style={{ float: "right", color: "#888" }}>
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default App;
