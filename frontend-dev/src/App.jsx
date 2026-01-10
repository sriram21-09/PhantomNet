import { useEffect, useState } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [logs, setLogs] = useState([])

  useEffect(() => {
    const fetchData = () => {
      axios.get('http://127.0.0.1:8000/logs')
        .then(response => {
          setLogs(response.data)
        })
        .catch(error => {
          console.error("Error fetching data:", error)
        })
    }

    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="dashboard">
      <h1>🕸️ PhantomNet Intelligence Center</h1>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Attacker IP</th>
            <th>Target</th>
            <th>Service</th>
            <th>Username</th>
            <th>Password</th>
          </tr>
        </thead>
        <tbody>
          {logs.map(log => (
            <tr key={log.id}>
              <td>{log.id}</td>
              <td>{new Date(log.timestamp).toLocaleTimeString()}</td>
              <td style={{color: 'red'}}>{log.attacker_ip}</td>
              <td>{log.target_node}</td>
              <td style={{color: 'cyan'}}>{log.service_type}</td>
              <td>{log.username}</td>
              <td style={{color: 'yellow'}}>{log.password}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default App