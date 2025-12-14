const mockEvents = [
  { time: "2025-03-01 12:12:48", ip: "203.0.113.199", type: "HTTP", port: 443, details: "HTTPS connection anomaly" },
  { time: "2025-03-01 11:49:55", ip: "198.51.100.200", type: "HTTP", port: 3389, details: "RDP handshake failure" },
  { time: "2025-03-01 11:47:23", ip: "203.0.113.199", type: "TELNET", port: 23, details: "Attempted default credentials" },
  { time: "2025-03-01 11:45:00", ip: "192.0.2.15", type: "SSH", port: 22, details: "Unauthorized access attempt" },
  { time: "2025-03-01 11:42:30", ip: "203.0.113.178", type: "HTTP", port: 80, details: "Attempt to access /backup.zip" },
  { time: "2025-03-01 11:40:45", ip: "10.0.4.55", type: "Database", port: 3306, details: "Brute-force attack on MySQL" },
  { time: "2025-03-01 11:37:12", ip: "203.0.113.202", type: "HTTP", port: 443, details: "Malformed HTTPS request" },
  { time: "2025-03-01 11:35:51", ip: "198.51.100.88", type: "FTP", port: 21, details: "Failed login using test/test" },
  { time: "2025-03-01 11:32:10", ip: "203.0.113.155", type: "SSH", port: 22, details: "Password spraying attempt" },
  { time: "2025-03-01 11:29:30", ip: "192.168.2.199", type: "HTTP", port: 8080, details: "Access to /config endpoint" },
  { time: "2025-03-01 11:26:10", ip: "198.51.100.12", type: "RDP", port: 3389, details: "RDP service probe detected" },
  { time: "2025-03-01 11:24:57", ip: "203.0.113.120", type: "TELNET", port: 23, details: "Plain-text credential attempt" },
  { time: "2025-03-01 11:23:19", ip: "203.0.113.88", type: "SMTP", port: 25, details: "Suspicious email relay attempt" },
  { time: "2025-03-01 11:20:02", ip: "198.51.100.45", type: "SSH", port: 22, details: "Failed login with user admin" },
  { time: "2025-03-01 11:18:55", ip: "203.0.113.32", type: "HTTP", port: 80, details: "Directory traversal attempt" },
  { time: "2025-03-01 11:16:41", ip: "192.0.2.77", type: "FTP", port: 21, details: "Anonymous FTP login attempt" },
  { time: "2025-03-01 11:15:09", ip: "198.51.100.9", type: "Database", port: 5432, details: "Unauthorized PostgreSQL connection" },
  { time: "2025-03-01 11:13:50", ip: "203.0.113.11", type: "HTTP", port: 8000, details: "SQL injection attempt on /login" }
];

export default mockEvents;