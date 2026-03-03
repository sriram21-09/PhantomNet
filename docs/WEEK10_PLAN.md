# PhantomNet - Week 10 Project Board & Plan

## 🎯 Objectives
Hardening the deception layer and expanding integration capabilities.

## 🗓️ Task Breakdown

### 🔐 Security & Hardening
- [ ] **SIEM Integration**: Prototype Splunk/Elasticsearch connector for centralized logging.
- [ ] **IP Banning Logic**: Implement automated firewall rule generation for HIGH threat scores.
- [ ] **Rate Limiting**: Add API-level rate limiting to prevent DoS on the management console.

### 🍯 Honeypot Expansion
- [ ] **DB Honeypot (MySQL)**: Initialize a new Docker container for simulated MySQL traffic.
- [ ] **Credential Trap**: Implement "honey-credentials" detection in existing protocols.

### 📊 Visualization & UX
- [ ] **Topology Optimization**: Improve React Flow performance for 50+ concurrent attacker nodes.
- [ ] **Mobile App PWA**: Configure basic PWA support for mobile monitoring.

### 🧪 Testing
- [ ] **Red Team Simulation**: Conduct a full attack simulation to verify the new blocking logic.
- [ ] **Stress Test**: Increase concurrent user simulation to 100 in Load Tests.

## 👥 Assignments
- **Sriram**: SIEM Integration & Project Oversight
- **Vivek**: DB Honeypot & IP Banning
- **Vikranth**: Red Team Simulation & ML Model Refinement
- **Manideep**: Topology Optimization & PWA Setup
