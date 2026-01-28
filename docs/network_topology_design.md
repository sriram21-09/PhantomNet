# 🕸️ PhantomNet Phase 2: Distributed Topology Design

## 1. Network Overview
**Architecture:** Star Topology (Central Switch)
**Controller:** Mininet Remote Controller
**Subnet:** 10.0.0.0/24

## 2. Node Assignments & IP Allocation
We will simulate 5 distinct nodes. Each serves a specific security role.

| Node | Hostname | IP Address | Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | `coordinator` | `10.0.0.1` | 🧠 **The Brain** | Runs the Database, Dashboard, and aggregates logs. |
| **H2** | `honeypot-ssh` | `10.0.0.2` | 🪤 **Trap 1** | Simulates a vulnerable Linux Server (SSH). |
| **H3** | `honeypot-http`| `10.0.0.3` | 🪤 **Trap 2** | Simulates a fake Corporate Login Page (Web). |
| **H4** | `honeypot-ftp` | `10.0.0.4` | 🪤 **Trap 3** | Simulates a File Server with fake sensitive docs. |
| **H5** | `attacker-pc` | `10.0.0.5` | ⚔️ **The Enemy** | Kali Linux simulator launching attacks. |

## 3. Link Characteristics
To make the simulation realistic, we apply constraints to the virtual ethernet cables.

* **Bandwidth:** `100 Mbps` (Simulating standard Fast Ethernet)
* **Latency:** `10ms` (Simulating internal LAN delay)
* **Loss:** `0%` (Perfect connection)

## 4. Data Flow Strategy
All Honeyots (H2, H3, H4) must report back to the Coordinator (H1).

1.  **Attack occurs:** Attacker (H5) -> SSH Pot (H2)
2.  **Log Generation:** H2 captures credentials/commands.
3.  **Transmission:** H2 sends JSON payload -> H1 (API Endpoint `10.0.0.1:8000/log`).
4.  **Storage:** H1 saves to PostgreSQL.

## 5. Schema Mapping
How protocol-specific data maps to our Unified `packet_logs` table:

| Source | Field | Target DB Column |
| :--- | :--- | :--- |
| **SMTP** | `Sender` | `mail_from` |
| **SMTP** | `Recipient`| `rcpt_to` |
| **HTTP** | `User-Agent` | `payload_metadata` (JSON) |
| **SSH** | `Username` | `payload_metadata` (JSON) |