# Week 5 – Dashboard Components Design

## 1. HoneypotStatus
Displays status of all 4 honeypots.

Data:
- honeypot_id
- status (active / inactive)
- last_seen

UI:
- Card layout
- Green = Active
- Red = Inactive

---

## 2. NetworkVisualization
Displays Mininet 5-node topology.

Data:
- nodes
- connections

UI:
- Static diagram (initially)
- Later replace with visualization

---

## 3. AttackSourceMap
Shows geographic source of attacks.

Data:
- country
- attack_count

UI:
- World map
- Color intensity based on count

---

## 4. ProtocolDistribution
Shows attack distribution by protocol.

Data:
- protocol
- count

UI:
- Pie or bar chart