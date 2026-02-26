# Honeypot Management Console

The PhantomNet Management Console provides a centralized interface for managing a fleet of distributed honeypot nodes.

## Core Components

### 1. Node Manager (`node_manager.py`)
Responsible for tracking honeypot instances across the network.
- **Registration**: Nodes register themselves on startup.
- **Heartbeats**: Periodic check-ins to monitor health.
- **Status Tracking**: Monitors if nodes are `active` or `inactive`.

### 2. Policy Engine (`policy_engine.py`)
Manages configuration profiles and distributes them to nodes.
- **Policies**: Named configurations (e.g., "Strict SSH", "Low Interaction HTTP").
- **Assignment**: Maps policies to specific nodes or groups.
- **JSON Configuration**: Supports flexible schema-less configuration.

## API Reference

### Fleet Management
- `POST /api/v1/management/register`: Register a new node.
- `POST /api/v1/management/heartbeat`: Update node status.
- `GET /api/v1/management/nodes`: List all managed nodes.

### Policy Management
- `GET /api/v1/management/policies`: List all policies.
- `POST /api/v1/management/policies`: Create a new policy.
- `POST /api/v1/management/policies/assign`: Assign a policy to a node.

## Usage Example (Node Registration)

```bash
curl -X POST http://localhost:8000/api/v1/management/register \
     -H "Content-Type: application/json" \
     -d '{
       "hostname": "honeypot-ssh-01",
       "ip_address": "10.0.0.5",
       "honeypot_type": "SSH"
     }'
```
