# PhantomNet SD-N Topology Architecture

This document describes the design behind the 3-Layer Miniminet topology used for simulating the SD-N environment in PhantomNet.

## Objective
To build a realistic, segment-isolated network topology that allows for continuous monitoring and logging of interactions with honeypots, simulating an enterprise environment setup.

## 1. 3-Layer Topology Architecture

The topology splits the network into a standard hierarchical topology:
- **Core Layer (`s1`)**: Central backbone of the network. Connects logically segmented branches. (1 Gbps links)
- **Distribution Layer (`s2`, `s3`)**: Separates internal/external traffic segments from honeypots/monitoring segments. (1 Gbps uplinks, 500 Mbps downlinks)
- **Access Layer (`s4`, `s5`, `s6`, `s7`)**: Edge switches connecting to the hosts directly. (100 Mbps links, 1ms - 10ms delays simulated)

### Hierarchy
```text
           [ Core Switch (s1) ]
          /                    \
[ Dist 1 (s2) ]            [ Dist 2 (s3) ]
  /        \                 /         \
[s4]      [s5]            [s6]         [s7]
 |          |              |  |          |
(h1)       (h2)           (h3)(h4)      (h5)
```

## 2. Node Roles

- **h1 (`10.0.0.10`)**: External Attacker
- **h2 (`10.0.1.20`)**: Internal User
- **h3 (`10.0.2.30`)**: SMTP Honeypot
- **h4 (`10.0.2.31`)**: SSH Honeypot
- **h5 (`10.0.3.40`)**: Monitor Dashboard & Backend

## 3. Traffic Mirroring Logic (Observability)

To passively observe attacks on honeypots (h3 and h4) without active interception logic inside the honeypots themselves, the topology uses Open vSwitch (OVS) **Port Mirroring** (SPAN).

### How it Works:
1. All traffic moving through the Distribution switch `s3` (which handles the Honeypot Access Switch `s6`) is mirrored.
2. The mirrored packets are duplicated and sent out via the port connected to the Monitoring switch (`s7`) and down to `h5`.
3. `h5` can run passive packet capture (e.g., `tcpdump`, `Zeek`, `Suricata`) to log all anomalous events locally, simulating a SOC's out-of-band monitoring tap.

### OVS Command
```bash
ovs-vsctl -- set Bridge s3 mirrors=@m \
  -- --id=@s3_port2 get Port s3-eth2 \
  -- --id=@s3_port3 get Port s3-eth3 \
  -- --id=@m create Mirror name=span1 select-all=true output-port=@s3_port3
```
This isolates the mirroring to the virtualization layer directly.

## 4. How to Start the Environment

1. Use the provided shell script to start the topology. It cleans old states and executes the topology file:
   ```bash
   sudo ./scripts/start_topology.sh
   ```
2. Once the Mininet CLI prompts `mininet>`, you can execute test commands, e.g.:
   - `h1 ping -c 3 h3` (Test attacker to SMTP honeypot)
   - `h5 tcpdump -i h5-eth0` (Monitor traffic on the backend tap)
