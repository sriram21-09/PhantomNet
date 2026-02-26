#!/bin/bash

# start_topology.sh
# Script to initialize the PhantomNet 3-Layer SD-N Topology

echo "==========================================="
echo " Starting PhantomNet Mininet Topology"
echo "==========================================="

# Ensure script is run as root, as Mininet requires elevated privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

# Clean previous Mininet state
echo "[*] Cleaning previous Mininet states..."
mn -c > /dev/null 2>&1

# Run the topology script
echo "[*] Launching 3-Layer Topology with Traffic Mirroring..."
# Assuming we are running this from the root of the PhantomNet project
python3 topology/phantomnet_topology.py
