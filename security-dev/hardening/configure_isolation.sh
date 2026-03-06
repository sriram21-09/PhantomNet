#!/bin/bash

# PhantomNet Honeypot Isolation Configuration Script
# This script applies iptables rules to prevent lateral movement and unauthorized outbound traffic.

# 1. Define Honeypot Network (adjust if different)
HONEYPOT_NET="172.18.0.0/16" 
POSTGRES_IP="172.18.0.2"
API_IP="172.18.0.3"

# 2. Flush existing rules for the chains we'll use (CAUTION in production)
# iptables -F FORWARD

echo "Applying Honeypot Isolation Rules..."

# 3. Block Honeypot-to-Honeypot Communication
# Prevent any honeypot from talking to another honeypot in the same subnet
iptables -A FORWARD -s $HONEYPOT_NET -d $HONEYPOT_NET -j DROP

# 4. Allow Honeypot to Database and Logging (API)
# Only allow traffic to the specific internal services
iptables -A FORWARD -s $HONEYPOT_NET -d $POSTGRES_IP -p tcp --dport 5432 -j ACCEPT
iptables -A FORWARD -s $HONEYPOT_NET -d $API_IP -p tcp --dport 8000 -j ACCEPT

# 5. Block all other outbound traffic from Honeypots
# Prevent honeypots from being used as a launchpad for external attacks
iptables -A FORWARD -s $HONEYPOT_NET -j DROP

# 6. Rate Limit Connections per IP (Prevent DoS)
iptables -A INPUT -p tcp --dport 2222 -m connlimit --connlimit-above 10 -j REJECT # SSH
iptables -A INPUT -p tcp --dport 8080 -m connlimit --connlimit-above 20 -j REJECT # HTTP

echo "Isolation rules applied successfully."
echo "Note: These rules are representative. In a Docker environment, these should be applied to the DOCKER-USER chain or via Docker network policies."
