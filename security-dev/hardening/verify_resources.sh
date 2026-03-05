#!/bin/bash

# PhantomNet Resource Limit Verification Script
# This script inspects the running Docker containers to ensure resource limits are active.

echo "Verifying Docker Resource Limits..."

containers=("ssh_honeypot" "http_honeypot" "ftp_honeypot" "smtp_honeypot")

for container in "${containers[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "$container"; then
        cpu_limit=$(docker inspect "$container" --format '{{.HostConfig.NanoCpus}}')
        mem_limit=$(docker inspect "$container" --format '{{.HostConfig.Memory}}')
        
        echo "Container: $container"
        if [ "$cpu_limit" != "0" ]; then
            echo "  ✅ CPU Limit: $((cpu_limit / 10000000))%"
        else
            echo "  ❌ NO CPU LIMIT SET"
        fi
        
        if [ "$mem_limit" != "0" ]; then
            echo "  ✅ Memory Limit: $((mem_limit / 1024 / 1024))MB"
        else
            echo "  ❌ NO MEMORY LIMIT SET"
        fi
    else
        echo "⚠️  $container is not running. Check docker-compose."
    fi
done
