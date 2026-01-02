# Troubleshooting PhantomNet

## Docker Engine Not Running
Error:
open //./pipe/dockerDesktopLinuxEngine

Solution:
- Start Docker Desktop
- Run: docker info

## Connection Refused
- Verify container is running: docker ps
- Check port mapping in docker-compose.yml

## SSH Disconnects Quickly
- Expected behavior due to timeout or risk detection

## FTP LIST Not Showing Files
- Intended behavior to prevent enumeration
- Verify logs instead of output

## Logs Not Updating
- Check volume mounts
- Ensure write permissions
- Restart containers
