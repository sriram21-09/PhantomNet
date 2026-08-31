# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| 2.0.x   | :x:                |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

The PhantomNet engineering team takes security vulnerabilities seriously. If you discover a vulnerability in PhantomNet, please follow these guidelines:

1. **Do not create a public GitHub issue.**
2. Send a confidential report to `security@phantomnet.local` or contact the repository maintainers directly:
   - Kasukurthi Sriram ([@sriram21-09](https://github.com/sriram21-09))
   - Muramreddy Vivekananda Reddy ([@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006))
3. Include detailed steps to reproduce the vulnerability, including attack payloads, configuration settings, and component versions.
4. Allow up to 48 hours for an initial response and acknowledgment from the team.
5. Coordinate with maintainers before public disclosure to ensure an official patch or mitigation is published.

## Security Architecture Principles

- **Zero Trust Network Segmentation**: Honeypots are strictly isolated from backend systems.
- **Principle of Least Privilege**: All containers run with dropped capabilities and non-root users.
- **Local AI Inference**: LLM processing (Ollama) is entirely local with zero cloud telemetry leakage.
