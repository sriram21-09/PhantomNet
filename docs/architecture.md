# PhantomNet System Architecture

## Overview

PhantomNet is a distributed honeypot mesh system with AI-driven threat detection.

## Components

### 1. Honeypot Layer
- **SSH Honeypot** (Port 2222): Captures SSH brute-force attacks
- **HTTP Honeypot** (Port 8080): Captures web-based attacks
- **FTP Honeypot** (Port 2121): Captures file transfer attacks

### 2. Log Aggregation
All honeypots write JSON logs to `data/logs/<protocol>/`

### 3. Database Layer
PostgreSQL stores parsed events and threat scores

### 4. AI/ML Pipeline
Analyzes patterns and generates threat scores

### 5. API Layer
FastAPI provides REST endpoints for the frontend

### 6. Frontend Layer
React dashboard visualizes attacks in real-time

## Data Flow

Attacker → Honeypot → Log File → Parser → Database → ML Pipeline → API → Frontend

[Continue with detailed sections...]
