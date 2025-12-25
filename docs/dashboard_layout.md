# Dashboard Layout – PhantomNet

## Overview
The Dashboard page provides a high-level view of honeypot activity and system health.

## Sections

### 1. Header
- Displays page title "Dashboard"
- Brief description of purpose

### 2. Metrics Section
- Total Events
- Unique IPs
- Active Honeypots
- Average Threat Score
- Critical Alerts

Each metric is displayed using reusable MetricCard components.

### 3. States Handling
- Loading state shown using spinner
- Error state displayed as message
- Empty state shown when no data is available

## Future Enhancements
- Charts for attack trends
- Recent events table