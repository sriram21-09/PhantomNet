# PhantomNet UI Style Guide

This document outlines the design tokens, grid systems, and component standards for the PhantomNet Command Center.

## 📐 Grid & Spacing
PhantomNet uses an **8px base grid** for all layouts.
- **Micro-spacing**: 4px, 8px, 12px
- **Component spacing**: 16px, 24px, 32px
- **Container padding**: 40px (Desktop)

## 🎨 Color Palette
Standardized CSS variables defined in `theme.css`.

### Core Colors
| Name | Hex | Usage |
| :--- | :--- | :--- |
| `Dark Background` | `#020617` | Main wrapper background |
| `Card Background` | `rgba(15, 23, 42, 0.8)` | Dashboard cards (Pro-card) |
| `Neon Blue` | `#3b82f6` | Primary actions, focused data |
| `Neon Purple` | `#a855f7` | Secondary accents, anomaly markers |
| `Neon Green` | `#10b981` | Safe states, established links |
| `Neon Orange` | `#f59e0b` | Warning states, moderate risk |
| `Neon Red` | `#ef4444` | Critical alerts, high risk |

## 🧩 Components

### 1. Cards (`.pro-card`)
- **Backdrop Blur**: 12px
- **Border Radius**: 24px
- **Border**: 1px solid rgba(255, 255, 255, 0.1)

### 2. Interactions
- **Hovers**: Subtle lift (translateY -2px) and stronger glow.
- **Animations**: Use `cubic-bezier(0.4, 0, 0.2, 1)` for transitions.

## ⌨️ Typography
- **Font Family**: Inter, sans-serif
- **Headings**: Semi-bold to Black (600-900)
- **Data/Mono**: Fira Code or system monospace (for IPs and timestamps)

## 🛡️ Theme Support
The application supports Light/Dark mode via `body[data-theme]`.
> [!IMPORTANT]
> Always verify component Contrast Ratios in Light mode to ensure accessibility.
