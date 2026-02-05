# Frontend API Integration Guide
## PhantomNet – Week 6 (Day 4 & Day 5)

---

## 1. Overview

This document describes how the PhantomNet frontend is prepared for backend ML API integration, including feature visualization, threat indication, testing, and verification.

The main goal was to integrate API-ready logic **without disturbing the existing UI**, while ensuring the frontend is stable, testable, and documented.

---

## 2. Architecture Summary

The frontend follows a **clean separation of concerns**:

- **UI Components**: Display data only
- **API Layer**: Handles all backend communication
- **Mocks**: Used as safe fallbacks and for testing
- **Test Controls**: Isolated, optional, and non-intrusive

---

## 3. API Layer (`mlClient.js`)

### Location

### Responsibilities
- Centralized API request handling
- Backend-ready endpoints
- Consistent error handling
- Easy switch from mock → live backend

### Available Functions
- `getEventFeatures(eventId)`
- `getBatchFeatures(eventIds[])`

---

## 4. FeatureVector Component

### Location


### Purpose
- Displays extracted ML features in tabular form
- Renders all 15 features for an event
- Uses mock data as fallback if API fails

### Key Characteristics
- API-ready
- No UI changes during integration
- Responsive (horizontal scroll on small screens)
- Dark-theme compatible

---

## 5. ThreatIndicator Component

### Location

### Purpose
- Visualizes threat level using a percentage bar
- Supports Low, Medium, and High threat levels
- Can accept live API data or mock values

### Threat Levels
- Low: 0–49
- Medium: 50–79
- High: 80–100

---

## 6. Batch Feature Support

### Location

### Purpose
- Fetches ML features for multiple events
- Enables scalability for dashboards and analytics
- Includes fallback logic and error handling

---

## 7. Testing Strategy (Week 6 – Day 5)

### 7.1 FeatureVector Testing
- Verified rendering of all 15 features
- Tested using normal and anomalous mock events
- Confirmed no layout breaks or missing rows

### 7.2 ThreatIndicator Testing
- Tested different threat levels:
  - Low (Normal Event)
  - Medium / High (Anomalous Event)
- Verified bar width, labels, and percentage updates

### 7.3 Test Control Panel
- Added a **test-only control** in `FeatureAnalysis.jsx`
- Allows switching between mock events
- Completely isolated from production UI
- Dark-theme safe

---

## 8. Responsive Design Verification

Tested on:
- Desktop
- Tablet
- Mobile

### Improvements
- Feature table supports horizontal scrolling on small screens
- No changes to desktop UI

---

## 9. Error Handling

- API failures fall back to mock data
- Errors are logged to console
- UI remains stable and usable

---

## 10. Design Principles Followed

- No UI regression
- Logic and UI separation
- Backend-ready architecture
- Testability without clutter
- Clean, maintainable code

---

## 11. Final Status

✅ Frontend is stable  
✅ API integration is prepared  
✅ Components are fully tested  
✅ Documentation completed  

**Week 6 – Day 4 and Day 5 successfully completed.**
