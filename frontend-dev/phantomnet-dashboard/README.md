# PhantomNet Frontend

## Prerequisites
- Node.js (v18 or above)
- npm

## Install dependencies
npm install

## Run development server
npm run dev

## Build for production
npm run build

## Project Structure
- src/pages → Dashboard, Events, About
- src/components → Navbar, EventsTable, MetricCard, LoadingSpinner
- src/data → mockEvents.json

Frontend runs on http://localhost:5173

# PhantomNet Frontend

## Install dependencies
npm install

## Run development server
npm run dev

## Build for production
npm run build

## Pages
- Dashboard
- Events
- About

# PhantomNet Frontend Dashboard

PhantomNet is a React-based dashboard used to monitor honeypot attack events.
It supports both real API integration and mock fallback data.

## Project Structure

src/
├── components/        # Reusable UI components
│   ├── Navbar.jsx
│   ├── MetricCard.jsx
│   ├── LoadingSpinner.jsx
├── pages/             # Application pages
│   ├── Dashboard.jsx
│   ├── Events.jsx
│   ├── About.jsx
├── context/           # Theme & global state
│   ├── ThemeContext.jsx
├── data/              # Mock data (fallback)
├── App.jsx
├── main.jsx

## API Integration

The application attempts to fetch data from backend APIs.

If the API fails or backend is unavailable, mock data is used automatically.

Example:
- API URL: http://localhost:3000/api/events
- Mock data: src/pages/Events.jsx

## Run the Application

1. Install dependencies:
   npm install

2. Start development server:
   npm run dev

3. Open browser:
   http://localhost:5173

## Frontend Sign-off (Week 4)

- Dashboard, Events, and About pages completed
- API + mock fallback integration verified
- UI responsive across devices
- Error handling tested
- No critical UI bugs remaining

Approved for Month 1 scope.

## Future Enhancements
- Real-time WebSocket updates
- Advanced analytics charts
- Role-based access control