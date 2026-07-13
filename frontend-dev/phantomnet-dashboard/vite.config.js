import fs from "fs"
import path from "path"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Read API_PORT dynamically from the root .env file if it exists, fallback to 8000
let apiPort = 8000;
try {
  const envPath = path.resolve(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, "utf-8");
    const match = envContent.match(/^API_PORT\s*=\s*(\d+)/m);
    if (match) {
      apiPort = parseInt(match[1], 10);
    }
  }
} catch (e) {
  console.warn("Failed to read root .env file:", e);
}

const target = `http://127.0.0.1:${apiPort}`;

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api": {
        target: target,
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      "/analyze-traffic": {
        target: target,
        changeOrigin: true,
        secure: false,
      },
    },
  },
})

