import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  use: {
    baseURL: 'http://127.0.0.1:3000',
    headless: true,
    channel: 'msedge', // Uses installed Edge on Windows
  },
  projects: [
    {
      name: 'desktop-edge',
      use: { ...devices['Desktop Edge'] },
    },
  ],
});
