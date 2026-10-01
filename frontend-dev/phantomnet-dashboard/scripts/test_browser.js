import { chromium } from '@playwright/test';

async function test() {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext();
  
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBZG1pbiIsImV4cCI6MTc5MTM4MTgwNn0.sMfONtOn0vn81EMl27A8kQWYhaNZvpMu2kbahWurPoU';
  await context.addCookies([
    {
      name: 'phantomnet_access_token',
      value: token,
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    },
    {
      name: 'phantomnet_access_token',
      value: token,
      domain: '127.0.0.1',
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    }
  ]);

  const page = await context.newPage();
  
  page.on('console', msg => console.log('CONSOLE:', msg.type(), msg.text()));
  page.on('request', req => console.log('REQ:', req.method(), req.url()));
  page.on('response', res => console.log('RESP:', res.status(), res.url()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.message));

  console.log('Navigating to http://localhost:3000/topology...');
  await page.goto('http://localhost:3000/topology', { waitUntil: 'domcontentloaded' });
  
  // Wait up to 10s
  await page.waitForTimeout(10000);
  
  const html = await page.content();
  console.log('HAS TOPOLOGY CONTAINER:', html.includes('topology-container'));
  console.log('HAS AUTHENTICATING:', html.includes('AUTHENTICATING PHANTOMNET'));
  
  await page.screenshot({ path: 'test_topology.png' });
  console.log('Screenshot saved to test_topology.png');
  
  await browser.close();
}

test().catch(console.error);
