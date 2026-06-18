// Thor Firewall Smart — k6 Performance & Regression Test (Phase 5)
//
// Usage:
//   k6 run tests/perf/k6-smoke.js
//   k6 run --vus 50 --duration 60s tests/perf/k6-smoke.js
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate     = new Rate('thor_error_rate');
const authLatency   = new Trend('thor_auth_latency_ms', true);
const alertsLatency = new Trend('thor_alerts_latency_ms', true);

const BASE_URL   = __ENV.THOR_URL   || 'http://localhost:8080';
const ADMIN_USER = __ENV.ADMIN_USER || 'thor_admin';
const ADMIN_PASS = __ENV.ADMIN_PASS || 'change_me_before_deploy';

export const options = {
  scenarios: {
    smoke: { executor: 'constant-vus', vus: 2, duration: '30s' },
    load:  {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [{ duration: '30s', target: 20 }, { duration: '60s', target: 50 }, { duration: '30s', target: 0 }],
      startTime: '35s',
    },
  },
  thresholds: {
    'http_req_duration{name:health}': ['p(95)<100', 'p(99)<200'],
    'http_req_duration{name:stats}':  ['p(95)<500', 'p(99)<1000'],
    'http_req_duration{name:alerts}': ['p(95)<1000'],
    'thor_error_rate':                ['rate<0.01'],
    'http_req_failed':                ['rate<0.02'],
  },
};

export function setup() {
  const res = http.post(
    `${BASE_URL}/api/v1/auth/login`,
    JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  if (res.status !== 200) {
    console.warn(`Login failed: ${res.status}`);
    return { token: null };
  }
  return { token: JSON.parse(res.body).token };
}

export default function(data) {
  const auth = data.token ? { 'Authorization': `Bearer ${data.token}`, 'Content-Type': 'application/json' } : {};

  group('Health', () => {
    const r = http.get(`${BASE_URL}/health`, { tags: { name: 'health' } });
    errorRate.add(!check(r, { '200 OK': (r) => r.status === 200 }));
  });

  if (!data.token) { sleep(1); return; }

  group('Stats', () => {
    const start = Date.now();
    const r = http.get(`${BASE_URL}/api/v1/stats`, { headers: auth, tags: { name: 'stats' } });
    authLatency.add(Date.now() - start);
    errorRate.add(!check(r, { '200': (r) => r.status === 200 }));
  });

  group('Alerts', () => {
    const start = Date.now();
    const r = http.get(`${BASE_URL}/api/v1/alerts?limit=20`, { headers: auth, tags: { name: 'alerts' } });
    alertsLatency.add(Date.now() - start);
    errorRate.add(!check(r, { '200': (r) => r.status === 200 }));
  });

  // Rate limit test (1% of VUs)
  if (Math.random() < 0.01) {
    const r = http.post(`${BASE_URL}/api/v1/auth/login`,
      JSON.stringify({ username: 'invalid', password: 'brute_force' }),
      { headers: { 'Content-Type': 'application/json' } });
    check(r, { 'bruteforce blocked': (r) => r.status === 401 || r.status === 429 });
  }

  sleep(0.5 + Math.random() * 0.5);
}

export function teardown(data) {
  if (data.token) {
    http.post(`${BASE_URL}/api/v1/auth/logout`, null,
      { headers: { 'Authorization': `Bearer ${data.token}` } });
  }
}
