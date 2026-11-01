// HTTP load test for the proxy — run by scripts/proof.sh, which starts the
// proxy in front of the stub upstream and passes the settings below.
//
// Each scenario runs alone (staggered start times) at a fixed arrival rate,
// so its latency is not inflated by the others. Latency is measured
// end-to-end at the client: it includes loopback HTTP to the proxy, the
// proxy's full governance pipeline, the hop to the stub upstream and back.
// It is therefore an upper bound on proxy overhead.
//
// Env: REVOC_BASE, API_KEY, RATE (req/s), DURATION (s), CANARY_EMAIL, CANARY_SSN,
//      CANARY_AWS, SUMMARY (output path), P95_MS, P99_MS.

import http from 'k6/http';
import { check } from 'k6';

const BASE = __ENV.REVOC_BASE || 'http://127.0.0.1:18080';
const RATE = parseInt(__ENV.RATE || '200', 10);
const DURATION = parseInt(__ENV.DURATION || '20', 10);
const WARMUP = 5;
const P95 = __ENV.P95_MS || '10';
const P99 = __ENV.P99_MS || '25';

const GOVERNED = ['llm_clean', 'llm_pii', 'mcp_tool', 'embeddings'];

function scenario(exec, index) {
  return {
    executor: 'constant-arrival-rate',
    exec,
    rate: RATE,
    timeUnit: '1s',
    duration: `${DURATION}s`,
    startTime: `${WARMUP + index * (DURATION + 2)}s`,
    preAllocatedVUs: 50,
    maxVUs: 200,
  };
}

const thresholds = { checks: ['rate==1.0'] };
for (const s of GOVERNED) {
  thresholds[`http_req_duration{scenario:${s}}`] = [`p(95)<${P95}`, `p(99)<${P99}`];
  thresholds[`http_req_failed{scenario:${s}}`] = ['rate==0'];
  thresholds[`http_reqs{scenario:${s}}`] = ['count>0'];
}

export const options = {
  discardResponseBodies: false,
  summaryTrendStats: ['min', 'med', 'avg', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    warmup: {
      executor: 'constant-arrival-rate',
      exec: 'llmClean',
      rate: RATE,
      timeUnit: '1s',
      duration: `${WARMUP}s`,
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
    llm_clean: scenario('llmClean', 0),
    llm_pii: scenario('llmPii', 1),
    mcp_tool: scenario('mcpTool', 2),
    embeddings: scenario('embeddings', 3),
  },
  thresholds,
};

// A block (403) is a correct governed outcome, not a failed request.
http.setResponseCallback(http.expectedStatuses(200, 403));

const JSON_HEADERS = {
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${__ENV.API_KEY || ''}`,
  },
};

function chat(content) {
  return JSON.stringify({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: 'You are a helpful finance assistant.' },
      { role: 'user', content },
    ],
  });
}

function governed(res) {
  return check(res, {
    'governed status': (r) => r.status === 200 || r.status === 403,
    'X-Revoc-Timing present': (r) => !!r.headers['X-Revoc-Timing'],
    'X-Revoc-Dashboard present': (r) => !!r.headers['X-Revoc-Dashboard'],
  });
}

export function llmClean() {
  governed(
    http.post(
      `${BASE}/v1/chat/completions`,
      chat('Summarise the quarterly revenue trends for the board in three bullet points.'),
      JSON_HEADERS,
    ),
  );
}

export function llmPii() {
  const res = http.post(
    `${BASE}/v1/chat/completions`,
    chat(
      `Email ${__ENV.CANARY_EMAIL} about SSN ${__ENV.CANARY_SSN}; ` +
        `deploy key ${__ENV.CANARY_AWS}.`,
    ),
    JSON_HEADERS,
  );
  governed(res);
  check(res, {
    'PII not echoed back': (r) =>
      !String(r.body).includes(__ENV.CANARY_EMAIL) && !String(r.body).includes(__ENV.CANARY_SSN),
  });
}

export function mcpTool() {
  governed(
    http.post(
      `${BASE}/mcp`,
      JSON.stringify({
        jsonrpc: '2.0',
        id: '1',
        method: 'tools/call',
        params: { name: 'list_tickets', arguments: { status: 'open', limit: 10 } },
      }),
      JSON_HEADERS,
    ),
  );
}

export function embeddings() {
  governed(
    http.post(
      `${BASE}/v1/embeddings`,
      JSON.stringify({ model: 'text-embedding-3-small', input: 'quarterly revenue trends' }),
      JSON_HEADERS,
    ),
  );
}

export function handleSummary(data) {
  const out = {};
  if (__ENV.SUMMARY) {
    out[__ENV.SUMMARY] = JSON.stringify(data, null, 2);
  }
  return out;
}
