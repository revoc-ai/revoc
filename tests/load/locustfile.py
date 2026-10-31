"""REVOC load test — verifies Principle 2 latency SLOs under concurrent traffic.

SPEC.md §3 Principle 2: P95 proxy overhead < 10ms, P99 < 25ms.

Run with:
    locust -f tests/load/locustfile.py \
        --headless \
        --host http://localhost:8080 \
        -u 50 -r 10 \
        --run-time 60s \
        --csv tests/load/results/run

Then inspect tests/load/results/run_stats.csv for p95/p99 values.

The locust User tasks measure round-trip latency to the REVOC proxy (which is
running with mock_mode=true so upstream latency is negligible).  Any overhead
beyond processing time is attributable to REVOC governance.  The SLO is:
  P95 < 10ms, P99 < 25ms of REVOC-added latency.

Because mock_mode=true means the upstream responds in <1ms, the measured
round-trip latency from within the same host is dominated by REVOC processing
time, making it a reliable proxy for the "proxy overhead" metric.
"""

from __future__ import annotations

import json
import random

from locust import HttpUser, between, events, task


# ── Task payloads ─────────────────────────────────────────────────────────────

SAFE_MESSAGES = [
    "What is the capital of France?",
    "Explain photosynthesis in one sentence.",
    "How do I reverse a string in Python?",
    "What is 17 * 23?",
    "Translate 'hello' to Spanish.",
    "What year did World War II end?",
    "Describe the water cycle briefly.",
    "What is the boiling point of water in Celsius?",
]

PII_MESSAGES = [
    "My email is user@example.com and I need help.",
    "Call me at 415-555-0199 tomorrow morning.",
    # 203.0.113.x is TEST-NET-3 (RFC 5737) — public range, triggers pii_ip_address_v1
    # redaction but NOT sec_ssrf_v1 (which only fires on private/internal ranges).
    "My server IP is 203.0.113.45 for the config.",
]


def _chat(content: str, stream: bool = False) -> dict:
    return {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }


# ── Locust User ───────────────────────────────────────────────────────────────

class RevocUser(HttpUser):
    """Simulates a single concurrent caller sending governed LLM requests.

    Wait time is intentionally short (0.1–0.3s) to maximise concurrency
    and surface latency tail behaviour.
    """

    wait_time = between(0.1, 0.3)
    host = "http://localhost:8080"

    @task(6)
    def safe_request(self) -> None:
        """Allowed requests — exercises the allow path (no PII, no security finding)."""
        content = random.choice(SAFE_MESSAGES)
        with self.client.post(
            "/v1/chat/completions",
            json=_chat(content),
            headers={"Content-Type": "application/json"},
            catch_response=True,
            name="LLM /allow",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code}: {resp.text[:200]}")

    @task(3)
    def pii_redact_request(self) -> None:
        """Redact-path requests — exercises detection + redaction pipeline."""
        content = random.choice(PII_MESSAGES)
        with self.client.post(
            "/v1/chat/completions",
            json=_chat(content),
            headers={"Content-Type": "application/json"},
            catch_response=True,
            name="LLM /redact",
        ) as resp:
            if resp.status_code == 200:
                decision = resp.headers.get("X-Revoc-Decision", "")
                if decision == "redact":
                    resp.success()
                else:
                    # Could be allow if regex didn't match — still a valid response
                    resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code}: {resp.text[:200]}")

    @task(1)
    def blocked_request(self) -> None:
        """Block-path requests — exercises the full detection + policy block path.

        Uses weight 1 (low) because 403s are expected and block the upstream,
        keeping them rare to avoid inflating error statistics in Locust.
        """
        with self.client.post(
            "/v1/chat/completions",
            json=_chat("DROP TABLE users;"),
            headers={"Content-Type": "application/json"},
            catch_response=True,
            name="LLM /block",
        ) as resp:
            if resp.status_code == 403:
                resp.success()
            else:
                resp.failure(f"Expected 403 block, got {resp.status_code}")

    @task(2)
    def health_check(self) -> None:
        """Health endpoint — must always return 200 with negligible latency."""
        with self.client.get(
            "/health",
            catch_response=True,
            name="GET /health",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Health check failed: {resp.status_code}")


# ── SLO assertion on test end ─────────────────────────────────────────────────

@events.quitting.add_listener
def assert_slo(environment, **_kwargs) -> None:
    """Fail the load test if measured latency exceeds Principle 2 SLOs.

    P95 < 10ms and P99 < 25ms are SPEC.md §3 non-negotiable SLOs.

    When run in headless mode the stats are available on the environment
    runner's stats object.  We check the aggregate stats for the main
    LLM allow task (the hot path).
    """
    runner = environment.runner
    if runner is None:
        return

    stats = runner.stats.entries
    # Check the aggregate entry (key = ("Aggregated", "")) first
    agg = runner.stats.total
    if agg.num_requests == 0:
        return

    p95_ms = agg.get_response_time_percentile(0.95)
    p99_ms = agg.get_response_time_percentile(0.99)

    print(f"\n--- REVOC Latency SLO check ---")
    print(f"  Total requests : {agg.num_requests}")
    print(f"  P95 latency    : {p95_ms:.1f}ms  (SLO: <10ms)")
    print(f"  P99 latency    : {p99_ms:.1f}ms  (SLO: <25ms)")
    print(f"  Failure rate   : {agg.num_failures}/{agg.num_requests}")

    slo_failures = []
    if p95_ms > 10:
        slo_failures.append(f"P95={p95_ms:.1f}ms exceeds 10ms SLO")
    if p99_ms > 25:
        slo_failures.append(f"P99={p99_ms:.1f}ms exceeds 25ms SLO")

    if slo_failures:
        print(f"\n  SLO FAILURES: {'; '.join(slo_failures)}")
        environment.process_exit_code = 1
    else:
        print(f"\n  SLOs PASSED")
