"""Dashboard live-feed SSE test — crates/revoc-dashboard/src/live_feed.rs.

Isolated into its own module (named to sort last alphabetically) because
opening a long-lived SSE connection to the dashboard on :3000 has been
observed to disrupt Docker Desktop's host<->container port forwarding for
:8080/:3000/:8081 for the remainder of the pytest session on Windows. Running
it last ensures no other test is affected by that environment quirk.
"""

import asyncio
import json

import httpx

from .conftest import DASHBOARD_BASE, chat_payload


async def test_live_sse_delivers_events(proxy_client, dashboard_client):
    """Connect to /live (SSE), fire a governed request, and confirm a
    GovernanceEvent for that trace_id arrives on the live feed.

    The reader runs in the background and records every trace_id it sees, so
    an event that arrives before the POST returns is not missed.
    """
    timeout = httpx.Timeout(10.0, read=None)
    async with httpx.AsyncClient(base_url=DASHBOARD_BASE, timeout=timeout) as sse_client:
        async with sse_client.stream("GET", "/live") as sse_resp:
            assert sse_resp.status_code == 200

            seen_trace_ids: set[str] = set()
            seen_event = asyncio.Event()

            async def reader():
                async for line in sse_resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    try:
                        payload = json.loads(line[len("data: "):])
                    except json.JSONDecodeError:
                        continue
                    seen = payload.get("trace_id")
                    if seen:
                        seen_trace_ids.add(seen)
                        seen_event.set()

            reader_task = asyncio.create_task(reader())
            try:
                await asyncio.sleep(0.3)
                r = await proxy_client.post(
                    "/v1/chat/completions",
                    json=chat_payload("Hello from the live feed test"),
                )
                assert r.status_code == 200
                trace_id = r.headers["X-Revoc-Trace-ID"]

                async def wait_for_trace():
                    while trace_id not in seen_trace_ids:
                        seen_event.clear()
                        await seen_event.wait()

                try:
                    await asyncio.wait_for(wait_for_trace(), timeout=30.0)
                except asyncio.TimeoutError:
                    pass
            finally:
                reader_task.cancel()

            assert trace_id in seen_trace_ids, (
                "expected a live-feed event for the fired request's trace_id"
            )
