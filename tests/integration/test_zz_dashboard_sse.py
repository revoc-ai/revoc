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
    GovernanceEvent for that trace_id arrives on the live feed."""
    async with httpx.AsyncClient(base_url=DASHBOARD_BASE, timeout=15.0) as sse_client:
        async with sse_client.stream("GET", "/live") as sse_resp:
            assert sse_resp.status_code == 200

            async def fire_request():
                await asyncio.sleep(0.3)
                r = await proxy_client.post(
                    "/v1/chat/completions",
                    json=chat_payload("Hello from the live feed test"),
                )
                assert r.status_code == 200
                return r.headers["X-Revoc-Trace-ID"]

            fire_task = asyncio.create_task(fire_request())

            found = False
            trace_id = None
            seen_trace_ids: set[str] = set()

            async def read_until_found():
                nonlocal found, trace_id
                async for line in sse_resp.aiter_lines():
                    if fire_task.done() and trace_id is None:
                        trace_id = fire_task.result()
                        if trace_id in seen_trace_ids:
                            found = True
                            return
                    if line.startswith("data: "):
                        try:
                            payload = json.loads(line[len("data: "):])
                        except json.JSONDecodeError:
                            continue
                        seen = payload.get("trace_id")
                        if seen:
                            seen_trace_ids.add(seen)
                        if trace_id and seen == trace_id:
                            found = True
                            return
                    if fire_task.done() and found:
                        return

            try:
                await asyncio.wait_for(read_until_found(), timeout=30.0)
            except asyncio.TimeoutError:
                pass
            finally:
                if not fire_task.done():
                    fire_task.cancel()
                elif trace_id and trace_id in seen_trace_ids:
                    found = True

            assert found, "expected a live-feed event for the fired request's trace_id"
