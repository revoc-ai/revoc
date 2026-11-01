#!/usr/bin/env python3
"""Checks for scripts/proof.sh.

    proof_check.py canaries <path>         write canary values, print shell exports
    proof_check.py report <out-dir>        evaluate a run, write report.md/.json

The report has four gates, each of which must pass:

* latency  — latency phase: k6 thresholds (P95/P99 per scenario, no failed
             requests, every check passed)
* audit    — latency phase: no audit event dropped, and at least one audit
             row per request sent
* egress   — evidence phase: every connect()/sendto() address the proxy used
             is loopback, and the traffic still succeeded
* pii      — evidence phase: no canary value (PII, the client API key, the
             upstream key) appears in the proxy log, the audit database, or
             the request bodies the upstream received
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import secrets
import sqlite3
import string
import sys
from pathlib import Path

SCENARIOS = ["llm_clean", "llm_pii", "mcp_tool", "embeddings"]
UPSTREAM_KEY = "sk-proof-not-a-real-key"


# ── canaries ──────────────────────────────────────────────────────────────────


def make_canaries(path: Path) -> None:
    rng = random.SystemRandom()
    area = rng.choice([a for a in range(100, 666)])
    canaries = {
        "CANARY_EMAIL": f"canary.{secrets.token_hex(6)}@proof-mail.example",
        "CANARY_SSN": f"{area:03d}-{rng.randint(10, 99):02d}-{rng.randint(1000, 9999):04d}",
        "CANARY_AWS": "AKIA" + "".join(rng.choice(string.ascii_uppercase + "234567") for _ in range(16)),
    }
    path.write_text(json.dumps(canaries, indent=2))
    for k, v in canaries.items():
        print(f"export {k}='{v}'")


# ── latency ───────────────────────────────────────────────────────────────────


def _k6_exit(phase: Path) -> int:
    try:
        return int((phase / "k6.exit").read_text().strip())
    except (OSError, ValueError):
        return -1


def latency(out: Path) -> dict:
    k6_exit = _k6_exit(out)
    summary_path = out / "k6-summary.json"
    if not summary_path.exists():
        return {"ok": False, "error": "k6 summary missing", "k6_exit": k6_exit, "scenarios": {}}
    metrics = json.loads(summary_path.read_text())["metrics"]
    scenarios = {}
    failures = []
    for s in SCENARIOS:
        dur = metrics.get(f"http_req_duration{{scenario:{s}}}", {})
        vals = dur.get("values", {})
        reqs = metrics.get(f"http_reqs{{scenario:{s}}}", {}).get("values", {})
        failed = metrics.get(f"http_req_failed{{scenario:{s}}}", {}).get("values", {})
        row = {
            "requests": int(reqs.get("count", 0)),
            # Each scenario runs alone for DURATION seconds.
            "rps": round(reqs.get("count", 0) / max(int(os.environ.get("DURATION", "20")), 1), 1),
            "p50_ms": round(vals.get("med", float("nan")), 2),
            "p90_ms": round(vals.get("p(90)", float("nan")), 2),
            "p95_ms": round(vals.get("p(95)", float("nan")), 2),
            "p99_ms": round(vals.get("p(99)", float("nan")), 2),
            "max_ms": round(vals.get("max", float("nan")), 2),
            "failed_rate": failed.get("rate", 0.0),
        }
        for metric in (dur, metrics.get(f"http_req_failed{{scenario:{s}}}", {})):
            for expr, res in metric.get("thresholds", {}).items():
                if not res.get("ok", False):
                    failures.append(f"{s}: {expr}")
        if row["requests"] == 0:
            failures.append(f"{s}: no requests")
        scenarios[s] = row
    checks = metrics.get("checks", {})
    for expr, res in checks.get("thresholds", {}).items():
        if not res.get("ok", False):
            failures.append(f"checks: {expr} (pass rate {checks.get('values', {}).get('rate')})")
    return {
        "ok": not failures and k6_exit == 0,
        "k6_exit": k6_exit,
        "failures": failures,
        "scenarios": scenarios,
    }


# ── audit completeness ────────────────────────────────────────────────────────


def audit(out: Path) -> dict:
    try:
        total = int(json.loads((out / "k6-summary.json").read_text())["metrics"]["http_reqs"]["values"]["count"])
    except (OSError, KeyError, ValueError):
        total = 0
    try:
        counters = json.loads((out / "ready.json").read_text())["audit"]
    except (OSError, KeyError, ValueError):
        counters = {}
    rows = _audit_rows(out / "audit.db")
    dropped = int(counters.get("dropped", -1))
    return {
        "ok": total > 0 and dropped == 0 and rows >= total,
        "requests": total,
        "audit_rows": rows,
        "dropped": dropped,
        "batches": int(counters.get("batches", 0)),
    }


# ── egress ────────────────────────────────────────────────────────────────────

_INET = re.compile(r'inet_addr\("([^"]+)"\)')
_INET6 = re.compile(r'inet_pton\(AF_INET6, "([^"]+)"')


def egress(out: Path) -> dict:
    log = out / "strace.log"
    if not log.exists() or log.stat().st_size == 0:
        return {"ok": False, "error": "strace log missing or empty"}
    destinations: dict[str, int] = {}
    external: dict[str, int] = {}
    calls = 0
    for line in log.read_text(errors="replace").splitlines():
        if "connect(" not in line and "sendto(" not in line and "sendmsg(" not in line:
            continue
        addrs = _INET.findall(line) + _INET6.findall(line)
        if not addrs:
            continue  # AF_UNIX / AF_NETLINK: host-local
        calls += 1
        for a in addrs:
            destinations[a] = destinations.get(a, 0) + 1
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                external[a] = external.get(a, 0) + 1
                continue
            mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
            if not (ip.is_loopback or ip.is_unspecified or (mapped and mapped.is_loopback)):
                external[a] = external.get(a, 0) + 1
    return {
        "ok": calls > 0 and not external and _k6_exit(out) == 0,
        "traffic_ok": _k6_exit(out) == 0,
        "network_calls": calls,
        "destinations": destinations,
        "external": external,
    }


# ── pii ───────────────────────────────────────────────────────────────────────


def _db_text(db: Path) -> str:
    if not db.exists():
        return ""
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        parts = []
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            for row in con.execute(f'SELECT * FROM "{t}"'):  # noqa: S608 - table names from sqlite_master
                parts.extend(str(v) for v in row if v is not None)
        return "\n".join(parts)
    finally:
        con.close()


def _audit_rows(db: Path) -> int:
    if not db.exists():
        return 0
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return int(con.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
    finally:
        con.close()


def pii(out: Path, root: Path) -> dict:
    canaries = json.loads((root / "canaries.json").read_text())
    secrets_ = {
        **canaries,
        "CLIENT_API_KEY": (root / "api_keys.txt").read_text().strip(),
        "UPSTREAM_API_KEY": UPSTREAM_KEY,
    }
    sources = {
        "proxy log": (out / "proxy.log").read_text(errors="replace")
        if (out / "proxy.log").exists()
        else "",
        "audit database": _db_text(out / "audit.db"),
        "upstream request bodies": (out / "upstream-bodies.jsonl").read_text(errors="replace")
        if (out / "upstream-bodies.jsonl").exists()
        else "",
    }
    # The upstream must receive the provider key (it is how the proxy
    # authenticates); it only travels in a header, never in a body.
    leaks = []
    for src, text in sources.items():
        for name, value in secrets_.items():
            if value and value in text:
                leaks.append(f"{name} found in {src}")
    log_lines = sources["proxy log"].count("\n")
    trace_lines = sources["proxy log"].count('"level":"TRACE"')
    errors = []
    if log_lines == 0:
        errors.append("proxy log is empty")
    if trace_lines == 0:
        errors.append("no TRACE-level lines: logging was not at trace level")
    if not sources["upstream request bodies"]:
        errors.append("upstream recorded no request bodies")
    return {
        "ok": not leaks and not errors,
        "leaks": leaks,
        "errors": errors,
        "log_lines": log_lines,
        "trace_lines": trace_lines,
        "audit_rows": _audit_rows(out / "audit.db"),
        "upstream_bodies": sources["upstream request bodies"].count("\n"),
        "scanned_for": sorted(secrets_),
    }


# ── report ────────────────────────────────────────────────────────────────────


def render(r: dict) -> str:
    mark = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
    lat, au, eg, pi = r["latency"], r["audit"], r["egress"], r["pii"]
    lines = [
        "# REVOC proof run",
        "",
        f"Latency phase: {r['rate']} req/s per scenario for {r['duration']} s, measured "
        "end-to-end at the client (client → proxy → stub upstream → proxy → client, "
        f"loopback, API-key auth, SQLite audit). Gate: P95 < {r['p95_gate']} ms, "
        f"P99 < {r['p99_gate']} ms. Host: {r['host']}.",
        "",
        f"## Latency — {mark(lat['ok'])}",
        "",
        "| Scenario | Requests | req/s | P50 ms | P90 ms | P95 ms | P99 ms | Max ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s, v in lat.get("scenarios", {}).items():
        lines.append(
            f"| `{s}` | {v['requests']} | {v['rps']} | {v['p50_ms']} | {v['p90_ms']} | "
            f"{v['p95_ms']} | {v['p99_ms']} | {v['max_ms']} |"
        )
    for f in lat.get("failures", []) + ([lat["error"]] if "error" in lat else []):
        lines.append(f"- failed: {f}")
    lines += [
        "",
        f"## Audit completeness — {mark(au['ok'])}",
        "",
        f"{au['requests']} requests sent, {au['audit_rows']} audit rows written in "
        f"{au['batches']} batches, {au['dropped']} events dropped.",
        "",
        f"## No egress — {mark(eg['ok'])}",
        "",
        f"Evidence phase ({r['evidence_rate']} req/s per scenario under strace, trace-level logs; "
        f"traffic {'succeeded' if eg.get('traffic_ok') else 'FAILED'}). "
        f"{eg.get('network_calls', 0)} network connect/send calls traced; destinations: "
        + (", ".join(f"`{k}` ×{v}" for k, v in sorted(eg.get("destinations", {}).items())) or "none"),
    ]
    if eg.get("external"):
        lines.append(f"- **non-loopback destinations:** {eg['external']}")
    if "error" in eg:
        lines.append(f"- failed: {eg['error']}")
    lines += [
        "",
        f"## No PII or secrets in logs — {mark(pi['ok'])}",
        "",
        f"Scanned {pi['log_lines']} proxy log lines ({pi['trace_lines']} at TRACE), "
        f"{pi['audit_rows']} audit rows and {pi['upstream_bodies']} upstream request bodies for: "
        + ", ".join(f"`{s}`" for s in pi["scanned_for"])
        + ".",
    ]
    for item in pi["leaks"] + pi["errors"]:
        lines.append(f"- failed: {item}")
    lines += ["", f"**Overall: {mark(r['ok'])}**", ""]
    return "\n".join(lines)


def _host() -> str:
    cpus = os.cpu_count() or 0
    model = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return f"{cpus} CPUs" + (f", {model}" if model else "")


def report(out: Path) -> int:
    lat_dir, ev_dir = out / "latency", out / "evidence"
    ev_pii = pii(ev_dir, out)
    r = {
        "latency": latency(lat_dir),
        "audit": audit(lat_dir),
        "egress": egress(ev_dir),
        "pii": ev_pii,
        "rate": int(os.environ.get("RATE", "200")),
        "duration": int(os.environ.get("DURATION", "20")),
        "evidence_rate": int(os.environ.get("EVIDENCE_RATE", "50")),
        "p95_gate": os.environ.get("P95_MS", "10"),
        "p99_gate": os.environ.get("P99_MS", "25"),
        "host": _host(),
    }
    r["ok"] = all(r[k]["ok"] for k in ("latency", "audit", "egress", "pii"))
    md = render(r)
    (out / "report.json").write_text(json.dumps(r, indent=2))
    (out / "report.md").write_text(md)
    print(md)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    return 0 if r["ok"] else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("canaries")
    c.add_argument("path", type=Path)
    rp = sub.add_parser("report")
    rp.add_argument("out", type=Path)
    a = ap.parse_args()
    if a.cmd == "canaries":
        make_canaries(a.path)
        return 0
    return report(a.out)


if __name__ == "__main__":
    sys.exit(main())
