from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent
from app.schemas.audit import AuditStatsResponse
from app.schemas.reports import ComplianceReportResponse


class ReportService:
    """Generate compliance reports from audit event data."""

    async def generate(
        self,
        db: AsyncSession,
        org_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> ComplianceReportResponse:
        stmt = (
            select(AuditEvent)
            .where(
                AuditEvent.org_id == org_id,
                AuditEvent.timestamp >= start_time.isoformat(),
                AuditEvent.timestamp <= end_time.isoformat(),
            )
            .order_by(AuditEvent.timestamp.asc())
        )
        result = await db.execute(stmt)
        events = list(result.scalars().all())

        total = len(events)
        blocked = sum(1 for e in events if e.decision == "block")
        redacted = sum(1 for e in events if e.decision == "redact")
        allowed = sum(1 for e in events if e.decision == "allow")

        # Top violated rules
        rule_counts: dict[str, int] = {}
        for ev in events:
            if ev.violated_rules:
                try:
                    rules: list[str] = json.loads(ev.violated_rules)
                    for r in rules:
                        rule_counts[r] = rule_counts.get(r, 0) + 1
                except (ValueError, TypeError):
                    pass

        top_rules: list[dict[str, Any]] = sorted(
            [{"rule_id": k, "count": v} for k, v in rule_counts.items()],
            key=lambda x: cast(int, x["count"]),
            reverse=True,
        )[:10]

        # Top callers by event volume
        caller_counts: dict[str, int] = {}
        for ev in events:
            if ev.caller_id:
                caller_counts[ev.caller_id] = caller_counts.get(ev.caller_id, 0) + 1

        top_callers: list[dict[str, Any]] = sorted(
            [{"caller_id": k, "count": v} for k, v in caller_counts.items()],
            key=lambda x: cast(int, x["count"]),
            reverse=True,
        )[:10]

        summary = AuditStatsResponse(
            total=total,
            blocked=blocked,
            redacted=redacted,
            allowed=allowed,
            top_rules=top_rules,
            top_callers=top_callers,
        )

        timeline = self._build_timeline(events, start_time, end_time)

        return ComplianceReportResponse(
            org_id=org_id,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
            timeline=timeline,
            top_violations=top_rules,
            generated_at=datetime.now(UTC),
        )

    @staticmethod
    def _build_timeline(
        events: list[AuditEvent],
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict[str, Any]]:
        """Bucket audit events into chronological windows for the report timeline.

        Buckets by hour when the report spans <= 48 hours (fine-grained view for
        short incident-response windows), otherwise by day (coarser view for
        longer compliance periods). Each bucket reports real counts derived
        directly from the queried events — never fabricated or interpolated.
        """
        span = end_time - start_time
        bucket_size = timedelta(hours=1) if span <= timedelta(hours=48) else timedelta(days=1)

        def bucket_start(ts: datetime) -> datetime:
            if bucket_size == timedelta(hours=1):
                return ts.replace(minute=0, second=0, microsecond=0)
            return ts.replace(hour=0, minute=0, second=0, microsecond=0)

        buckets: dict[datetime, dict[str, int]] = {}
        for ev in events:
            try:
                ts = datetime.fromisoformat(ev.timestamp)
            except (ValueError, TypeError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)

            key = bucket_start(ts)
            bucket = buckets.setdefault(
                key,
                {"total": 0, "blocked": 0, "redacted": 0, "allowed": 0, "audited": 0},
            )
            bucket["total"] += 1
            if ev.decision == "block":
                bucket["blocked"] += 1
            elif ev.decision == "redact":
                bucket["redacted"] += 1
            elif ev.decision == "allow":
                bucket["allowed"] += 1
            elif ev.decision == "audit":
                bucket["audited"] += 1

        return [
            {
                "bucket": key.isoformat(),
                "bucket_size": "hour" if bucket_size == timedelta(hours=1) else "day",
                "total": counts["total"],
                "blocked": counts["blocked"],
                "redacted": counts["redacted"],
                "allowed": counts["allowed"],
                "audited": counts["audited"],
            }
            for key, counts in sorted(buckets.items(), key=lambda kv: kv[0])
        ]

    def to_csv(self, report: ComplianceReportResponse) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)

        writer.writerow(["REVOC Compliance Report"])
        writer.writerow(["Organisation", report.org_id])
        period = f"{report.start_time.isoformat()} — {report.end_time.isoformat()}"
        writer.writerow(["Period", period])
        writer.writerow(["Generated", report.generated_at.isoformat()])
        writer.writerow([])
        writer.writerow(["Metric", "Count"])
        writer.writerow(["Total events", report.summary.total])
        writer.writerow(["Blocked", report.summary.blocked])
        writer.writerow(["Redacted", report.summary.redacted])
        writer.writerow(["Allowed", report.summary.allowed])
        writer.writerow([])
        writer.writerow(["Top Violated Rules"])
        writer.writerow(["Rule ID", "Count"])
        for rule in report.summary.top_rules:
            writer.writerow([rule.get("rule_id", ""), rule.get("count", 0)])
        writer.writerow([])
        writer.writerow(["Top Callers"])
        writer.writerow(["Caller ID", "Count"])
        for caller in report.summary.top_callers:
            writer.writerow([caller.get("caller_id", ""), caller.get("count", 0)])

        return buf.getvalue().encode("utf-8")

    def to_pdf(self, report: ComplianceReportResponse) -> bytes:
        from weasyprint import HTML

        html = self._report_to_html(report)
        pdf: bytes = HTML(string=html).write_pdf()
        return pdf

    # ── private ───────────────────────────────────────────────────────────────

    def _report_to_html(self, report: ComplianceReportResponse) -> str:
        rules_rows = "".join(
            f"<tr><td>{r.get('rule_id', '')}</td><td>{r.get('count', 0)}</td></tr>"
            for r in report.summary.top_rules
        )
        callers_rows = "".join(
            f"<tr><td>{c.get('caller_id', '')}</td><td>{c.get('count', 0)}</td></tr>"
            for c in report.summary.top_callers
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>REVOC Compliance Report — {report.org_id}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #1a1a2e; }}
    h1 {{ color: #0f3460; border-bottom: 2px solid #0f3460; padding-bottom: 8px; }}
    h2 {{ color: #0f3460; margin-top: 32px; }}
    .meta {{ color: #555; font-size: 0.9em; margin-bottom: 24px; }}
    .metrics {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
    .metric {{ padding: 16px 24px; border-radius: 8px; background: #f0f4f8;
               min-width: 110px; text-align: center; }}
    .metric-label {{ font-size: 0.85em; color: #666; }}
    .metric-value {{ font-size: 2em; font-weight: bold; color: #0f3460; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th {{ background: #0f3460; color: #fff; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .footer {{ margin-top: 40px; font-size: 0.8em; color: #999; }}
  </style>
</head>
<body>
  <h1>REVOC Compliance Report</h1>
  <div class="meta">
    <p><strong>Organisation:</strong> {report.org_id}</p>
    <p><strong>Period:</strong> {report.start_time.strftime("%Y-%m-%d %H:%M UTC")}
       &ndash; {report.end_time.strftime("%Y-%m-%d %H:%M UTC")}</p>
    <p><strong>Generated:</strong> {report.generated_at.strftime("%Y-%m-%d %H:%M UTC")}</p>
  </div>

  <h2>Summary</h2>
  <div class="metrics">
    <div class="metric">
      <div class="metric-label">Total</div>
      <div class="metric-value">{report.summary.total}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Blocked</div>
      <div class="metric-value">{report.summary.blocked}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Redacted</div>
      <div class="metric-value">{report.summary.redacted}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Allowed</div>
      <div class="metric-value">{report.summary.allowed}</div>
    </div>
  </div>

  <h2>Top Violated Rules</h2>
  <table>
    <tr><th>Rule ID</th><th>Count</th></tr>
    {rules_rows or "<tr><td colspan='2'>No violations in period</td></tr>"}
  </table>

  <h2>Top Callers</h2>
  <table>
    <tr><th>Caller ID</th><th>Events</th></tr>
    {callers_rows or "<tr><td colspan='2'>No data</td></tr>"}
  </table>

  <div class="footer">Generated by REVOC &mdash; revoc.io</div>
</body>
</html>"""
