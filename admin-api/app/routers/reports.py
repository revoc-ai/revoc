from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.schemas.reports import ComplianceReportResponse
from app.services.report_service import ReportService

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

_report_svc = ReportService()


@router.get("", response_model=ComplianceReportResponse)
async def get_report(
    org_id: str = Query(...),
    start_time: str = Query(..., description="ISO-8601 datetime"),
    end_time: str = Query(..., description="ISO-8601 datetime"),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> ComplianceReportResponse:
    """Generate a JSON compliance report for the given time window."""
    from datetime import datetime

    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)
    return await _report_svc.generate(db, org_id, start, end)


@router.get("/csv")
async def get_report_csv(
    org_id: str = Query(...),
    start_time: str = Query(...),
    end_time: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> Response:
    """Download a CSV compliance report."""
    from datetime import datetime

    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)
    report = await _report_svc.generate(db, org_id, start, end)
    csv_bytes = _report_svc.to_csv(report)
    filename = f"revoc-report-{org_id}-{start.date()}.csv"
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/pdf")
async def get_report_pdf(
    org_id: str = Query(...),
    start_time: str = Query(...),
    end_time: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _user: Any = Depends(get_current_user),
) -> StreamingResponse:
    """Download a PDF compliance report."""
    from datetime import datetime

    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)
    report = await _report_svc.generate(db, org_id, start, end)
    pdf_bytes = _report_svc.to_pdf(report)
    filename = f"revoc-report-{org_id}-{start.date()}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
