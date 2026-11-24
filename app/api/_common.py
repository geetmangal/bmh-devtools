"""Helpers shared by the email / DNSBL / SMTP / health / BGP API routers."""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator, Callable

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.mailcheck.models import clean_domain
from app.core.ratelimit import Gate
from app.core.validate import ValidationError

log = logging.getLogger("bmh_tools")


class DomainRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253, examples=["example.com"])


def valid_domain(raw: str) -> str:
    """Public-looking domain name (never an IP). 422 otherwise."""
    try:
        return clean_domain(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def nd(obj: Any) -> bytes:
    """One NDJSON line."""
    return (json.dumps(obj, separators=(",", ":"), default=str) + "\n").encode()


def ndjson_response(gen: AsyncIterator[bytes]) -> StreamingResponse:
    return StreamingResponse(gen, media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


async def guarded_stream(gate: Gate | None, producer: Callable[[], AsyncIterator[dict]]) -> AsyncIterator[bytes]:
    """NDJSON generator: runs ``producer`` inside the concurrency gate. A busy gate or an unexpected failure
    becomes a final {"type": "error"} line (the HTTP status is already 200 once streaming started)."""
    try:
        if gate is None:
            async for obj in producer():
                yield nd(obj)
        else:
            async with gate.slot():
                async for obj in producer():
                    yield nd(obj)
    except HTTPException as exc:
        yield nd({"type": "error", "status": exc.status_code, "message": str(exc.detail)})
    except Exception as exc:  # noqa: BLE001
        log.exception("stream failed")
        yield nd({"type": "error", "status": 500, "message": f"The check failed unexpectedly ({type(exc).__name__})."})
