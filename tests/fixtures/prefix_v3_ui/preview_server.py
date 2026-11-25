"""Test-only preview of the BGP prefix tabs UI without the backend or Turnstile.

    cd <repo> && python tests/fixtures/prefix_v3_ui/preview_server.py [port]      # default 8765
    open http://127.0.0.1:8765/tools/bgp-prefix-lookup?q=160.22.108.0/24#validation

It mounts the real app (templates, JS, CSS) and puts three fixture routes in front of the real API routes. Special
prefixes: 10.x -> sparse report (every optional source null); 192.0.2.x -> whois and rdns answer 502 (retry UI).
Nothing here is imported by the app; it is not part of the production image.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from app.core.config import API_PREFIX  # noqa: E402
from app.main import app  # noqa: E402

FX = pathlib.Path(__file__).parent
load = lambda n: json.loads((FX / n).read_text())  # noqa: E731


async def prefix(request):
    p = request.path_params["prefix"]
    if p.startswith("10."):
        return JSONResponse({**load("prefix-sparse.json"), "prefix": p, "queried": p})
    return JSONResponse({**load("prefix.json"), "prefix": p, "queried": p})


async def whois(request):
    if request.path_params["prefix"].startswith("192.0.2."):
        return JSONResponse({"detail": "The registry did not answer."}, status_code=502)
    return JSONResponse(load("whois.json"))


async def rdns(request):
    body = await request.json()
    if str(body.get("prefix", "")).startswith("192.0.2."):
        return JSONResponse({"detail": "Reverse DNS scan unavailable."}, status_code=502)
    return JSONResponse({**load("rdns.json"), "prefix": body.get("prefix")})


app.router.routes[0:0] = [
    Route(f"{API_PREFIX}/prefix/{{prefix:path}}", prefix, methods=["GET"]),
    Route(f"{API_PREFIX}/prefix-whois/{{prefix:path}}", whois, methods=["GET"]),
    Route(f"{API_PREFIX}/prefix-rdns", rdns, methods=["POST"]),
]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
