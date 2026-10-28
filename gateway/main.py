"""Guard402 REST/MCP compatibility gateway to four canonical owned services."""

import hmac
import html
import json
import os
import time

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .autopatch_vault import (
    acquire_verified_bundle,
    audit_target,
    register_vault_entry,
    VerifiedPatchUnavailable,
)
from .service_engines import (
    MCP_TOOLS_CATALOG,
    TOOL_BY_NAME,
    UPSTREAM_TOOLS,
    get_mcp_tools_list,
    proxy_tool_call,
    InputValidationError,
)
from .ssrf_guard import SSRFBlockedError
from .x402_engine import get_payout_wallet

BOOT_TIME = time.time()
app = FastAPI(title="Guard402 Canonical Service Gateway", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["Content-Type", "PAYMENT-SIGNATURE", "X-PAYMENT", "Authorization"],
    expose_headers=[
        "PAYMENT-REQUIRED",
        "PAYMENT-RESPONSE",
        "X-Payment-Required",
        "X-402-Payment-Required",
        "WWW-Authenticate",
        "Retry-After",
    ],
)


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputValidationError("Duplicate JSON keys are unsupported")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise InputValidationError("Non-finite JSON numbers are unsupported")


def _extract_payment_header(request):
    values = [
        request.headers.get(key)
        for key in ("PAYMENT-SIGNATURE", "X-PAYMENT", "X-Payment-Signature")
        if request.headers.get(key)
    ]
    if len(set(values)) > 1:
        raise InputValidationError("Conflicting payment headers")
    return values[0] if values else None


async def _request_arguments(request):
    args = dict(request.query_params)
    if len(args) != len(request.query_params.multi_items()):
        raise InputValidationError("Duplicate query parameters are unsupported")
    if request.method == "POST":
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 1_048_576:
                raise InputValidationError("JSON request exceeds 1 MiB")
        try:
            body = json.loads(
                raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_invalid_json_constant,
            )
        except (ValueError, UnicodeError):
            raise InputValidationError("Expected a JSON object")
        if not isinstance(body, dict):
            raise InputValidationError("Expected a JSON object")
        for key, value in body.items():
            if key in args and args[key] != value:
                raise InputValidationError("Conflicting query/body argument " + key)
            args[key] = value
    return args


def _failure(error, req_id=None):
    if isinstance(error, SSRFBlockedError):
        data = {"error": "ssrf_blocked", "rule": error.rule, "detail": error.message}
        message = "SSRF Guard Blocked URL: " + error.message
    else:
        data = {"error": "invalid_arguments", "detail": str(error)}
        message = str(error)
    if req_id is not None:
        data = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": message},
        }
    return JSONResponse(status_code=400, content=data)


def _vault_unavailable():
    return JSONResponse(
        status_code=503,
        content={
            "error": "VERIFIED_PATCH_UNAVAILABLE",
            "payment_collected": False,
            "message": "Target source acquisition and verified target-bound patches are unavailable. No payment challenge or settlement is created.",
        },
    )


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "guard402-autonomous-engine",
        "version": __version__,
        "tool_count": len(MCP_TOOLS_CATALOG),
        "proxied_tools": len(UPSTREAM_TOOLS),
        "unavailable_vault_tools": 2,
        "payout_wallet_base": get_payout_wallet(),
        "payment_mode": "canonical_upstream_only",
        "vault_count": 0,
        "uptime_seconds": round(time.time() - BOOT_TIME, 3),
    }


@app.get("/version")
async def version_endpoint():
    return {
        "service": "guard402-autonomous-engine",
        "version": __version__,
        "revision": os.getenv("RENDER_GIT_COMMIT")
        or os.getenv("GIT_COMMIT")
        or "unknown",
    }


@app.get("/")
async def storefront_home():
    rows = "".join(
        f"<tr><td>{html.escape(t['title'])}</td><td>{html.escape(t['price_usd'])} USDC</td><td>{html.escape(t['description'])}</td></tr>"
        for t in MCP_TOOLS_CATALOG
    )
    return HTMLResponse(
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Guard402 AutoPatch Vault and Service Gateway</title><body><h1>Guard402 AutoPatch Vault and Service Gateway</h1><p>Use the REST aliases or MCP endpoint to access the canonical services. The upstream payment challenge sets the exact price and resource. Guard adds no second charge.</p><p>AutoPatch purchases are unavailable until source acquisition and target-specific patch verification are implemented.</p><table><thead><tr><th>Tool</th><th>Reference price</th><th>Coverage</th></tr></thead><tbody>"
        + rows
        + "</tbody></table><p><a href='/docs'>API documentation</a> · <a href='/.well-known/x402.json'>Service catalog</a></p></body></html>"
    )


@app.get("/.well-known/x402.json")
async def well_known_x402():
    return {
        "x402Version": 2,
        "service": "guard402-autonomous-engine",
        "payment_mode": "canonical_upstream_only",
        "local_free_quota": 0,
        "vault_purchases_available": False,
        "tools": [
            {
                k: t[k]
                for k in (
                    "name",
                    "description",
                    "price_usd",
                    "amount_units",
                    "upstream",
                )
            }
            for t in MCP_TOOLS_CATALOG
        ],
    }


@app.get("/.well-known/mcp.json")
@app.get("/.well-known/mcp")
async def well_known_mcp():
    return {
        "name": "Guard402",
        "version": __version__,
        "transport": "streamable-http",
        "endpoint": "/mcp",
        "payment_mode": "canonical_upstream_only",
        "tools": get_mcp_tools_list(),
    }


@app.get("/mcp")
async def mcp_get():
    return {
        "status": "ok",
        "protocol": "model-context-protocol",
        "tools": get_mcp_tools_list(),
    }


@app.head("/mcp")
@app.options("/mcp")
async def mcp_transport():
    return Response(status_code=200)


@app.post("/mcp")
async def mcp_post(request: Request):
    try:
        payload = await _request_arguments(request)
    except InputValidationError as error:
        return _failure(error)
    req_id, method = payload.get("id"), payload.get("method")
    params = payload.get("params", {})
    if payload.get("jsonrpc") != "2.0" or not isinstance(params, dict):
        return _failure(InputValidationError("Invalid JSON-RPC request"), req_id)
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "guard402-autonomous-engine",
                "version": __version__,
            },
        }
    elif method == "tools/list":
        result = {"tools": get_mcp_tools_list()}
    elif method in ("ping", "notifications/initialized"):
        if req_id is None:
            return Response(status_code=204)
        result = {}
    elif method in ("resources/list", "resources/templates/list", "prompts/list"):
        result = {
            {
                "resources/list": "resources",
                "resources/templates/list": "resourceTemplates",
                "prompts/list": "prompts",
            }[method]: []
        }
    elif method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or name not in TOOL_BY_NAME:
            return JSONResponse(
                status_code=404,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": "Unknown tool"},
                },
            )
        try:
            status, headers, body = await proxy_tool_call(
                name, params.get("arguments", {}), _extract_payment_header(request)
            )
        except (InputValidationError, SSRFBlockedError) as error:
            return _failure(error, req_id)
        result = {
            "content": [{"type": "text", "text": json.dumps(body)}],
            "structuredContent": body,
            "isError": status >= 400,
        }
        return JSONResponse(
            status_code=status,
            headers=headers,
            content={"jsonrpc": "2.0", "id": req_id, "result": result},
        )
    else:
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Method not found"},
            },
        )
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


@app.post("/mcp/reset-quota")
async def mcp_reset_quota_endpoint():
    return JSONResponse(status_code=410, content={"error": "QUOTA_RESET_REMOVED"})


@app.get("/v1/audit-target")
@app.post("/v1/audit-target")
async def audit_target_endpoint(request: Request):
    try:
        args = await _request_arguments(request)
        audit_target(
            args.get("target") or args.get("url") or args.get("contractAddress")
        )
    except (ValueError, SSRFBlockedError) as error:
        return _failure(error)
    except VerifiedPatchUnavailable:
        return _vault_unavailable()
    return _vault_unavailable()


@app.post("/v1/vault/register")
async def vault_register_endpoint(request: Request):
    token = os.getenv("GUARD402_VAULT_ADMIN_TOKEN", "")
    if len(token) < 32:
        return JSONResponse(
            status_code=503, content={"error": "VAULT_ADMIN_AUTH_NOT_CONFIGURED"}
        )
    supplied = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied.encode(), ("Bearer " + token).encode()):
        return JSONResponse(
            status_code=401, content={"error": "VAULT_ADMIN_AUTH_REQUIRED"}
        )
    # Authentication is necessary but cannot turn an uploaded claim into evidence.
    return _vault_unavailable()


@app.get("/v1/unlock-patch/{audit_id}")
@app.post("/v1/unlock-patch/{audit_id}")
async def unlock_patch_endpoint(audit_id: str, request: Request):
    try:
        acquire_verified_bundle(audit_id)
    except VerifiedPatchUnavailable:
        return _vault_unavailable()
    # Keep settlement disabled even if acquisition is later replaced accidentally.
    return _vault_unavailable()


ROUTE_TO_TOOL = {
    "/v1/canaryguard/sanitize": "canaryguard_sanitize_prompt",
    "/v1/canaryguard/firewall": "canaryguard_sanitize_prompt",
    "/v1/canaryguard/audit-mcp": "canaryguard_audit_mcp_schema",
    "/v1/canaryguard/verify-eip712": "canaryguard_verify_eip712",
    "/v1/stealthguard/sanitize-url": "stealthguard_sanitize_url",
    "/v1/stealthguard/scrape": "stealthguard_sanitize_url",
    "/v1/stealthguard/polymarket-whales": "stealthguard_polymarket_whale_radar",
    "/v1/stealthguard/odds-divergence": "stealthguard_odds_divergence",
    "/v1/rugshield/scan": "rugshield_scan_token",
    "/v1/rugshield/simulate-honeypot": "rugshield_simulate_honeypot",
    "/v1/rugshield/sybil-clusters": "rugshield_sybil_cluster_map",
    "/v1/tollbooth/ai-intel": "tollbooth_ai_intel",
    "/v1/tollbooth/arbitrage": "tollbooth_arbitrage_scan",
    "/v1/tollbooth/router": "tollbooth_smart_router",
    "/v1/tollbooth/audit": "tollbooth_contract_audit",
    "/toll/ai-intel": "tollbooth_ai_intel",
    "/toll/ai_intel": "tollbooth_ai_intel",
    "/toll/arbitrage": "tollbooth_arbitrage_scan",
    "/toll/arbitrage_scan": "tollbooth_arbitrage_scan",
    "/toll/router": "tollbooth_smart_router",
    "/toll/smart_router": "tollbooth_smart_router",
    "/api/audit": "tollbooth_contract_audit",
}


async def _handle_tier1_rest(request: Request, name):
    try:
        args = await _request_arguments(request)
        status, headers, body = await proxy_tool_call(
            name,
            args,
            _extract_payment_header(request),
            query_strings=request.method == "GET",
        )
        return JSONResponse(status_code=status, headers=headers, content=body)
    except (InputValidationError, SSRFBlockedError) as error:
        return _failure(error)


def _handler(name):
    async def endpoint(request: Request):
        return await _handle_tier1_rest(request, name)

    return endpoint


for index, (path, name) in enumerate(ROUTE_TO_TOOL.items()):
    for method in ("GET", "POST"):
        app.add_api_route(
            path,
            _handler(name),
            methods=[method],
            name=f"canonical_alias_{index}_{method.lower()}",
            operation_id=f"canonical_alias_{index}_{method.lower()}",
        )
