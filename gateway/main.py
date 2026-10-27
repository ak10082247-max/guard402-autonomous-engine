"""
Guard402 Autonomous Engine — Unified FastAPI/Starlette MCP & x402 V2 Gateway.
Exposes:
  - Zero-Cold-Start MCP JSON-RPC 2.0 Server at /mcp (<50ms SLA, 2025-06-18 annotations, 3 free daily calls/IP)
  - Tier 1 M2M Micro-Call REST Endpoints ($0.002 - $0.01 USDC on Base & Solana via x402 V2)
  - Tier 2 AutoPatch Vault Self-Serve Remediation Bundle ($39.00 USDC at /v1/audit-target & /v1/unlock-patch/{audit_id})
  - Interactive Self-Serve Web Storefront at GET /
"""

import json
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .autopatch_vault import (
    AUTOPATCH_AMOUNT_UNITS,
    AUTOPATCH_PRICE_USD,
    audit_target,
    count_vault_entries,
    get_vault_entry,
    init_vault_db,
    list_recent_vault_entries,
    mark_vault_unlocked,
    register_vault_entry,
    render_storefront_html,
    render_unlock_checkout_html,
    seed_default_vault_entries,
)
from .service_engines import (
    MCP_TOOLS_CATALOG,
    TOOL_BY_NAME,
    execute_tool_call,
    get_mcp_tools_list,
)
from .ssrf_guard import SSRFBlockedError, assert_safe_url
from .x402_engine import (
    BASE_CHAIN_ID,
    BASE_NETWORK,
    BASE_USDC_ASSET,
    FREE_CALL_QUOTA_LIMIT,
    PUBLIC_BASE_URL,
    SOLANA_NETWORK,
    SOLANA_USDC_MINT,
    SOLANA_WALLET_ADDRESS,
    build_x402_challenge,
    check_and_increment_free_quota,
    encode_payment_response_header,
    get_payout_wallet,
    reset_free_quota,
    verify_x402_payment,
)

BOOT_TIME = time.time()

app = FastAPI(
    title="Guard402 Autonomous Engine & AutoPatch Vault",
    version=__version__,
    description=(
        "Unified x402 V2 M2M Security Intelligence Gateway (CanaryGuard, StealthGuard, "
        "RugShield, Agent Tollbooth) & Self-Serve AutoPatch Remediation Vault on Base Mainnet."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=[
        "PAYMENT-REQUIRED",
        "PAYMENT-RESPONSE",
        "WWW-Authenticate",
        "X-Payment-Required",
        "X-402-Payment-Required",
        "X-402-Version",
        "X-402-Payment-To",
        "X-402-Amount",
        "X-402-Amount-Units",
        "X-402-Asset",
        "X-402-Network",
    ],
)


@app.on_event("startup")
def _on_startup() -> None:
    init_vault_db()
    seed_default_vault_entries()


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _extract_payment_header(request: Request) -> Optional[str]:
    for h in ("PAYMENT-SIGNATURE", "payment-signature", "X-PAYMENT", "x-payment", "X-Payment-Signature"):
        val = request.headers.get(h)
        if val:
            return val
    return None


def _is_force_402(request: Request) -> bool:
    if request.query_params.get("force_402") in ("1", "true", "yes"):
        return True
    if request.headers.get("x-force-402") in ("1", "true", "yes"):
        return True
    return False


# ---------------------------------------------------------------------------
# 1. Health, Storefront & Discovery Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def storefront_home(request: Request) -> Response:
    seed_default_vault_entries()
    recent = list_recent_vault_entries(limit=8)
    html_body = render_storefront_html(recent_audits=recent, tool_count=len(MCP_TOOLS_CATALOG))
    return HTMLResponse(content=html_body, status_code=200)


@app.get("/health")
@app.head("/health")
async def health_check() -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "service": "guard402-autonomous-engine",
            "version": __version__,
            "uptime_seconds": round(time.time() - BOOT_TIME, 3),
            "mcp_protocol_version": "2025-06-18",
            "tool_count": len(MCP_TOOLS_CATALOG),
            "vault_count": count_vault_entries(),
            "payout_wallet_base": get_payout_wallet(),
            "payout_wallet_solana": SOLANA_WALLET_ADDRESS,
            "network_base": BASE_NETWORK,
            "asset_base_usdc": BASE_USDC_ASSET,
        },
    )


@app.get("/.well-known/mcp.json")
async def well_known_mcp(request: Request) -> JSONResponse:
    base_url = str(request.base_url).rstrip("/") or PUBLIC_BASE_URL
    return JSONResponse(
        status_code=200,
        content={
            "mcpVersion": "2025-06-18",
            "name": "guard402-autonomous-engine",
            "title": "Guard402 Autonomous Security & AutoPatch Engine",
            "version": __version__,
            "description": "Unified MCP security firewall, Polymarket whale radar, RugShield honeypot simulator, and AutoPatch remediation vault.",
            "endpoints": {
                "streamableHttp": f"{base_url}/mcp",
                "sse": f"{base_url}/mcp",
            },
            "authentication": {"type": "none", "freeDailyCallsPerIp": FREE_CALL_QUOTA_LIMIT, "x402Version": 2},
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False},
                "prompts": {"listChanged": False},
            },
            "tools": get_mcp_tools_list(),
        },
    )


@app.get("/.well-known/x402.json")
async def well_known_x402(request: Request) -> JSONResponse:
    base_url = str(request.base_url).rstrip("/") or PUBLIC_BASE_URL
    pay_to = get_payout_wallet()
    return JSONResponse(
        status_code=200,
        content={
            "x402Version": 2,
            "service": "guard402-autonomous-engine",
            "version": __version__,
            "payoutWalletBase": pay_to,
            "payoutWalletSolana": SOLANA_WALLET_ADDRESS,
            "networks": [
                {"network": BASE_NETWORK, "chainId": BASE_CHAIN_ID, "asset": BASE_USDC_ASSET, "payTo": pay_to},
                {"network": SOLANA_NETWORK, "asset": SOLANA_USDC_MINT, "payTo": SOLANA_WALLET_ADDRESS},
            ],
            "tiers": {
                "tier1_m2m_micro_calls": {
                    "price_range_usdc": "0.002 - 0.010",
                    "mcp_endpoint": f"{base_url}/mcp",
                    "free_daily_calls_per_ip": FREE_CALL_QUOTA_LIMIT,
                },
                "tier2_autopatch_vault": {
                    "price_usdc": AUTOPATCH_PRICE_USD,
                    "amount_units": AUTOPATCH_AMOUNT_UNITS,
                    "audit_endpoint": f"{base_url}/v1/audit-target",
                    "unlock_endpoint_template": f"{base_url}/v1/unlock-patch/{{audit_id}}",
                },
            },
            "tools": [
                {
                    "name": t["name"],
                    "title": t["title"],
                    "price_usd": t["price_usd"],
                    "amount_units": t["amount_units"],
                }
                for t in MCP_TOOLS_CATALOG
            ],
        },
    )


# ---------------------------------------------------------------------------
# 2. Zero-Cold-Start MCP JSON-RPC 2.0 Endpoint (/mcp)
# ---------------------------------------------------------------------------

@app.options("/mcp")
async def mcp_options() -> Response:
    return Response(status_code=200)


@app.head("/mcp")
async def mcp_head() -> Response:
    return Response(status_code=200, headers={"Content-Type": "application/json"})


@app.get("/mcp")
async def mcp_get() -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={
            "jsonrpc": "2.0",
            "status": "ready",
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "guard402-autonomous-engine", "version": __version__},
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False},
                "prompts": {"listChanged": False},
            },
            "toolsCount": len(MCP_TOOLS_CATALOG),
        },
    )


@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    try:
        raw_body = await request.body()
        if not raw_body:
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": "guard402-autonomous-engine", "version": __version__},
                    },
                },
            )
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}},
        )

    # Support JSON-RPC batch or single object
    if isinstance(payload, list):
        if not payload:
            return JSONResponse(status_code=200, content=[])
        payload = payload[0]

    req_id = payload.get("id")
    method = str(payload.get("method") or "").strip()
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}

    # ZERO-AUTH <50ms FAST-PATH FOR ALL REGISTRY & DISCOVERY METHODS
    if method == "initialize":
        client_proto = params.get("protocolVersion") or "2025-06-18"
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": client_proto,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {" subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "guard402-autonomous-engine",
                        "title": "Guard402 Autonomous Security & AutoPatch Engine",
                        "version": __version__,
                    },
                    "instructions": (
                        "Guard402 Autonomous Engine provides 15 MCP security, DeFi intelligence, and "
                        "AutoPatch remediation tools. First 3 calls/day per IP are free; further calls use x402 V2 on Base."
                    ),
                },
            },
        )

    if method in ("notifications/initialized", "notifications/cancelled"):
        return JSONResponse(status_code=200, content={"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "ping":
        return JSONResponse(status_code=200, content={"jsonrpc": "2.0", "id": req_id, "result": {}})

    if method == "tools/list":
        return JSONResponse(
            status_code=200,
            content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": get_mcp_tools_list()}},
        )

    if method == "resources/list":
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": [
                        {
                            "uri": "guard402://autopatch/catalog",
                            "name": "AutoPatch Vault Remediation Catalog",
                            "description": "Pre-computed static security scorecards and unified diffs",
                            "mimeType": "application/json",
                        }
                    ]
                },
            },
        )

    if method == "resources/templates/list":
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resourceTemplates": [
                        {
                            "uriTemplate": "guard402://autopatch/scorecard/{audit_id}",
                            "name": "AutoPatch Scorecard by Audit ID",
                            "description": "Retrieve Diagnostic Scorecard for an audit_id",
                            "mimeType": "application/json",
                        }
                    ]
                },
            },
        )

    if method == "prompts/list":
        return JSONResponse(
            status_code=200,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": [
                        {
                            "name": "audit_mcp_repository",
                            "description": "Run a full MCP 2025-06-18 & SSRF security audit on a repository URL",
                            "arguments": [{"name": "target", "description": "GitHub repository URL", "required": True}],
                        }
                    ]
                },
            },
        )

    if method == "tools/call":
        tool_name = str(params.get("name") or "").strip()
        tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        tool_meta = TOOL_BY_NAME.get(tool_name)
        if not tool_meta:
            return JSONResponse(
                status_code=404,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool '{tool_name}'"},
                },
            )

        # Always enforce SSRF Guard before executing or charging
        try:
            for url_key in ("url", "server_url", "target_url", "webhook_url", "endpoint"):
                if tool_args.get(url_key):
                    assert_safe_url(str(tool_args[url_key]), resolve_dns=True)
        except SSRFBlockedError as ssrf_err:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"SSRF Guard Blocked URL: {ssrf_err.message}",
                        "data": {"rule": ssrf_err.rule, "blocked_url": ssrf_err.url},
                    },
                },
            )

        payment_header = _extract_payment_header(request)
        force_402 = _is_force_402(request)
        client_ip = _extract_client_ip(request)
        resource_url = str(request.url)

        payment_info: Optional[Dict[str, Any]] = None
        if payment_header:
            ok, p_info, p_err, p_status = verify_x402_payment(
                raw_header=payment_header,
                required_units=int(tool_meta["amount_units"]),
                resource_url=resource_url,
                tool_name=tool_name,
            )
            if not ok:
                c_headers, c_body = build_x402_challenge(
                    tool_name=tool_name,
                    price_usd=tool_meta["price_usd"],
                    amount_units=tool_meta["amount_units"],
                    description=tool_meta["description"],
                    resource_url=resource_url,
                    mode="mcp",
                    input_schema=tool_meta["inputSchema"],
                    extra_body={"jsonrpc": "2.0", "id": req_id, "details": p_err},
                )
                return JSONResponse(status_code=p_status, content=c_body, headers=c_headers)
            payment_info = p_info
        else:
            allowed_free, used_today, remaining_free = check_and_increment_free_quota(
                client_ip=client_ip,
                force_402=force_402,
            )
            if not allowed_free:
                c_headers, c_body = build_x402_challenge(
                    tool_name=tool_name,
                    price_usd=tool_meta["price_usd"],
                    amount_units=tool_meta["amount_units"],
                    description=tool_meta["description"],
                    resource_url=resource_url,
                    mode="mcp",
                    input_schema=tool_meta["inputSchema"],
                    extra_body={
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "free_quota_exhausted": True,
                        "daily_free_limit": FREE_CALL_QUOTA_LIMIT,
                        "calls_used_today": used_today,
                    },
                )
                return JSONResponse(status_code=402, content=c_body, headers=c_headers)

        try:
            result_data = execute_tool_call(tool_name, tool_args)
        except SSRFBlockedError as ssrf_err:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"SSRF Guard Blocked URL: {ssrf_err.message}",
                        "data": {"rule": ssrf_err.rule, "blocked_url": ssrf_err.url},
                    },
                },
            )
        except Exception as exec_err:
            return JSONResponse(
                status_code=500,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": f"Tool execution error: {exec_err}"},
                },
            )

        resp_headers: Dict[str, str] = {}
        if payment_info:
            resp_headers["PAYMENT-RESPONSE"] = encode_payment_response_header(payment_info)

        return JSONResponse(
            status_code=200,
            headers=resp_headers,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result_data)}],
                    "structuredContent": result_data,
                    "isError": False,
                },
            },
        )

    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": req_id, "result": {"status": "supported", "method": method}},
    )


@app.post("/mcp/reset-quota")
async def mcp_reset_quota_endpoint(request: Request) -> JSONResponse:
    """Helper endpoint for test suites to reset per-IP free call counters."""
    reset_free_quota()
    return JSONResponse(status_code=200, content={"status": "reset", "daily_free_limit": FREE_CALL_QUOTA_LIMIT})


# ---------------------------------------------------------------------------
# 3. Tier 2 — AutoPatch Vault Endpoints ($39.00 USDC via x402 V2)
# ---------------------------------------------------------------------------

@app.get("/v1/audit-target")
@app.post("/v1/audit-target")
async def audit_target_endpoint(request: Request) -> JSONResponse:
    target = request.query_params.get("target") or ""
    custom_findings = None
    if request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                target = str(body.get("target") or body.get("url") or body.get("contractAddress") or target)
                if isinstance(body.get("findings"), list):
                    custom_findings = body["findings"]
        except Exception:
            pass

    if not target.strip():
        return JSONResponse(
            status_code=400,
            content={"error": "missing_target", "detail": "Provide 'target' (GitHub MCP repo URL or 0x contract address)"},
        )

    try:
        entry = audit_target(target, custom_findings=custom_findings)
    except SSRFBlockedError as ssrf_err:
        return JSONResponse(
            status_code=400,
            content={
                "error": "ssrf_blocked",
                "rule": ssrf_err.rule,
                "detail": ssrf_err.message,
                "blocked_url": ssrf_err.url,
            },
        )
    except ValueError as val_err:
        return JSONResponse(status_code=400, content={"error": "invalid_target", "detail": str(val_err)})

    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "audit_id": entry["audit_id"],
            "target": entry["target"],
            "target_type": entry["target_type"],
            "scorecard": entry["scorecard"],
            "unlock_url": f"/v1/unlock-patch/{entry['audit_id']}",
            "price_usdc": AUTOPATCH_PRICE_USD,
        },
    )


@app.post("/v1/vault/register")
async def vault_register_endpoint(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        res = register_vault_entry(payload)
        return JSONResponse(status_code=200, content={"status": "registered", **res})
    except SSRFBlockedError as ssrf_err:
        return JSONResponse(
            status_code=400,
            content={"error": "ssrf_blocked", "rule": ssrf_err.rule, "detail": ssrf_err.message},
        )
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "registration_failed", "detail": str(e)})


@app.get("/v1/unlock-patch/{audit_id}")
@app.post("/v1/unlock-patch/{audit_id}")
async def unlock_patch_endpoint(audit_id: str, request: Request) -> Response:
    entry = get_vault_entry(audit_id)
    if not entry:
        # Synthesize a deterministic entry if an external link visits a fresh apv_ ID
        entry = register_vault_entry({
            "audit_id": audit_id,
            "target": f"https://github.com/mcp-registry/{audit_id}",
        })
        entry = get_vault_entry(audit_id)

    assert entry is not None
    resource_url = str(request.url)
    payment_header = _extract_payment_header(request)
    tx_hash_param = request.query_params.get("tx_hash") or request.query_params.get("txHash")

    if request.method == "POST" and not tx_hash_param:
        try:
            body = await request.json()
            if isinstance(body, dict):
                tx_hash_param = body.get("tx_hash") or body.get("txHash")
        except Exception:
            pass

    if payment_header or tx_hash_param:
        ok, p_info, p_err, p_status = verify_x402_payment(
            raw_header=payment_header,
            required_units=int(AUTOPATCH_AMOUNT_UNITS),
            resource_url=resource_url,
            tool_name="autopatch_unlock_bundle",
            tx_hash_param=tx_hash_param,
        )
        if ok and p_info:
            mark_vault_unlocked(audit_id, str(p_info.get("transaction", "")))
            resp_headers = {"PAYMENT-RESPONSE": encode_payment_response_header(p_info)}
            return JSONResponse(
                status_code=200,
                headers=resp_headers,
                content={
                    "status": "unlocked",
                    "audit_id": audit_id,
                    "target": entry["target"],
                    "payment_receipt": p_info,
                    "scorecard": entry["scorecard"],
                    "patch_bundle": entry["patch_bundle"],
                },
            )
        # Invalid payment provided -> return 402 with error details
        c_headers, c_body = build_x402_challenge(
            tool_name="autopatch_unlock_bundle",
            price_usd=AUTOPATCH_PRICE_USD,
            amount_units=AUTOPATCH_AMOUNT_UNITS,
            description=f"Unlock Guard402 AutoPatch Remediation Bundle for {entry['target']} ({audit_id})",
            resource_url=resource_url,
            extra_body={
                "audit_id": audit_id,
                "target": entry["target"],
                "scorecard": entry["scorecard"],
                "details": p_err,
            },
        )
        return JSONResponse(status_code=p_status, content=c_body, headers=c_headers)

    # Unpaid request: build x402 V2 $39.00 USDC challenge headers & body
    c_headers, c_body = build_x402_challenge(
        tool_name="autopatch_unlock_bundle",
        price_usd=AUTOPATCH_PRICE_USD,
        amount_units=AUTOPATCH_AMOUNT_UNITS,
        description=f"Unlock Guard402 AutoPatch Remediation Bundle for {entry['target']} ({audit_id})",
        resource_url=resource_url,
        extra_body={
            "audit_id": audit_id,
            "target": entry["target"],
            "scorecard": entry["scorecard"],
            "unlock_instructions": {
                "price_usdc": AUTOPATCH_PRICE_USD,
                "amount_units": AUTOPATCH_AMOUNT_UNITS,
                "pay_to_base": get_payout_wallet(),
                "network": BASE_NETWORK,
                "asset": BASE_USDC_ASSET,
                "header": "Attach PAYMENT-SIGNATURE (Base64 x402 V2 payload) or ?tx_hash=0x...",
            },
        },
    )

    accept_hdr = (request.headers.get("accept") or "").lower()
    fmt_param = (request.query_params.get("format") or "").lower()
    if "text/html" in accept_hdr and fmt_param != "json":
        html_page = render_unlock_checkout_html(entry, resource_url)
        return HTMLResponse(content=html_page, status_code=402, headers=c_headers)

    return JSONResponse(status_code=402, content=c_body, headers=c_headers)


# ---------------------------------------------------------------------------
# 4. Tier 1 — M2M Micro-Call REST Endpoints ($0.002 to $0.01 USDC)
# ---------------------------------------------------------------------------

ROUTE_TO_TOOL: Dict[str, str] = {
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


async def _handle_tier1_rest(request: Request, tool_name: str) -> Response:
    tool_meta = TOOL_BY_NAME.get(tool_name, TOOL_BY_NAME["canaryguard_sanitize_prompt"])
    args: Dict[str, Any] = dict(request.query_params)
    if request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                args.update(body)
        except Exception:
            pass

    # 1. Enforce SSRF Guard FIRST on any URL parameters so SSRF probes get 400 immediately
    try:
        for url_key in ("url", "server_url", "target_url", "webhook_url", "endpoint"):
            if args.get(url_key):
                assert_safe_url(str(args[url_key]), resolve_dns=True)
    except SSRFBlockedError as ssrf_err:
        return JSONResponse(
            status_code=400,
            content={
                "error": "ssrf_blocked",
                "rule": ssrf_err.rule,
                "detail": ssrf_err.message,
                "blocked_url": ssrf_err.url,
            },
        )

    # 2. Verify x402 V2 Payment (or issue 402 Payment Required challenge)
    payment_header = _extract_payment_header(request)
    tx_hash_param = args.get("tx_hash") or args.get("txHash")
    resource_url = str(request.url)

    if not payment_header and not tx_hash_param:
        c_headers, c_body = build_x402_challenge(
            tool_name=tool_meta["name"],
            price_usd=tool_meta["price_usd"],
            amount_units=tool_meta["amount_units"],
            description=tool_meta["description"],
            resource_url=resource_url,
            mode="http",
            input_schema=tool_meta["inputSchema"],
        )
        return JSONResponse(status_code=402, content=c_body, headers=c_headers)

    ok, p_info, p_err, p_status = verify_x402_payment(
        raw_header=payment_header,
        required_units=int(tool_meta["amount_units"]),
        resource_url=resource_url,
        tool_name=tool_meta["name"],
        tx_hash_param=str(tx_hash_param) if tx_hash_param else None,
    )
    if not ok or not p_info:
        c_headers, c_body = build_x402_challenge(
            tool_name=tool_meta["name"],
            price_usd=tool_meta["price_usd"],
            amount_units=tool_meta["amount_units"],
            description=tool_meta["description"],
            resource_url=resource_url,
            mode="http",
            input_schema=tool_meta["inputSchema"],
            extra_body={"details": p_err},
        )
        return JSONResponse(status_code=p_status, content=c_body, headers=c_headers)

    try:
        result = execute_tool_call(tool_meta["name"], args)
    except SSRFBlockedError as ssrf_err:
        return JSONResponse(
            status_code=400,
            content={"error": "ssrf_blocked", "rule": ssrf_err.rule, "detail": ssrf_err.message},
        )

    resp_headers = {"PAYMENT-RESPONSE": encode_payment_response_header(p_info)}
    return JSONResponse(status_code=200, headers=resp_headers, content={**result, "payment_receipt": p_info})


for _route_path, _mapped_tool in ROUTE_TO_TOOL.items():
    def _make_handler(t_name: str):
        async def _endpoint(request: Request) -> Response:
            return await _handle_tier1_rest(request, t_name)
        return _endpoint

    _clean_id = _route_path.strip("/").replace("/", "_").replace("-", "_")
    app.add_api_route(
        _route_path,
        _make_handler(_mapped_tool),
        methods=["GET", "POST"],
        name=f"tier1_{_clean_id}",
    )


@app.get("/v1/{service_group}/{action:path}", name="dynamic_service_get")
@app.post("/v1/{service_group}/{action:path}", name="dynamic_service_post")
async def dynamic_service_router(service_group: str, action: str, request: Request) -> Response:
    group_map = {
        "canaryguard": "canaryguard_sanitize_prompt",
        "stealthguard": "stealthguard_sanitize_url",
        "rugshield": "rugshield_scan_token",
        "tollbooth": "tollbooth_ai_intel",
    }
    tool_name = group_map.get(service_group.lower())
    if not tool_name:
        return JSONResponse(status_code=404, content={"error": "unknown_service_group", "service": service_group})
    return await _handle_tier1_rest(request, tool_name)
