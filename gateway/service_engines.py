"""Fixed upstream adapters: no fabricated analysis or local payment settlement."""

import json
import re
from decimal import Decimal
import httpx
from .ssrf_guard import assert_safe_url

CANARY = "https://canaryguard-402.onrender.com"
STEALTH = "https://stealthguard-402.onrender.com"
RUG = "https://rugshield-402.onrender.com"
TOLL = "https://x402-agent-tollbooth.onrender.com"
# name -> canonical URL, reference price, scope, property types, required fields.
# URLs cannot be changed through user input, environment, forwarded headers or redirects.
UPSTREAM_TOOLS = {
    "canaryguard_sanitize_prompt": (
        CANARY + "/v1/sanitize",
        "0.010",
        "Inspect and sanitize untrusted text",
        {"content": "string", "strict_mode": "boolean"},
        ["content"],
    ),
    "canaryguard_audit_mcp_schema": (
        CANARY + "/v1/mcp-tool-auditor",
        "0.010",
        "Inspect one MCP tool; multi-tool batches unsupported",
        {"tool_name": "string", "tool_description": "string", "input_schema": "object"},
        ["tool_name"],
    ),
    "canaryguard_verify_eip712": (
        CANARY + "/v1/eip712-signature-audit",
        "0.010",
        "Inspect EIP-712 typed data; no universal safety certificate",
        {"typed_data": "object"},
        ["typed_data"],
    ),
    "stealthguard_sanitize_url": (
        STEALTH + "/v1/stealth_scrape_and_sanitize",
        "0.015",
        "Acquire and sanitize the requested public page",
        {
            "url": "string",
            "strict_mode": "boolean",
            "render_js": "boolean",
            "extract_schema": "object",
        },
        ["url"],
    ),
    "stealthguard_polymarket_whale_radar": (
        STEALTH + "/v1/alpha/polymarket-whale-orderflow",
        "0.020",
        "Measured Polymarket trades; optional identity-matched Polymarket/Limitless outcome books and 100-share VWAP with venue fees, without a fill or profit guarantee",
        {
            "min_order_usd": "number",
            "include_cross_venue": "boolean",
            "strict_mode": "boolean",
        },
        [],
    ),
    "stealthguard_odds_divergence": (
        STEALTH + "/v1/polymarket_alpha_divergence",
        "0.020",
        "Identity-checked supported paired markets and displayed book evidence; no execution or profit guarantee",
        {"category": "string", "limit": "integer", "strict_mode": "boolean"},
        [],
    ),
    "rugshield_scan_token": (
        RUG + "/v1/scan",
        "0.010",
        "Base: scoped V2 buy/sell. Solana: only explicit simulate_sell:false mint inspection; full simulation unavailable",
        {
            "token_address": "string",
            "chain": "string",
            "chain_id": "integer",
            "simulate_sell": "boolean",
        },
        ["token_address"],
    ),
    "rugshield_simulate_honeypot": (
        RUG + "/v1/scan",
        "0.010",
        "Base Uniswap V2, 0.001 ETH, unsigned stateful buy/sell; other sizes/pools unsupported",
        {"token_address": "string", "chain": "string", "simulate_sell": "boolean"},
        ["token_address"],
    ),
    "rugshield_sybil_cluster_map": (
        RUG + "/v1/audit/holder-cluster-map",
        "0.020",
        "Full holder-cluster acquisition unavailable; no settlement",
        {"token_address": "string", "chain": "string"},
        ["token_address"],
    ),
    "tollbooth_ai_intel": (
        TOLL + "/toll/ai_intel",
        "0.001",
        "Configured AI review or explicit limited_review:true pattern-only review; no security guarantee",
        {
            "prompt": "string",
            "contractAddress": "string",
            "chain": "string",
            "isPatch": "boolean",
            "limited_review": "boolean",
        },
        [],
    ),
    "tollbooth_arbitrage_scan": (
        TOLL + "/toll/arbitrage_scan",
        "0.002",
        "Acquire supported routes for a specified exact decimal-string amount; profit is never guaranteed",
        {
            "pair": "string",
            "chain": "string",
            "amount": "string",
            "min_spread_bps": "integer",
            "slippage_bps": "integer",
        },
        ["pair"],
    ),
    "tollbooth_smart_router": (
        TOLL + "/toll/smart_router",
        "0.001",
        "Acquire supported execution route quotes using the supplied exact decimal-string human-unit amount",
        {
            "tokenIn": "string",
            "tokenOut": "string",
            "amount": "string",
            "chain": "string",
            "slippage_bps": "integer",
        },
        ["tokenIn", "tokenOut", "amount"],
    ),
    "tollbooth_contract_audit": (
        TOLL + "/api/audit",
        "0.020",
        "Contract review; limited_review:true explicitly purchases pattern-only review without a patch or safety certificate",
        {
            "contractAddress": "string",
            "chain": "string",
            "isPatch": "boolean",
            "limited_review": "boolean",
        },
        ["contractAddress"],
    ),
}


def _tool(name, price, description, props, required, url=None):
    return {
        "name": name,
        "title": name.replace("_", " ").title(),
        "description": description,
        "price_usd": price,
        "amount_units": str(int(Decimal(price) * 1000000)),
        "upstream": url,
        "inputSchema": {
            "type": "object",
            "properties": {k: {"type": v} for k, v in props.items()},
            "required": required,
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    }


MCP_TOOLS_CATALOG = [
    _tool(n, p, d, props, required, url)
    for n, (url, p, d, props, required) in UPSTREAM_TOOLS.items()
]
MCP_TOOLS_CATALOG += [
    _tool(
        "autopatch_static_audit",
        "0",
        "Unavailable until target source acquisition and verified patch generation exist; no invented diagnostic",
        {"target": "string"},
        ["target"],
    ),
    _tool(
        "autopatch_unlock_bundle",
        "0",
        "Unavailable until a genuine target-bound bundle passes verification; no $39 payment requested",
        {"audit_id": "string"},
        ["audit_id"],
    ),
]
TOOL_BY_NAME = {t["name"]: t for t in MCP_TOOLS_CATALOG}


def get_mcp_tools_list():
    return [
        {
            k: v
            for k, v in t.items()
            if k in ("name", "title", "description", "inputSchema", "annotations")
        }
        for t in MCP_TOOLS_CATALOG
    ]


class InputValidationError(ValueError):
    pass


def normalize_arguments(name, arguments, *, query_strings=False):
    if not isinstance(name, str) or name not in TOOL_BY_NAME:
        raise InputValidationError("Unknown tool")
    if not isinstance(arguments, dict):
        raise InputValidationError("arguments must be a JSON object")
    args = dict(arguments)
    if (
        name in ("tollbooth_smart_router", "tollbooth_arbitrage_scan")
        and "amount" in args
    ):
        value = args["amount"]
        if isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if (
            not isinstance(value, str)
            or len(value) > 128
            or not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d+)?", value)
            or Decimal(value) <= 0
        ):
            raise InputValidationError(
                "amount must be a positive exact decimal string; floating-point amounts are unsupported"
            )
        args["amount"] = value
    if name == "tollbooth_smart_router":
        for old, new in (("token_in", "tokenIn"), ("token_out", "tokenOut")):
            if old in args:
                if new in args and args[old] != args[new]:
                    raise InputValidationError("Conflicting token aliases")
                args[new] = args.pop(old)
    if name == "canaryguard_audit_mcp_schema" and "tools" in args:
        tools = args.pop("tools")
        if (
            not isinstance(tools, list)
            or len(tools) != 1
            or not isinstance(tools[0], dict)
        ):
            raise InputValidationError("Only one MCP tool per purchase is supported")
        tool = tools[0]
        converted = {
            "tool_name": tool.get("name"),
            "input_schema": tool.get("inputSchema", {}),
        }
        if tool.get("description"):
            converted["tool_description"] = tool["description"]
        for key, value in converted.items():
            if key in args and args[key] != value:
                raise InputValidationError("Conflicting MCP tool definitions")
            args[key] = value
    if name == "canaryguard_verify_eip712" and "typed_data" not in args:
        if set(args) == {"domain", "types", "primaryType", "message"}:
            args = {"typed_data": args}
        else:
            raise InputValidationError(
                "typed_data needs domain/types/primaryType/message"
            )
    schema = TOOL_BY_NAME[name]["inputSchema"]
    unknown = set(args) - set(schema["properties"])
    if unknown:
        raise InputValidationError(
            "Unsupported arguments: " + ", ".join(sorted(unknown))
        )
    for key in schema["required"]:
        if key not in args:
            raise InputValidationError("Missing required " + key)
    for key, value in list(args.items()):
        kind = schema["properties"][key]["type"]
        if query_strings and isinstance(value, str):
            if kind == "boolean" and value in ("true", "false"):
                value = value == "true"
            elif kind in ("number", "integer"):
                try:
                    value = int(value) if kind == "integer" else float(value)
                except ValueError:
                    pass
        valid = (
            (kind == "string" and isinstance(value, str) and bool(value.strip()))
            or (kind == "object" and isinstance(value, dict))
            or (kind == "boolean" and isinstance(value, bool))
            or (
                kind in ("number", "integer")
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
                and (kind != "integer" or isinstance(value, int))
            )
        )
        if not valid:
            raise InputValidationError(f"Invalid {key}: expected {kind}")
        if kind in ("number", "integer") and (
            not Decimal(str(value)).is_finite() or value < 0
        ):
            raise InputValidationError("Invalid numeric " + key)
        args[key] = value
    if "url" in args:
        assert_safe_url(args["url"], resolve_dns=True)
    if name == "canaryguard_verify_eip712" and not all(
        k in args["typed_data"] for k in ("domain", "types", "primaryType", "message")
    ):
        raise InputValidationError("Incomplete typed_data")
    if name == "tollbooth_ai_intel" and not (
        args.get("prompt") or args.get("contractAddress")
    ):
        raise InputValidationError("prompt or contractAddress is required")
    if name == "rugshield_simulate_honeypot":
        if args.get("simulate_sell") is False:
            raise InputValidationError("This tool requires buy/sell simulation")
        args["simulate_sell"] = True
    return args


PASS_RESPONSE_HEADERS = {
    "payment-required",
    "x-payment-required",
    "x-402-payment-required",
    "payment-response",
    "payment-receipt",
    "www-authenticate",
    "retry-after",
    "x-402-version",
    "x-free-trial-remaining",
    "x-trial-notice",
    "location",
}


async def proxy_tool_call(name, arguments, payment_header=None, *, query_strings=False):
    args = normalize_arguments(name, arguments, query_strings=query_strings)
    if name not in UPSTREAM_TOOLS:
        return (
            503,
            {},
            {
                "error": "VERIFIED_PATCH_UNAVAILABLE",
                "payment_collected": False,
                "message": "Target source acquisition and verified patch generation are unavailable; no payment requested",
            },
        )
    headers = {"Accept": "application/json"}
    if payment_header:
        if not isinstance(payment_header, str) or len(payment_header) > 32768:
            raise InputValidationError("Invalid payment header size")
        headers["PAYMENT-SIGNATURE"] = payment_header
    try:
        # Exactly one upstream attempt. Never retry a possibly settled payment or follow redirects.
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(75, connect=15),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream(
                "POST", UPSTREAM_TOOLS[name][0], json=args, headers=headers
            ) as response:
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 2097152:
                        raise ValueError("Upstream response too large")
                    chunks.append(chunk)
                body = json.loads(b"".join(chunks))
                if not isinstance(body, dict):
                    raise ValueError("Upstream must return a JSON object")
                response_headers = {
                    k: v
                    for k, v in response.headers.items()
                    if k.lower() in PASS_RESPONSE_HEADERS
                }
                return response.status_code, response_headers, body
    except (httpx.HTTPError, ValueError):
        if payment_header:
            return (
                503,
                {},
                {
                    "error": "SETTLEMENT_PENDING_RECONCILIATION",
                    "message": "Upstream outcome unknown. Reuse the identical authorization and request; do not pay again",
                },
            )
        return (
            503,
            {},
            {
                "error": "UPSTREAM_UNAVAILABLE",
                "payment_collected": False,
                "message": "Canonical provider unavailable",
            },
        )


def execute_tool_call(*_args, **_kwargs):
    raise RuntimeError("Local fallback engines removed; use async proxy_tool_call")
