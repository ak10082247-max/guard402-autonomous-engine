"""Unfunded regression tests: all upstream traffic is an explicit HTTP mock.

The original six test entry points remain; TESTING and magic-payment fixtures
have been replaced by canonical proxy and fail-closed assertions.
"""

import asyncio
import base64
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gateway.main import app
from gateway import service_engines as engines
from gateway.x402_engine import (
    get_payout_wallet,
    verify_x402_payment,
    verify_onchain_base_tx,
)

ORIGINAL_ASYNC_CLIENT = httpx.AsyncClient


class Client:
    def request(self, method, url, **kwargs):
        async def send():
            async with ORIGINAL_ASYNC_CLIENT(
                transport=httpx.ASGITransport(app), base_url="http://guard.test"
            ) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(send())

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)


client = Client()


@pytest.fixture(autouse=True)
def canonical_mock(monkeypatch):
    calls = []
    urls = {spec[0]: spec[1] for spec in engines.UPSTREAM_TOOLS.values()}

    def handler(request):
        calls.append(request)
        url = str(request.url)
        assert url in urls, "Proxy attempted a non-whitelisted upstream"
        assert request.method == "POST"
        assert "authorization" not in request.headers
        assert "x-forwarded-for" not in request.headers
        payment = request.headers.get("payment-signature")
        if payment == "OFFLINE_UNKNOWN":
            raise httpx.ReadTimeout(
                "offline timeout after possible settlement", request=request
            )
        if payment != "OFFLINE_AUTHORIZATION":
            required = {
                "x402Version": 2,
                "resource": {"url": url},
                "accepts": [
                    {
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "amount": str(int(float(urls[url]) * 1_000_000)),
                        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                        "payTo": get_payout_wallet(),
                    }
                ],
            }
            return httpx.Response(
                402,
                json=required,
                headers={
                    "PAYMENT-REQUIRED": base64.b64encode(
                        json.dumps(required).encode()
                    ).decode(),
                    "WWW-Authenticate": "Payment OFFLINE_CANONICAL_QUOTE",
                },
            )
        if request.url.path.endswith("holder-cluster-map"):
            return httpx.Response(
                503, json={"error": "ANALYSIS_UNAVAILABLE", "payment_collected": False}
            )
        receipt = base64.b64encode(
            json.dumps(
                {
                    "success": True,
                    "network": "eip155:8453",
                    "transaction": "0x" + "ab" * 32,
                    "amount": "10000",
                    "resource": url,
                    "fixture": True,
                }
            ).encode()
        ).decode()
        return httpx.Response(
            200,
            json={
                "status": "success",
                "offline_fixture": True,
                "requested": json.loads(request.content),
                "source": url,
            },
            headers={"PAYMENT-RESPONSE": receipt},
        )

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return ORIGINAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(engines.httpx, "AsyncClient", factory)
    return calls


def test_health_and_discovery(canonical_mock):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["tool_count"] == 15
    assert response.json()["proxied_tools"] == 13
    assert response.json()["payout_wallet_base"] == get_payout_wallet()
    assert response.json()["payment_mode"] == "canonical_upstream_only"
    assert "Guard402 AutoPatch Vault" in client.get("/").text
    for path in ("/.well-known/mcp.json", "/.well-known/x402.json", "/openapi.json"):
        assert client.get(path).status_code == 200
    catalog = client.get("/.well-known/x402.json").json()
    schema = client.get("/openapi.json").json()
    operation_ids = [
        operation["operationId"]
        for methods in schema["paths"].values()
        for operation in methods.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]
    assert len(operation_ids) == len(set(operation_ids))
    assert catalog["vault_purchases_available"] is False
    assert {t["name"]: t["price_usd"] for t in catalog["tools"]}[
        "tollbooth_smart_router"
    ] == "0.001"
    assert canonical_mock == []


def test_mcp_zero_cold_start_and_annotations(canonical_mock):
    for method in (client.get, client.head, client.options):
        assert method("/mcp").status_code == 200
    for method in (
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    ):
        response = client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}
        )
        assert response.status_code == 200
        assert "result" in response.json()
    tools = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    ).json()["result"]["tools"]
    assert len(tools) == 15
    for tool in tools:
        assert isinstance(tool["annotations"]["readOnlyHint"], bool)
        assert tool["annotations"]["destructiveHint"] is False
        assert tool["annotations"]["idempotentHint"] is False  # paid calls can settle
    assert canonical_mock == []


def test_mcp_3_free_calls_then_402_and_paid_retry(canonical_mock):
    """Legacy test name retained: there are now no local quota/payment bypasses."""
    body = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "canaryguard_sanitize_prompt",
            "arguments": {"content": "owner offline fixture"},
        },
    }
    for _ in range(4):
        response = client.post("/mcp", json=body)
        assert response.status_code == 402
        assert response.json()["result"]["isError"] is True
        required = json.loads(base64.b64decode(response.headers["payment-required"]))
        assert required["resource"]["url"] == engines.CANARY + "/v1/sanitize"
        assert required["accepts"][0]["amount"] == "10000"
    response = client.post(
        "/mcp", json=body, headers={"PAYMENT-SIGNATURE": "OFFLINE_AUTHORIZATION"}
    )
    assert response.status_code == 200
    assert response.json()["result"]["structuredContent"]["offline_fixture"] is True
    receipt = json.loads(base64.b64decode(response.headers["payment-response"]))
    assert receipt["resource"] == engines.CANARY + "/v1/sanitize"
    assert receipt["fixture"] is True
    assert len(canonical_mock) == 5
    assert client.post("/mcp/reset-quota").status_code == 410


def test_ssrf_guard_blocking(canonical_mock):
    for target in (
        "http://127.0.0.1:8000/admin",
        "http://localhost/secret",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "dict://127.0.0.1/",
    ):
        response = client.post("/v1/stealthguard/sanitize-url", json={"url": target})
        assert response.status_code == 400
        assert response.json()["error"] == "ssrf_blocked"
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {
                    "name": "stealthguard_sanitize_url",
                    "arguments": {"url": target},
                },
            },
        )
        assert response.status_code == 400
        assert "SSRF Guard Blocked" in response.json()["error"]["message"]
        assert (
            client.post("/v1/audit-target", json={"target": target}).status_code == 400
        )
    assert canonical_mock == []


def test_autopatch_vault_audit_and_unlock(canonical_mock, monkeypatch):
    # A valid target is no excuse to invent a scorecard, repository, patch or grade.
    response = client.post("/v1/audit-target", json={"target": "0x" + "22" * 20})
    assert response.status_code == 503
    assert "scorecard" not in response.json()
    for method in (client.get, client.post):
        response = method(
            "/v1/unlock-patch/apv_missing?tx_hash=0xtest_MAGIC",
            headers={"PAYMENT-SIGNATURE": "OFFLINE_AUTHORIZATION"},
        )
        assert response.status_code == 503
        assert response.json()["payment_collected"] is False
        assert "payment-required" not in response.headers
        assert "payment-response" not in response.headers
        assert "patch_bundle" not in response.json()
    monkeypatch.setenv(
        "GUARD402_VAULT_ADMIN_TOKEN", "OFFLINE_ADMIN_TOKEN_VALUE_32_CHARS_LONG"
    )
    assert client.post("/v1/vault/register", json={"verified": True}).status_code == 401
    response = client.post(
        "/v1/vault/register",
        json={"verified": True},
        headers={"Authorization": "Bearer OFFLINE_ADMIN_TOKEN_VALUE_32_CHARS_LONG"},
    )
    assert response.status_code == 503
    assert canonical_mock == []


def test_no_secret_files_in_repo():
    root = Path(__file__).resolve().parent.parent
    forbidden = [
        str(p)
        for p in root.rglob("*")
        if p.is_file()
        and (
            p.name.lower().startswith(".env")
            or p.name.lower().endswith((".pem", ".key"))
        )
    ]
    assert forbidden == []


def test_real_alias_normalization_and_no_fallback(canonical_mock):
    request = {
        "token_in": "USDC",
        "token_out": "WETH",
        "amount": "1000",
        "chain": "base",
    }
    response = client.post(
        "/toll/router",
        json=request,
        headers={
            "PAYMENT-SIGNATURE": "OFFLINE_AUTHORIZATION",
            "Authorization": "Bearer DO_NOT_FORWARD",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    assert response.status_code == 200
    assert response.json()["requested"] == {
        "tokenIn": "USDC",
        "tokenOut": "WETH",
        "amount": "1000",
        "chain": "base",
    }
    assert len(canonical_mock) == 1
    for body in (
        {**request, "tokenIn": "OTHER"},
        {**request, "upstream_url": "http://127.0.0.1/"},
        {**request, "tx_hash": "0xtest_MAGIC"},
    ):
        assert client.post("/toll/router", json=body).status_code == 400
    assert len(canonical_mock) == 1
    assert client.post("/v1/rugshield/unknown-operation", json={}).status_code == 404
    response = client.post(
        "/v1/rugshield/sybil-clusters",
        json={"token_address": "0x" + "22" * 20},
        headers={"PAYMENT-SIGNATURE": "OFFLINE_AUTHORIZATION"},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "ANALYSIS_UNAVAILABLE"
    assert "payment-response" not in response.headers


def test_uncertain_payment_is_not_retried_and_magic_payments_never_unlock(
    canonical_mock, monkeypatch
):
    response = client.post(
        "/v1/canaryguard/sanitize",
        json={"content": "owner fixture"},
        headers={"PAYMENT-SIGNATURE": "OFFLINE_UNKNOWN"},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "SETTLEMENT_PENDING_RECONCILIATION"
    assert len(canonical_mock) == 1
    monkeypatch.setenv("TESTING", "1")
    for magic in ("0xtest_MAGIC", "0x" + "11" * 32, "0xaaMOCK", "test"):
        assert (
            verify_x402_payment(magic, 10000, "http://guard.test", "tool")[0] is False
        )
        assert verify_onchain_base_tx(magic, 10000, get_payout_wallet())[0] is False
        response = client.post(
            "/v1/canaryguard/sanitize",
            json={"content": "fixture"},
            headers={"PAYMENT-SIGNATURE": magic},
        )
        assert response.status_code == 402
        assert "payment-response" not in response.headers
    assert len(canonical_mock) == 5


def test_mcp_and_typed_data_normalization(canonical_mock):
    response = client.post(
        "/v1/canaryguard/audit-mcp",
        json={
            "tools": [
                {
                    "name": "fixture",
                    "description": "test",
                    "inputSchema": {"type": "object"},
                }
            ]
        },
    )
    assert response.status_code == 402
    assert json.loads(canonical_mock[-1].content) == {
        "tool_name": "fixture",
        "tool_description": "test",
        "input_schema": {"type": "object"},
    }
    assert (
        client.post(
            "/v1/canaryguard/audit-mcp", json={"tools": [{"name": "a"}, {"name": "b"}]}
        ).status_code
        == 400
    )
    typed = {"domain": {}, "types": {}, "primaryType": "Fixture", "message": {}}
    assert client.post("/v1/canaryguard/verify-eip712", json=typed).status_code == 402
    assert json.loads(canonical_mock[-1].content) == {"typed_data": typed}
    assert (
        client.post(
            "/v1/canaryguard/verify-eip712", json={"primaryType": "Fixture"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/v1/rugshield/simulate-honeypot",
            json={"token_address": "0x" + "22" * 20, "amount_usdc": 100},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/toll/ai_intel", json={"prompt": "fixture", "limited_review": True}
        ).status_code
        == 402
    )
    assert json.loads(canonical_mock[-1].content)["limited_review"] is True
    assert client.post("/toll/ai_intel", json={"prompt": "fixture"}).status_code == 402
    assert "limited_review" not in json.loads(canonical_mock[-1].content)


def test_strict_json_and_argument_validation(canonical_mock):
    for body in (
        "null",
        "[]",
        "{broken",
        '{"content":"a","content":"b"}',
        '{"content":"a","strict_mode":NaN}',
    ):
        assert client.post("/v1/canaryguard/sanitize", content=body).status_code == 400
    assert (
        client.get("/v1/rugshield/scan?token_address=x&token_address=y").status_code
        == 400
    )
    assert (
        client.post(
            "/v1/canaryguard/sanitize",
            json={"content": "fixture", "strict_mode": "false"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "canaryguard_sanitize_prompt", "arguments": []},
            },
        ).status_code
        == 400
    )
    for name in ([], {}, None):
        assert (
            client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": {}},
                },
            ).status_code
            == 404
        )
    assert canonical_mock == []


def test_trade_amount_precision_is_preserved(canonical_mock):
    amount = "1.000000000000000001"
    response = client.get(
        "/toll/arbitrage_scan",
        params={
            "pair": "WETH/USDC",
            "amount": amount,
            "min_spread_bps": "8",
            "slippage_bps": "50",
        },
    )
    assert response.status_code == 402
    assert json.loads(canonical_mock[-1].content)["amount"] == amount
    assert json.loads(canonical_mock[-1].content)["slippage_bps"] == 50
    response = client.post(
        "/toll/router", json={"tokenIn": "WETH", "tokenOut": "USDC", "amount": amount}
    )
    assert response.status_code == 402
    assert json.loads(canonical_mock[-1].content)["amount"] == amount
    response = client.post(
        "/toll/arbitrage_scan", json={"pair": "WETH/USDC", "amount": 1.01}
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("canaryguard_sanitize_prompt", {"content": "fixture"}),
        ("canaryguard_audit_mcp_schema", {"tool_name": "fixture"}),
        (
            "canaryguard_verify_eip712",
            {
                "typed_data": {
                    "domain": {},
                    "types": {},
                    "primaryType": "Fixture",
                    "message": {},
                }
            },
        ),
        ("stealthguard_sanitize_url", {"url": "https://example.org/"}),
        (
            "stealthguard_polymarket_whale_radar",
            {"include_cross_venue": False, "min_order_usd": 10000},
        ),
        ("stealthguard_odds_divergence", {"category": "crypto", "limit": 5}),
        ("rugshield_scan_token", {"token_address": "0x" + "22" * 20}),
        ("rugshield_simulate_honeypot", {"token_address": "0x" + "22" * 20}),
        ("rugshield_sybil_cluster_map", {"token_address": "0x" + "22" * 20}),
        ("tollbooth_ai_intel", {"prompt": "fixture"}),
        ("tollbooth_arbitrage_scan", {"pair": "WETH/USDC", "amount": 1000}),
        (
            "tollbooth_smart_router",
            {"tokenIn": "USDC", "tokenOut": "WETH", "amount": "1000"},
        ),
        (
            "tollbooth_contract_audit",
            {"contractAddress": "0x" + "22" * 20, "limited_review": True},
        ),
    ],
)
def test_every_proxy_tool_preserves_canonical_quote(
    name, arguments, canonical_mock, monkeypatch
):
    # DNS is separately covered by SSRF tests. No network resolution in this matrix.
    monkeypatch.setattr(engines, "assert_safe_url", lambda *_args, **_kwargs: {})
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert response.status_code == 402
    required = json.loads(base64.b64decode(response.headers["payment-required"]))
    assert required["resource"]["url"] == engines.UPSTREAM_TOOLS[name][0]
    assert (
        required["accepts"][0]["amount"] == engines.TOOL_BY_NAME[name]["amount_units"]
    )
    assert len(canonical_mock) == 1
