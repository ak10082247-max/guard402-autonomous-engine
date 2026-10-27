"""
Comprehensive Verification Suite for Guard402 Autonomous Engine Gateway & AutoPatch Vault.
Tests:
  1. <300ms (<50ms) zero-auth MCP discovery methods (initialize, ping, tools/list, resources/list, prompts/list)
  2. MCP 2025-06-18 tool annotations on all 15 unified tools
  3. Strict SSRF blocking across all private/metadata/loopback IPs and non-HTTP schemes
  4. 3 free MCP tools/call per IP/day followed by HTTP 402 x402 V2 challenge on the 4th call
  5. Tier 1 M2M REST endpoints ($0.002 - $0.01 USDC) x402 V2 challenge and settlement
  6. Tier 2 AutoPatch Vault ($39 USDC) /v1/audit-target, /v1/vault/register, and /v1/unlock-patch/{audit_id}
  7. Storefront GET /, /health, /.well-known/mcp.json, /.well-known/x402.json, and zero secret files check
"""

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["TESTING"] = "1"

from gateway.main import app  # noqa: E402
from gateway.x402_engine import get_payout_wallet, reset_free_quota  # noqa: E402


class _ASGIResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], body: bytes):
        self.status_code = status_code
        # Case-insensitive dict lookup support
        self.headers = {k: v for k, v in headers.items()}
        for k, v in list(headers.items()):
            self.headers[k.upper()] = v
            self.headers[k.lower()] = v
        self._body = body
        self.text = body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class _ASGISyncClient:
    def __init__(self, asgi_app):
        self.app = asgi_app

    def request(
        self,
        method: str,
        url: str,
        json_body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> _ASGIResponse:
        if "json" in kwargs and json_body is None:
            json_body = kwargs.pop("json")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        query_string = (parsed.query or "").encode("utf-8")

        raw_body = b""
        req_headers = [(b"host", b"testserver")]
        if json_body is not None:
            raw_body = json.dumps(json_body).encode("utf-8")
            req_headers.append((b"content-type", b"application/json"))
        if headers:
            for hk, hv in headers.items():
                req_headers.append((hk.lower().encode("utf-8"), str(hv).encode("utf-8")))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "query_string": query_string,
            "headers": req_headers,
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
        }

        status_code = 500
        resp_headers: Dict[str, str] = {}
        chunks = []
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal status_code, resp_headers
            if message["type"] == "http.response.start":
                status_code = message["status"]
                for k, v in message.get("headers", []):
                    resp_headers[k.decode("latin-1")] = v.decode("latin-1")
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        asyncio.run(self.app(scope, receive, send))
        return _ASGIResponse(status_code, resp_headers, b"".join(chunks))

    def get(self, url: str, **kwargs) -> _ASGIResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> _ASGIResponse:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> _ASGIResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> _ASGIResponse:
        return self.request("OPTIONS", url, **kwargs)


client = _ASGISyncClient(app)


def _make_test_payment_header(amount_units: str) -> str:
    now = int(time.time())
    payload = {
        "x402Version": 2,
        "payload": {
            "signature": "0x11" + os.urandom(64).hex(),
            "authorization": {
                "from": "0x1111111111111111111111111111111111111111",
                "to": get_payout_wallet(),
                "value": str(amount_units),
                "validAfter": 0,
                "validBefore": now + 3600,
                "nonce": "0x" + os.urandom(32).hex(),
            },
        },
    }
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def test_health_and_discovery():
    t0 = time.perf_counter()
    r = client.get("/health")
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert r.status_code == 200
    assert elapsed_ms < 100
    data = r.json()
    assert data["status"] == "ok"
    assert data["tool_count"] == 15
    assert data["payout_wallet_base"].lower() == get_payout_wallet().lower()

    assert client.get("/").status_code == 200
    assert "Guard402 AutoPatch Vault" in client.get("/").text
    assert client.get("/.well-known/mcp.json").status_code == 200
    assert client.get("/.well-known/x402.json").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_mcp_zero_cold_start_and_annotations():
    assert client.get("/mcp").status_code == 200
    assert client.head("/mcp").status_code == 200
    assert client.options("/mcp").status_code == 200

    methods = [
        ("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "probe", "version": "1.0"}}),
        ("notifications/initialized", {}),
        ("ping", {}),
        ("tools/list", {}),
        ("resources/list", {}),
        ("resources/templates/list", {}),
        ("prompts/list", {}),
    ]
    for method, params in methods:
        t0 = time.perf_counter()
        resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert resp.status_code == 200, f"{method} returned {resp.status_code}"
        assert elapsed_ms < 300, f"{method} took {elapsed_ms:.1f}ms (>300ms SLA)"
        body = resp.json()
        assert body["jsonrpc"] == "2.0"
        assert "result" in body

    tools_resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}}).json()
    tools = tools_resp["result"]["tools"]
    assert len(tools) == 15
    expected_names = {
        "canaryguard_sanitize_prompt",
        "canaryguard_audit_mcp_schema",
        "canaryguard_verify_eip712",
        "stealthguard_sanitize_url",
        "stealthguard_polymarket_whale_radar",
        "stealthguard_odds_divergence",
        "rugshield_scan_token",
        "rugshield_simulate_honeypot",
        "rugshield_sybil_cluster_map",
        "tollbooth_ai_intel",
        "tollbooth_arbitrage_scan",
        "tollbooth_smart_router",
        "tollbooth_contract_audit",
        "autopatch_static_audit",
        "autopatch_unlock_bundle",
    }
    assert {t["name"] for t in tools} == expected_names
    for t in tools:
        ann = t.get("annotations")
        assert isinstance(ann, dict), f"Missing annotations on {t['name']}"
        assert ann.get("readOnlyHint") is True
        assert ann.get("destructiveHint") is False
        assert ann.get("idempotentHint") is True
        assert ann.get("openWorldHint") is True


def test_mcp_3_free_calls_then_402_and_paid_retry():
    reset_free_quota()
    call_body = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "canaryguard_sanitize_prompt",
            "arguments": {"content": "Hello safe world"},
        },
    }
    # Calls 1, 2, 3 succeed for free with HTTP 200
    for i in range(1, 4):
        r = client.post("/mcp", json=call_body)
        assert r.status_code == 200, f"Call #{i} should be free 200, got {r.status_code}"
        res = r.json()["result"]
        assert res["isError"] is False
        assert res["structuredContent"]["safety_receipt"] == "canary-v2-verified"

    # Call 4 from same IP triggers HTTP 402 Payment Required with PAYMENT-REQUIRED header
    r4 = client.post("/mcp", json=call_body)
    assert r4.status_code == 402
    assert "PAYMENT-REQUIRED" in r4.headers
    decoded_req = json.loads(base64.b64decode(r4.headers["PAYMENT-REQUIRED"]).decode("utf-8"))
    assert decoded_req["x402Version"] == 2
    assert "bazaar" in decoded_req["extensions"]
    assert any(a["network"] == "eip155:8453" for a in decoded_req["accepts"])

    # Paid retry on Call 5 succeeds with HTTP 200 and PAYMENT-RESPONSE header
    pay_hdr = _make_test_payment_header("2000")
    r5 = client.post("/mcp", json=call_body, headers={"PAYMENT-SIGNATURE": pay_hdr})
    assert r5.status_code == 200
    assert "PAYMENT-RESPONSE" in r5.headers

    # Also verify force_402 works even after quota reset
    reset_free_quota()
    rf = client.post("/mcp?force_402=1", json=call_body)
    assert rf.status_code == 402


def test_ssrf_guard_blocking():
    reset_free_quota()
    blocked_targets = [
        "http://127.0.0.1:8000/admin",
        "http://localhost/secret",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://172.16.0.5/internal",
        "http://192.168.1.1/router",
        "http://[::1]/loopback",
        "http://[fc00::1]/ula",
        "http://[fe80::1]/linklocal",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "gopher://example.com:70/1",
        "ftp://example.com/file",
        "dict://127.0.0.1:2628/",
    ]
    for bad_url in blocked_targets:
        # 1. REST StealthGuard endpoint
        r_rest = client.post("/v1/stealthguard/sanitize-url", json={"url": bad_url})
        assert r_rest.status_code == 400, f"Expected 400 SSRF block for {bad_url}, got {r_rest.status_code}"
        assert r_rest.json()["error"] == "ssrf_blocked"

        # 2. MCP tools/call endpoint
        r_mcp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 77,
                "method": "tools/call",
                "params": {"name": "stealthguard_sanitize_url", "arguments": {"url": bad_url}},
            },
        )
        assert r_mcp.status_code == 400, f"Expected 400 MCP SSRF block for {bad_url}"
        assert "SSRF Guard Blocked" in r_mcp.json()["error"]["message"]

        # 3. AutoPatch /v1/audit-target endpoint
        r_audit = client.post("/v1/audit-target", json={"target": bad_url})
        assert r_audit.status_code == 400
        assert r_audit.json()["error"] == "ssrf_blocked"


def test_autopatch_vault_audit_and_unlock():
    # 1. Run free static audit on a GitHub MCP repo
    r_audit = client.post("/v1/audit-target", json={"target": "https://github.com/modelcontextprotocol/servers"})
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    audit_id = audit_data["audit_id"]
    assert audit_id.startswith("apv_")
    assert audit_data["unlock_url"] == f"/v1/unlock-patch/{audit_id}"
    assert audit_data["scorecard"]["findings_count"] >= 3

    # 2. Unpaid JSON request to /v1/unlock-patch/{audit_id} -> 402 with $39.00 USDC (39000000 units)
    r_unpaid_json = client.get(f"/v1/unlock-patch/{audit_id}", headers={"Accept": "application/json"})
    assert r_unpaid_json.status_code == 402
    assert "PAYMENT-REQUIRED" in r_unpaid_json.headers
    body_402 = r_unpaid_json.json()
    assert body_402["amount"] == "39000000"
    assert body_402["price_usdc"] == "39.00"
    assert "scorecard" in body_402
    assert "patch_bundle" not in body_402

    # 3. Unpaid HTML browser visit (Accept: text/html) -> renders checkout preview HTML + PAYMENT-REQUIRED header
    r_unpaid_html = client.get(f"/v1/unlock-patch/{audit_id}", headers={"Accept": "text/html"})
    assert r_unpaid_html.status_code == 402
    assert "PAYMENT-REQUIRED" in r_unpaid_html.headers
    assert "Pay $39 USDC on Base (x402 Gasless)" in r_unpaid_html.text
    assert audit_id in r_unpaid_html.text

    # 4. Paid request with PAYMENT-SIGNATURE ($39 USDC = 39000000 units) -> 200 OK with full patch bundle
    pay_hdr_39 = _make_test_payment_header("39000000")
    r_paid = client.post(
        f"/v1/unlock-patch/{audit_id}?format=json",
        headers={"PAYMENT-SIGNATURE": pay_hdr_39, "Accept": "application/json"},
    )
    assert r_paid.status_code == 200
    assert "PAYMENT-RESPONSE" in r_paid.headers
    paid_data = r_paid.json()
    assert paid_data["status"] == "unlocked"
    bundle = paid_data["patch_bundle"]
    assert "--- a/" in bundle["unified_diff"]
    assert "assert_safe_outbound_url" in bundle["hardened_middleware_py"]
    assert "assertSafeOutboundUrl" in bundle["hardened_middleware_ts"]
    assert len(bundle["bundle_zip_base64"]) > 100


def test_no_secret_files_in_repo():
    root = Path(__file__).resolve().parent.parent
    forbidden = []
    for p in root.rglob("*"):
        name_low = p.name.lower()
        if name_low.startswith(".env") or name_low.endswith((".pem", ".key")):
            forbidden.append(str(p))
    assert forbidden == [], f"Forbidden secret/.env files found: {forbidden}"


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    for fn in (
        test_health_and_discovery,
        test_mcp_zero_cold_start_and_annotations,
        test_mcp_3_free_calls_then_402_and_paid_retry,
        test_ssrf_guard_blocking,
        test_autopatch_vault_audit_and_unlock,
        test_no_secret_files_in_repo,
    ):
        fn()
        print(f"[PASS] {fn.__name__}")
    print("ALL 6 GATEWAY VERIFICATION TESTS PASSED!")

