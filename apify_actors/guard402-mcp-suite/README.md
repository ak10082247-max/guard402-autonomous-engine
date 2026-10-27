# Guard402 Autonomous MCP Security, Web Sanitizer & DeFi Audit Suite

**Guard402 Autonomous MCP Suite** (`guard402-autonomous-mcp-suite`) is a 6-in-1 security verification, prompt-injection firewall, SSRF-safe stealth web extraction, and on-chain DeFi intelligence Actor built for autonomous AI agents, MCP servers, and Web3 execution pipelines.

Backed by the live **Kurox x402 V2 Dual-Chain Intelligence Fleet** (`canaryguard-402`, `stealthguard-402`, `rugshield-402`, and `x402-agent-tollbooth`), every run produces a deterministic security score (`0–100`), machine-verifiable cryptographic receipt (`guard402-v2-*`), and an optional **AutoPatch Vault** unified diff remediation preview.

---

## Capabilities & Supported Actions

| Action (`action`) | PPE Event Key | Price (USD) | Description |
| :--- | :--- | :---: | :--- |
| **`audit_mcp_repo`** | `mcp_security_audit` | **`$0.02`** | Static compliance & security audit of MCP repositories for JSON-RPC 2.0 schema validation, SSRF vectors, command injection, and SPDX licensing. |
| **`sanitize_prompt`** | `prompt_firewall_scan` | **`$0.01`** | Deterministic prompt-injection firewall that detects and neutralizes system prompt overrides, hidden Unicode, HTML scripts, and wallet-drainer instructions. |
| **`stealth_extract`** | `stealth_web_extract` | **`$0.02`** | SSRF-guarded web extraction that strips active scripts/trackers into clean LLM Markdown and scrubs extracted DOM text through CanaryGuard. |
| **`scan_base_token`** | `token_rug_simulation` | **`$0.02`** | On-chain Base Mainnet (`eip155:8453`) bytecode verification and pre-trade honeypot/tax simulation via RugShield-402 & Base RPC. |
| **`contract_audit`** | `smart_contract_patch_preview` | **`$0.05`** | Smart contract vulnerability analysis (reentrancy, unchecked calls, EIP-3009 nonce replay) with unified diff patch generation. |
| **`polymarket_whale_radar`** | `stealth_web_extract` | **`$0.02`** | Live Polymarket Gamma active market volume, liquidity depth, and whale orderflow divergence radar. |

---

## Example Input

```json
{
  "action": "audit_mcp_repo",
  "target": "https://github.com/modelcontextprotocol/servers",
  "include_patch": true,
  "strict_mode": true
}
```

## Example Output (Dataset Item)

```json
{
  "action": "audit_mcp_repo",
  "target": "https://github.com/modelcontextprotocol/servers",
  "status": "completed",
  "security_score": 94,
  "risk_level": "LOW",
  "charged_event": "mcp_security_audit",
  "charged_price_usd": 0.02,
  "safety_receipt": "guard402-v2-8f93a1c2e4b09d12",
  "autopatch_vault": {
    "patch_id": "apv-4c81e90b2a11",
    "remediation_ready": true,
    "vault_verify_url": "https://x402-agent-tollbooth.onrender.com/api/audit?patch_id=apv-4c81e90b2a11"
  }
}
```

---

## x402 V2 Dual-Chain Direct Settlement (Base & Solana)

In addition to Apify Pay-Per-Event billing, all upstream Guard402 services support gasless **x402 V2** micropayments on:
- **Base Mainnet (`eip155:8453`)**: USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
- **Solana Mainnet (`solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`)**: USDC (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)
