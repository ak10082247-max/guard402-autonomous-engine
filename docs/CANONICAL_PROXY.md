# Canonical service gateway

Guard exposes the existing REST aliases and 15 MCP tool names. Thirteen tools
forward to fixed HTTPS endpoints on the four owned services. The two AutoPatch
tools are unavailable until source acquisition and patch verification exist.

The upstream response supplies the authoritative price, resource, payment
requirements and receipt. Buyers authorize that canonical resource and send
the same payment payload through Guard or directly to the canonical endpoint.
Guard forwards the payload unchanged, sends no separate settlement request,
and does not turn a public transaction hash into proof of buyer ownership.

There is no local free-call quota or public quota-reset operation. Upstream
services retain their own payment and any trial policy. Unknown REST actions
return 404 rather than invoking a default paid tool. Unknown or conflicting
arguments return 400. Inputs for a different trade size, an unsupported
multi-tool audit, or an unimplemented capability must never be silently dropped.

Canonical field normalization includes one MCP tool definition, complete
EIP-712 typed data, and snake_case router token aliases. All other parameters
must follow the displayed tool schema. In particular:

- Solana mint inspection requires explicit `simulate_sell:false`; it proves no
  buy/sell execution. Solana buy/sell simulation remains unavailable.
- Base buy/sell simulation currently covers one supported Uniswap V2 WETH pool
  and a disclosed 0.001 ETH input, rather than arbitrary user trade sizes.
- `include_cross_venue:false` requests Polymarket-only measured trades.
  Cross-venue mode acquires identity-matched Polymarket/Limitless outcome books,
  100-share VWAP and venue fees for supported coverage; fills and profit are not guaranteed.
- `limited_review:true` explicitly requests Tollbooth's limited pattern review;
  Guard never inserts this choice on behalf of a buyer.
- Specialized RugShield analyses may return unavailable or incomplete evidence.
  Proxying an endpoint is not a claim that the full analysis is implemented.

Requests make exactly one upstream attempt, without redirects. A paid timeout
returns `SETTLEMENT_PENDING_RECONCILIATION`; callers must retain the identical
authorization and request. Guard never retries with a new authorization.

AutoPatch source generation, fake scorecards, placeholder patches and invented
post-patch grades were removed. Historical data files remain unchanged and are
ineligible for sale. Both acquisition and unlock reject before issuing a $39
challenge or settling funds. Vault registration requires a configured admin
Bearer token and still fails closed because authentication cannot substitute
for a verified bundle. No $39 live payment is part of the capped test program.

Run the unfunded proxy suite with `python -m pytest tests/test_gateway.py -q`.
Its HTTP mocks are test-only and no test accepts a payment based on `TESTING`,
a signature prefix, a fixed payer address or an invented transaction hash.
