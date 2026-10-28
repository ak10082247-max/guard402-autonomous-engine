"""Public payment metadata only. Canonical services own authorization and fulfillment.

Guard never interprets magic signatures, unlocks using a public transaction hash,
settles a second transfer, or invents a transaction receipt.
"""

BASE_NETWORK = "eip155:8453"
BASE_CHAIN_ID = 8453
BASE_USDC_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PAYOUT_WALLET_ADDRESS = "0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_WALLET_ADDRESS = "9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh"
PUBLIC_BASE_URL = "https://guard402-autonomous-engine.onrender.com"
FREE_CALL_QUOTA_LIMIT = 0


def get_payout_wallet():
    return PAYOUT_WALLET_ADDRESS


def verify_x402_payment(*_args, **_kwargs):
    # Intentionally fails closed for every input, including TESTING=1. Legacy
    # caller code must use the upstream proxy rather than a second settlement.
    return False, None, "LOCAL_SETTLEMENT_DISABLED_USE_CANONICAL_SERVICE", 503


def verify_onchain_base_tx(*_args, **_kwargs):
    return False, None, "PUBLIC_TRANSACTION_HASH_IS_NOT_BUYER_AUTHENTICATION"


def build_x402_challenge(*_args, **_kwargs):
    raise RuntimeError("Use the canonical service's exact payment challenge")


def encode_payment_response_header(receipt):
    raise RuntimeError(
        "Forward the canonical service's exact receipt; do not synthesize one"
    )


def check_and_increment_free_quota(*_args, **_kwargs):
    return False, 0, 0


def reset_free_quota(*_args, **_kwargs):
    """Compatibility no-op; public quota bypasses no longer exist."""
