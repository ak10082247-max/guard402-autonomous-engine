"""Vault gate. Historical template rows are preserved on disk and cannot be sold.

Source acquisition, target-bound patch generation and verification are not yet
implemented. No generic diff, client finding or admin assertion is a certificate.
"""

import re
from urllib.parse import urlsplit
from .ssrf_guard import assert_safe_url

AUTOPATCH_PRICE_USD = "39.00"
AUTOPATCH_AMOUNT_UNITS = "39000000"


class VerifiedPatchUnavailable(RuntimeError):
    pass


def validate_target(target):
    if not isinstance(target, str) or not target.strip():
        raise ValueError("A target string is required")
    if target.lower().startswith(
        ("http:", "https:", "file:", "gopher:", "ftp:", "dict:")
    ):
        assert_safe_url(target, resolve_dns=True)
    clean = target.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", clean):
        return clean
    url = urlsplit(clean)
    if (
        url.scheme == "https"
        and url.hostname == "github.com"
        and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", url.path)
        and not url.query
        and not url.fragment
        and not url.username
    ):
        return clean
    raise ValueError("Expected a public GitHub repository URL or Base contract address")


def audit_target(target, **_kwargs):
    validate_target(target)
    raise VerifiedPatchUnavailable(
        "Target source acquisition and patch verification are unavailable"
    )


def register_vault_entry(payload):
    raise VerifiedPatchUnavailable(
        "Verified target-bound bundle ingestion is not implemented"
    )


def acquire_verified_bundle(audit_id):
    # Must run before either challenge or settlement. An audit_id is never used
    # to synthesize a repository, findings, diff or post-patch grade.
    raise VerifiedPatchUnavailable(
        "No verified target-bound bundle is available; payment is disabled"
    )


def get_vault_entry(_audit_id):
    return None


def list_recent_vault_entries(limit=10):
    return []


def count_vault_entries():
    return 0


def init_vault_db():
    pass


def seed_default_vault_entries():
    pass
