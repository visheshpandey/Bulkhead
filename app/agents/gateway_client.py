"""Gateway client names for Bulkhead integrations.

Some integrations historically imported ``gateway_client`` rather than the
shorter ``client`` module.  Keep this module deliberately boring: the single
implementation remains in :mod:`app.agents.client`, so both paths get the same
API-key, identity, and decision handling.
"""

from .client import (
    BulkheadBlocked,
    BulkheadClient,
    bulkhead_guard,
    guard,
    guard_tool,
)

GatewayClient = BulkheadClient
BulkheadGatewayClient = BulkheadClient

__all__ = [
    "BulkheadBlocked",
    "BulkheadClient",
    "BulkheadGatewayClient",
    "GatewayClient",
    "bulkhead_guard",
    "guard",
    "guard_tool",
]
