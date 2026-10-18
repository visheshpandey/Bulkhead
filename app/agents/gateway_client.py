"""Gateway client names for Bulkhead integrations.

Some integrations historically imported ``gateway_client`` rather than the
shorter ``client`` module.  Keep this module deliberately boring: the single
implementation remains in :mod:`app.agents.client`, so both paths get the same
API-key, identity, and decision handling.
"""

from .client import (
    AirlockBlocked,
    AirlockClient,
    BulkheadBlocked,
    BulkheadClient,
    airlock_guard,
    bulkhead_guard,
    guard,
    guard_tool,
)

GatewayClient = BulkheadClient
BulkheadGatewayClient = BulkheadClient
AirlockGatewayClient = BulkheadClient

__all__ = [
    "AirlockBlocked",
    "AirlockClient",
    "AirlockGatewayClient",
    "BulkheadBlocked",
    "BulkheadClient",
    "BulkheadGatewayClient",
    "GatewayClient",
    "airlock_guard",
    "bulkhead_guard",
    "guard",
    "guard_tool",
]
