"""Backwards-compatible names for the AIRLOCK agent gateway client.

Some integrations historically imported ``gateway_client`` rather than the
shorter ``client`` module.  Keep this module deliberately boring: the single
implementation remains in :mod:`app.agents.client`, so both paths get the same
API-key, identity, and decision handling.
"""

from .client import AirlockBlocked, AirlockClient, guard, guard_tool

GatewayClient = AirlockClient
AirlockGatewayClient = AirlockClient

__all__ = [
    "AirlockBlocked",
    "AirlockClient",
    "AirlockGatewayClient",
    "GatewayClient",
    "guard",
    "guard_tool",
]
