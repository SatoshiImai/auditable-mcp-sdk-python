"""Durable-ledger persistence: the repository contract and an in-memory implementation.

The SDK defines `LedgerRepository`; integrators implement it over their own backend. No cloud SDK
enters this package.
"""

from auditable_mcp.storage.memory import InMemoryLedgerRepository
from auditable_mcp.storage.repository import LedgerRepository, RepositoryError

__all__ = [
    'InMemoryLedgerRepository',
    'LedgerRepository',
    'RepositoryError',
]
