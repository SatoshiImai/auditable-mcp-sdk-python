"""Injectable signing/verification adapters for external key-management backends.

These plug into the same `EventSigner` (tool) and `SignatureVerifier` (host) seams as the bundled
local Ed25519 implementation. They are optional and each keeps its backend a soft dependency: the
adapter code takes an injected client (duck-typed) and never imports the vendor SDK, so `import`ing
it does not require the extra. Users install the backend via an extra, e.g. `auditable-mcp-sdk[aws]`.
"""
