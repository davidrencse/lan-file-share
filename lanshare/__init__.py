"""LANShare -- a small, reasonably secure LAN file-sharing tool.

Cross-platform (Windows <-> Linux) peer-to-peer file transfer over the local
network. Every transfer is:

  * encrypted with TLS 1.2+ (self-signed per-device identity certificate;
    TLS 1.3 when both peers support it, with the 1.2 cipher list pinned to
    forward-secret AEAD suites),
  * authenticated from a shared secret with a SPAKE2 password-authenticated key
    exchange plus a key confirmation bound to the TLS certificate fingerprint
    (a PAKE, so no offline-guessable material is exposed; channel-bound ->
    MITM-safe),
  * explicitly approved by the person on the receiving device,
  * restricted to peers on the local/private network,
  * written only into a designated download directory, with validated and
    sanitized file names and enforced size limits.

See the README for usage.
"""

__version__ = "1.0.0a1"

# Wire-protocol version. Bump when the framing / message shapes change.
PROTOCOL_VERSION = 2

# Default TCP port for the TLS transfer service.
DEFAULT_PORT = 51888

# Default UDP port used for LAN peer discovery.
DEFAULT_DISCOVERY_PORT = 51889

__all__ = ["__version__", "PROTOCOL_VERSION", "DEFAULT_PORT", "DEFAULT_DISCOVERY_PORT"]
