"""TLS context construction for both ends of a transfer.

Certificates are self-signed device identities, so we deliberately do *not*
perform CA validation or hostname checking. Confidentiality comes from TLS;
peer *identity* is established out-of-band via the certificate fingerprint plus
the SPAKE2 key-confirmation (see :mod:`lanshare.auth`).

TLS 1.2 is the floor and TLS 1.3 is used automatically whenever both peers
support it (TLS always negotiates the highest version in common). On TLS 1.2 we
additionally pin the cipher suite list to modern, forward-secret AEAD suites --
ECDHE key agreement with AES-GCM or ChaCha20-Poly1305 -- so a 1.2 connection
can never fall back to a non-PFS (RSA key-exchange) or CBC/3DES suite even if
some future OpenSSL default would otherwise allow one. TLS 1.3's suites are all
AEAD + PFS by construction, so there is nothing to pin there. The device
identity key is an EC P-256 key, so an ECDHE suite is always available.
"""

from __future__ import annotations

import ssl
from pathlib import Path

# Applied to TLS 1.2 only (set_ciphers does not affect 1.3). OpenSSL ignores
# names it does not know, and both ends offer the same small set, so the chosen
# suite is always forward-secret and AEAD.
_TLS12_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)


def _harden(ctx: ssl.SSLContext) -> None:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_TLS12_CIPHERS)
    except ssl.SSLError:
        # An unusual OpenSSL build may know none of these names. Rather than
        # fail to talk at all, fall back to the library default -- still TLS
        # 1.2+ -- which on any modern build is already PFS/AEAD.
        pass


def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _harden(ctx)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    # We authenticate the client with the SPAKE2 step, not a client certificate.
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # check_hostname must be cleared before verify_mode on a CLIENT context.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Self-signed peer: skip CA/hostname checks; we pin the fingerprint instead.
    _harden(ctx)
    return ctx
