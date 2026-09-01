"""TLS context construction for both ends of a transfer.

Certificates are self-signed device identities, so we deliberately do *not*
perform CA validation or hostname checking. Confidentiality comes from TLS;
peer *identity* is established out-of-band via the certificate fingerprint plus
the shared-secret HMAC (see :mod:`lanshare.auth`). TLS 1.2 is the floor; 1.3 is
used automatically when both peers support it.
"""

from __future__ import annotations

import ssl
from pathlib import Path


def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    # We authenticate the client with the HMAC step, not a client certificate.
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def client_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Self-signed peer: skip CA/hostname checks; we pin the fingerprint instead.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
