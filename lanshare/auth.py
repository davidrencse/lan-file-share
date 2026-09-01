"""Mutual authentication over an established TLS channel.

We cannot rely on CA-validated certificates on a LAN, so authentication is done
with a shared secret using an HMAC challenge-response. Crucially, each HMAC is
computed over both random nonces *and* the server's TLS certificate
fingerprint. Binding the proof to the certificate fingerprint means a
man-in-the-middle (who would necessarily present a different certificate, and
who does not know the shared secret) cannot relay a valid exchange -- this is
classic channel binding.

Flow (client = sender, server = receiver):

    server -> client : {"nonce": Ns}
    client -> server : {"nonce": Nc, "mac": HMAC(secret, "client"|Ns|Nc|fpr)}
    server verifies client mac
    server -> client : {"mac": HMAC(secret, "server"|Ns|Nc|fpr)}
    client verifies server mac

Both directions must verify for the transfer to proceed, giving mutual auth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import socket

from .netutil import ProtocolError, recv_msg, send_msg

NONCE_BYTES = 32


class AuthError(Exception):
    """Raised when the peer fails to prove knowledge of the shared secret."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"invalid base64 in auth message: {exc}") from exc


def _mac(secret: bytes, role: str, ns: bytes, nc: bytes, fpr: str) -> bytes:
    msg = b"lanshare-auth-v1|" + role.encode("ascii") + b"|" + ns + b"|" + nc
    msg += b"|" + fpr.encode("ascii")
    return hmac.new(secret, msg, hashlib.sha256).digest()


def server_authenticate(sock: socket.socket, secret: bytes, server_fpr: str) -> None:
    """Run the receiver (server) side of the handshake. Raises on failure."""
    ns = secrets.token_bytes(NONCE_BYTES)
    send_msg(sock, {"type": "auth-challenge", "nonce": _b64(ns)})

    resp = recv_msg(sock)
    if resp.get("type") != "auth-response":
        raise ProtocolError("expected auth-response")
    nc = _unb64(str(resp.get("nonce", "")))
    if len(nc) < 16:
        raise ProtocolError("client nonce too short")
    client_mac = _unb64(str(resp.get("mac", "")))

    expected = _mac(secret, "client", ns, nc, server_fpr)
    if not hmac.compare_digest(client_mac, expected):
        raise AuthError("peer failed shared-secret authentication")

    server_mac = _mac(secret, "server", ns, nc, server_fpr)
    send_msg(sock, {"type": "auth-confirm", "mac": _b64(server_mac)})


def client_authenticate(sock: socket.socket, secret: bytes, server_fpr: str) -> None:
    """Run the sender (client) side of the handshake. Raises on failure."""
    challenge = recv_msg(sock)
    if challenge.get("type") != "auth-challenge":
        raise ProtocolError("expected auth-challenge")
    ns = _unb64(str(challenge.get("nonce", "")))
    if len(ns) < 16:
        raise ProtocolError("server nonce too short")

    nc = secrets.token_bytes(NONCE_BYTES)
    client_mac = _mac(secret, "client", ns, nc, server_fpr)
    send_msg(sock, {"type": "auth-response", "nonce": _b64(nc), "mac": _b64(client_mac)})

    confirm = recv_msg(sock)
    if confirm.get("type") != "auth-confirm":
        # A rejecting server may close instead; surface a clear message.
        raise AuthError("server did not confirm authentication")
    server_mac = _unb64(str(confirm.get("mac", "")))
    expected = _mac(secret, "server", ns, nc, server_fpr)
    if not hmac.compare_digest(server_mac, expected):
        raise AuthError("server failed shared-secret authentication (possible MITM)")
