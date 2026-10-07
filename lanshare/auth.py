"""Mutual authentication over an established TLS channel, using a PAKE.

We cannot rely on CA-validated certificates on a LAN, so authentication is done
from the shared pairing secret. The secret is often short and human-chosen, so
the handshake must never hand an eavesdropper -- or a device that lures us into
connecting -- material they could brute-force *offline*.

A plain HMAC challenge-response does leak such material: whoever sees the
exchange learns ``HMAC(secret, nonces)`` and can then guess the secret offline
at full speed. We use a **password-authenticated key exchange (SPAKE2)**
instead. Its defining property is that observing (or even taking part in) a run
reveals nothing that helps guess the password faster than one *online* attempt
per run -- so an impostor gets a single guess per connection, which the
receiver's auth throttle already rate-limits, and a passive eavesdropper gets
nothing at all.

SPAKE2 turns the shared secret into a strong shared key ``K`` only if both
sides hold the same secret; a mismatch yields two unrelated keys and no error.
We therefore add an explicit **key-confirmation** step, and -- crucially -- bind
each confirmation MAC to the server's TLS certificate fingerprint. That binding
is what defeats a man-in-the-middle: a MITM necessarily presents a different
certificate, so even if it somehow completed SPAKE2 it could not produce a
confirmation that matches the fingerprint the honest peer sees. This is classic
channel binding, now on top of a PAKE rather than a bare HMAC.

Flow (client = sender = SPAKE2 "A", server = receiver = SPAKE2 "B"):

    client -> server : {"pake-msg": A}
    server -> client : {"pake-msg": B}
    (both derive K = SPAKE2(secret); unequal secrets -> unrelated K)
    client -> server : {"pake-confirm": MAC_K("client" | A | B | fpr)}
    server verifies, then
    server -> client : {"pake-confirm": MAC_K("server" | A | B | fpr)}
    client verifies

Both confirmations must verify for the transfer to proceed, giving mutual auth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import socket
import struct

from spake2 import SPAKE2_A, SPAKE2_B

from .netutil import ProtocolError, recv_msg, send_msg

# Fixed role identifiers mixed into the SPAKE2 run. They must be identical on
# both ends and pin which side is which, so a message from one role can never
# be replayed as the other's.
_ID_SENDER = b"lanshare-sender"
_ID_RECEIVER = b"lanshare-receiver"

# Versioned so the transcript (and thus every confirmation MAC) changes if the
# construction ever does; also namespaces the MAC against the discovery HMACs.
_CONFIRM_TAG = b"lanshare-pake-confirm-v1"


class AuthError(Exception):
    """Raised when the peer fails to prove knowledge of the shared secret."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"invalid base64 in auth message: {exc}") from exc


def _confirm(key: bytes, role: str, msg_a: bytes, msg_b: bytes, fpr: str) -> bytes:
    """Key-confirmation MAC, bound to both SPAKE2 messages and the server fpr.

    Keyed with the SPAKE2-derived key, so only a peer that ran SPAKE2 with the
    same secret can produce it; the length-prefixed fields mean no field can be
    slid into another, and including *fpr* channel-binds the proof to the TLS
    certificate the honest peer actually sees.
    """
    h = hmac.new(key, digestmod=hashlib.sha256)
    h.update(_CONFIRM_TAG)
    for field in (role.encode("ascii"), msg_a, msg_b, fpr.encode("ascii")):
        h.update(struct.pack(">I", len(field)) + field)
    return h.digest()


def _recv_pake_msg(sock: socket.socket) -> bytes:
    msg = recv_msg(sock)
    if msg.get("type") != "pake-msg":
        raise ProtocolError("expected pake-msg")
    body = _unb64(str(msg.get("body", "")))
    # SPAKE2 group elements are a fixed, small size; anything wildly off is not
    # a valid message and must not reach the library's parser.
    if not 1 <= len(body) <= 256:
        raise ProtocolError("pake-msg has an implausible length")
    return body


def server_authenticate(sock: socket.socket, secret: bytes, server_fpr: str) -> None:
    """Run the receiver (server = SPAKE2 B) side of the handshake.

    Raises :class:`AuthError` if the peer cannot prove the shared secret, or
    :class:`ProtocolError` on a malformed exchange.
    """
    b = SPAKE2_B(secret, idA=_ID_SENDER, idB=_ID_RECEIVER)
    msg_b = b.start()

    msg_a = _recv_pake_msg(sock)
    send_msg(sock, {"type": "pake-msg", "body": _b64(msg_b)})

    try:
        key = b.finish(msg_a)
    except Exception as exc:  # noqa: BLE001 -- any library error is a failed auth
        raise AuthError("peer sent an invalid key-exchange message") from exc

    confirm = recv_msg(sock)
    if confirm.get("type") != "pake-confirm":
        raise ProtocolError("expected pake-confirm")
    client_mac = _unb64(str(confirm.get("mac", "")))
    expected = _confirm(key, "client", msg_a, msg_b, server_fpr)
    if not hmac.compare_digest(client_mac, expected):
        raise AuthError("peer failed shared-secret authentication")

    server_mac = _confirm(key, "server", msg_a, msg_b, server_fpr)
    send_msg(sock, {"type": "pake-confirm", "mac": _b64(server_mac)})


def client_authenticate(sock: socket.socket, secret: bytes, server_fpr: str) -> None:
    """Run the sender (client = SPAKE2 A) side of the handshake.

    Raises :class:`AuthError` if the server cannot prove the shared secret, or
    :class:`ProtocolError` on a malformed exchange.
    """
    a = SPAKE2_A(secret, idA=_ID_SENDER, idB=_ID_RECEIVER)
    msg_a = a.start()

    send_msg(sock, {"type": "pake-msg", "body": _b64(msg_a)})
    msg_b = _recv_pake_msg(sock)

    try:
        key = a.finish(msg_b)
    except Exception as exc:  # noqa: BLE001 -- any library error is a failed auth
        raise AuthError("server sent an invalid key-exchange message") from exc

    client_mac = _confirm(key, "client", msg_a, msg_b, server_fpr)
    send_msg(sock, {"type": "pake-confirm", "mac": _b64(client_mac)})

    confirm = recv_msg(sock)
    if confirm.get("type") != "pake-confirm":
        # A rejecting server may just close instead; surface a clear message.
        raise AuthError("server did not confirm authentication")
    server_mac = _unb64(str(confirm.get("mac", "")))
    expected = _confirm(key, "server", msg_a, msg_b, server_fpr)
    if not hmac.compare_digest(server_mac, expected):
        raise AuthError("server failed shared-secret authentication (possible MITM)")
