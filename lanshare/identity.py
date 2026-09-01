"""Per-device TLS identity: a persistent self-signed certificate + key.

Each device generates one keypair/certificate the first time it runs and reuses
it forever after. The certificate is *not* validated against a CA (there is no
CA on a LAN); instead its SHA-256 fingerprint is used as a stable device
identity and as the channel-binding value for the HMAC authentication step
(see :mod:`lanshare.auth`).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import stat
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import config


def _paths() -> Tuple[Path, Path]:
    d = config.config_dir()
    return d / "identity.key", d / "identity.crt"


def ensure_identity(device_name: str) -> Tuple[Path, Path]:
    """Return (key_path, cert_path), generating them on first use."""
    key_path, cert_path = _paths()
    if key_path.exists() and cert_path.exists():
        return key_path, cert_path
    _generate(device_name, key_path, cert_path)
    return key_path, cert_path


def _generate(device_name: str, key_path: Path, cert_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"lanshare:{device_name}")]
    )
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    # Write the key with owner-only perms *before* the bytes land, where we can.
    key_path.write_bytes(key_bytes)
    if os.name != "nt":
        try:
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
    cert_path.write_bytes(cert_bytes)


def fingerprint_from_der(der: bytes) -> str:
    """SHA-256 fingerprint of a DER-encoded certificate, as lowercase hex."""
    return hashlib.sha256(der).hexdigest()


def fingerprint_pretty(hex_fpr: str) -> str:
    """Group a hex fingerprint into colon-separated byte pairs for display."""
    return ":".join(hex_fpr[i : i + 2] for i in range(0, len(hex_fpr), 2))


def own_fingerprint() -> str | None:
    """SHA-256 fingerprint of this device's own certificate, if generated."""
    _key_path, cert_path = _paths()
    if not cert_path.exists():
        return None
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = cert.public_bytes(serialization.Encoding.DER)
    return fingerprint_from_der(der)
