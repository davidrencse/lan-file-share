# LANShare

A small, **reasonably secure**, cross-platform file-sharing tool for devices on
the same local network. It works in every direction — Windows → Linux,
Linux → Windows, Linux → Linux, Windows → Windows — as long as both machines are
on the same Wi‑Fi / LAN.

Every transfer is:

- **Encrypted** with TLS 1.2+ (TLS 1.3 when both ends support it), using a
  persistent self‑signed identity certificate generated per device.
- **Authenticated** in both directions with a shared secret via an HMAC
  challenge‑response that is *bound to the TLS certificate fingerprint*
  (channel binding), so a man‑in‑the‑middle cannot relay a session.
- **Approved by a human** on the receiving device before a single byte is
  written (unless you explicitly opt into `--yes` for testing).
- **Restricted to the local network** — connections from routable/public IP
  addresses are refused.
- **Written safely** — file names are sanitized, sizes are validated against a
  limit and against free disk space, and files can only ever land inside the
  configured download directory (no path traversal, no overwrites).

It is pure Python and depends only on the well‑known
[`cryptography`](https://pypi.org/project/cryptography/) library.

---

## Requirements

- Python 3.8 or newer on each device.
- The `cryptography` package.

## Install

On **each** device:

```bash
pip install -r requirements.txt
```

Optionally install the `lanshare` command:

```bash
pip install .
```

If you don't install it, run everything as `python -m lanshare ...` from this
folder instead of `lanshare ...`.

---

## Quick start

### 1. Initialise each device

On device **A**:

```bash
lanshare init --name laptop-alice
```

This generates the device's TLS identity and prints a freshly generated
**shared secret**, e.g. `41fkBA77ZRC3iOiqrjMPkg`.

### 2. Pair the other device with the same secret

On device **B**, use the secret shown on A (both devices must share it):

```bash
lanshare init --name desktop-bob
lanshare set-secret 41fkBA77ZRC3iOiqrjMPkg
```

> The shared secret is what authenticates devices to each other. Anyone who
> knows it can send you files (still subject to your approval). Treat it like a
> Wi‑Fi password: share it out‑of‑band, keep it off untrusted machines. You can
> reprint it with `lanshare show-secret` or replace it with `lanshare set-secret`.

### 3. Start the receiver on the device that will *receive*

```bash
lanshare receive
```

You'll see something like:

```
LANShare receiver 'desktop-bob' is ready.
  Listening on : 192.168.1.42 port 51888
  Saving files to: C:\Users\bob\LANShare received
  This device's fingerprint: 96:8e:55:d1:...
  Waiting for transfers... (Ctrl+C to stop)
```

### 4. Send from the other device

Find receivers on the network:

```bash
lanshare discover
```

Then send by IP:

```bash
lanshare send 192.168.1.42 ./report.pdf ./photo.jpg
```

…or by device name (resolved automatically via discovery):

```bash
lanshare send desktop-bob ./report.pdf --find
```

The receiver is prompted to **accept or decline** each file:

```
  Incoming file transfer request
    From        : laptop-alice  (192.168.1.7)
    File        : report.pdf
    Size        : 2.4 MiB
    Will save to: C:\Users\bob\LANShare received

  Accept this file? [y/N]
```

On accept, the file is streamed, its SHA‑256 is verified on both ends, and it's
saved atomically into the download directory.

---

## Commands

| Command | Description |
|---|---|
| `lanshare init [--name NAME]` | Generate identity + a shared secret (first run). |
| `lanshare set-secret [SECRET]` | Set the shared secret (prompts if omitted). |
| `lanshare show-secret` | Print the current secret and this device's fingerprint. |
| `lanshare info` | Show configuration, paths, identity fingerprint, local IPs. |
| `lanshare config [--name --dir --port --max-size --discovery]` | View/change persistent settings. |
| `lanshare receive [--dir --port --name --no-discovery --yes]` | Run the receiver and wait for transfers. |
| `lanshare send TARGET FILE... [--port --find]` | Send file(s) to a receiver (IP, or name with `--find`). |
| `lanshare discover [--timeout N]` | List LANShare receivers on the network. |
| `lanshare selftest` | Run a local loopback transfer to verify the install. |

Useful options:

- `lanshare config --dir "D:\Incoming"` — change where received files are saved.
- `lanshare config --max-size 20G` — cap the size of files you'll accept.
- `lanshare receive --port 52000` — use a non‑default TCP port (default `51888`).
- `lanshare receive --yes` — **insecure**: auto‑accept every transfer. Testing only.

---

## Cross-platform notes

- **Windows ↔ Linux both ways** are supported and tested; the wire protocol is
  OS‑independent and file names are normalised safely for the receiving OS.
- **Firewall:** the receiver listens on TCP `51888` and answers UDP discovery on
  `51889`. Allow these on the receiver:
  - *Windows:* the first run of `lanshare receive` usually triggers a Windows
    Defender Firewall prompt — allow it on **Private** networks. Or, in an
    elevated PowerShell:
    ```powershell
    New-NetFirewallRule -DisplayName "LANShare" -Direction Inbound -Protocol TCP -LocalPort 51888 -Action Allow -Profile Private
    New-NetFirewallRule -DisplayName "LANShare discovery" -Direction Inbound -Protocol UDP -LocalPort 51889 -Action Allow -Profile Private
    ```
  - *Linux (ufw):*
    ```bash
    sudo ufw allow from 192.168.0.0/16 to any port 51888 proto tcp
    sudo ufw allow from 192.168.0.0/16 to any port 51889 proto udp
    ```
- **Discovery** relies on UDP broadcast, which some networks (guest Wi‑Fi,
  "client isolation", most corporate VLANs) block. If `discover` finds nothing,
  send by IP directly — that always works as long as the two machines can reach
  each other. Find a device's IP with `lanshare info` on that device.

---

## Where things are stored

| What | Windows | Linux/macOS |
|---|---|---|
| Config & identity | `%APPDATA%\LANShare` | `~/.config/lanshare` |
| Received files (default) | `~\LANShare received` | `~/LANShare received` |

Set `LANSHARE_HOME` to override the config directory (handy for running two
instances on one machine, as the tests do).

---

## Security model — what it does and doesn't protect

**Threat model:** other devices on the same LAN, including a malicious one that
can see traffic or try to connect to you.

What LANShare provides:

1. **Confidentiality & integrity in transit** — TLS 1.2+/1.3 encrypts the
   stream; a per‑file SHA‑256 is verified end‑to‑end.
2. **Mutual authentication** — both ends prove knowledge of the shared secret
   with an HMAC exchange over two random nonces. The HMAC also covers the
   receiver's certificate fingerprint, so an attacker who intercepts the
   connection (and therefore presents a *different* certificate) cannot produce
   a valid exchange even though they can't read the secret. This is the same
   channel‑binding idea used by SCRAM.
3. **Trust on first use (TOFU)** — the sender remembers each receiver's
   certificate fingerprint and warns loudly if a known device name later shows a
   different fingerprint (possible impersonation, or a legitimate reinstall).
4. **Explicit consent** — nothing is written without the receiving user saying
   yes (outside `--yes` test mode).
5. **Network scoping** — the receiver refuses connections whose source address
   isn't loopback / link‑local / RFC1918‑private, and the sender refuses to
   connect to non‑LAN addresses.
6. **Safe file handling** — untrusted file names are reduced to a sanitized base
   name (no directories, no `..`, no control characters, no Windows reserved
   device names, length‑capped); the destination is verified to be inside the
   download directory; existing files are never overwritten (`name (1).ext`);
   declared sizes are checked against a configurable ceiling and free disk space;
   incoming bytes are read to an exact count into a temp file and atomically
   renamed only after the hash checks out.

Honest limitations (it's "reasonably secure", not a hardened product):

- The shared secret and TLS private key are stored on disk. On POSIX they're
  written `0600` in a `0700` directory; on Windows they rely on your user
  profile's ACL. Protect the machine accordingly.
- Certificates are self‑signed; identity trust is TOFU + the shared secret, not
  a CA. A brand‑new device is trusted the first time you talk to it.
- Anyone who knows your shared secret can *offer* you files (you still approve
  each one) and, if they also run a receiver, receive from you. Rotate the
  secret (`lanshare set-secret`) if it leaks.
- There's no rate limiting / brute‑force lockout; it's built for a home/office
  LAN, not a hostile public network.

---

## Development

Run the test suite (no third‑party test runner required):

```bash
python tests/test_lanshare.py
```

…or with pytest if you have it:

```bash
pytest -q
```

Verify a working transfer without a second machine:

```bash
python -m lanshare selftest
```

## License

MIT
"# lan-file-share" 
