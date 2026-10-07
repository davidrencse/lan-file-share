# The journey

How LANShare went from an empty repository to a cross-platform, PAKE-authenticated
file-sharing tool. This is the story the commit history tells — the dead ends,
the bugs that only show up on real networks, and the way the security model grew
one honest limitation at a time.

> This is a narrative, not an API reference. For how to *use* the thing, see the
> [usage guide](USAGE.md).

---

## Timeline at a glance

| Date | Commit | Milestone |
|---|---|---|
| 2026-09-01 | `1ddf2d2` | Empty repository |
| 2026-09-01 | `5b73007` | A working cross-platform CLI |
| 2026-09-01 | `c163650` | The PySide6 desktop GUI |
| 2026-09-01 | `f0634bb` | A full security + correctness audit pass |
| 2026-09-02 | `925e315` | Installs on modern (PEP 668) Linux |
| 2026-09-02 | `7009631` | Stops rejecting the user’s *own* network |
| 2026-09-02 | `286a384` | The app learns to explain itself |
| 2026-09-03 | `bbfee4a` | Folder transfers |
| 2026-09-15 | `bd3ab77` | More features, polish |
| 2026-10-07 | `583b208` | SPAKE2 handshake, pinned TLS ciphers, CI |
| 2026-10-07 | `e4f58a3` | scrypt-hardened discovery |

---

## Phase 1 — a transfer that works (`5b73007`)

The first real commit was the engine: a TLS server that accepts a connection,
authenticates the peer, asks for approval, and writes the file safely; and a
client that connects, authenticates, and streams. From the start the shape was
the one that survives to today:

- **TLS for confidentiality**, with a self-signed per-device certificate rather
  than a CA (there is no CA on a home LAN).
- **A shared secret for authentication**, because a self-signed certificate
  proves nothing about *who* you’re talking to on its own.
- **Explicit approval** on the receiving end — the receiver, not the sender,
  decides whether a byte is written.
- **A framed JSON control protocol** with a hard size cap, so a malicious peer
  can’t ask the receiver to buffer something enormous. File *content* streams
  separately and never goes through that path.

The authentication was an HMAC challenge-response: two random nonces, and —
crucially even then — the HMAC covered the server’s TLS certificate fingerprint.
That **channel binding** is what made a man-in-the-middle fail: an attacker who
intercepts the connection necessarily presents a different certificate, so the
proof the honest peer computes won’t match. (Phase 7 keeps this idea and swaps
the HMAC underneath it for a PAKE.)

## Phase 2 — a face (`c163650`)

A command-line file-sharer is a hard sell to the person whose laptop is the
*other* end of the transfer. The PySide6 GUI put a Dashboard, a Send page, a
Files page and Settings over the same engine — no second implementation, just a
different front end calling the same `send_files()` / `Receiver`.

Two decisions here paid off later: the GUI talks to the engine through
callbacks (progress, log, approval, completion) rather than reaching into it,
and peer-supplied text is always rendered as **plain text** — no chance for a
file named with markup or control characters to do anything but display.

## Phase 3 — the audit (`f0634bb`)

Before adding features, a deliberate pass over everything a *remote peer*
controls: file names, sizes, paths. This is where most of `safety.py` comes
from, and the thinking is worth preserving:

- **File names are hostile input.** Strip directory components and traversal,
  neutralize Windows reserved device names (`CON`, `LPT1`, …), cap the length,
  and — subtly — strip Unicode **bidirectional overrides and zero-width
  characters**. Without that, a sender could name a file `‮gnp.exe` that
  *renders* as `exe.png` in the approval prompt, defeating the entire point of
  showing the user a name to approve.
- **The destination must be provably inside the download directory**, checked by
  resolving the real path (so a planted symlink is caught, not written through),
  and claimed atomically with `O_EXCL` so two concurrent transfers can never
  select the same path.
- **Sizes are checked** against a ceiling and free disk space *before* a byte is
  written — and the rejection told the peer only “too big”, never the actual
  limit or the actual free space, so a paired peer can’t read your disk layout
  by offering impossible files.

## Phase 4 — meeting reality on Linux (`925e315`)

The tool worked; installing it didn’t. Modern distributions (Arch, Debian 12+,
Ubuntu 23.04+, Fedora 38+) ship an `EXTERNALLY-MANAGED` marker and **refuse
`pip install`** into the system Python (PEP 668) — on purpose. Advice that boils
down to “just run pip install” is actively wrong there.

So LANShare learned to *detect* the situation and give the right answer per
system: the distro package name when there is one (`python-cryptography` on
Arch, `python3-cryptography` on Debian), or `./install.sh` to build a local
`.venv`. The installer reuses system site-packages where they exist, which on
Arch also gets you a Qt that matches your Wayland stack.

## Phase 5 — the bug that only exists on real Wi-Fi (`7009631`)

This is the most instructive fix in the project.

The receiver only accepts peers on the “local network”, and the obvious
implementation is: *is this a private (RFC1918) address?* It passed every test
on every developer machine — and then refused **every** peer on a real home
Wi-Fi, because that router handed out `172.1.140.16/20`, which is *public*
address space. The shortcut (“private range == local”) is simply wrong.

The fix was to stop guessing and **ask the operating system which networks this
host is actually attached to** (`localnet.py`: a Windows `GetAdaptersAddresses`
path and a POSIX `ioctl` path), then accept an address if it falls inside one of
*those* — plus loopback, link-local, RFC1918/ULA, and any subnet the user
explicitly trusts. A genuinely remote host is still refused. There’s even a
regression test pinning the exact real-world network (`172.1.0.0/16`) that
started it.

The lesson generalized: a lot of LANShare’s correctness is about **real
networks being messier than the model** — multiple interfaces, VirtualBox/WSL
adapters, VPNs, Wi-Fi and Ethernet on separate subnets.

## Phase 6 — the app explains itself (`286a384`)

On a LAN, “it doesn’t work” almost always means one of a handful of things:
Receiving is off on the other side, the secrets don’t match, a firewall, or a
network that blocks broadcast. None of those produce an *error* — they produce
**silence**, which looks identical to “there’s nothing out there.”

So this phase was about turning silence into an explanation:

- A **setup wizard** that generates the secret and a **Secret ID** — a short
  hash shown on both devices so you can confirm a match without comparing the
  full secret. (It’s display-only and never transmitted; putting it on the wire
  would hand an eavesdropper an offline check against guessed secrets.)
- A **“Why can’t I see my other device?”** diagnostic that runs every check it
  can from this side and reports what it found — including *counting* the
  connections it refused as “not local”, which previously vanished to stderr the
  GUI never showed.
- Authenticated discovery became part of the answer, too: with it, a mismatched
  secret produces silence — so the UI had to make “you two don’t share a secret”
  visible, which is exactly what the Secret ID does.
- A persistent **Files** page backed by a transfer **history** file, so “what
  did they send me, and where did it go?” has an answer after a restart.

## Phase 7 — folders, and the batch protocol (`bbfee4a`)

Sending a directory naïvely — flatten it, or re-prompt per file — is either
lossy or unusable for a few thousand files. LANShare added a **batch** protocol
instead: one `batch` message describes the whole folder, the user approves it
**once**, a fresh top-level directory is claimed for it, and the files stream in
at their relative paths until a `batch_end` closes it.

The security stance is that the **receiver**, not the sender’s say-so, stays in
charge of whether directories get created at all: every file inside an approved
batch is still re-sanitized component by component (`sanitize_relpath` refuses
traversal rather than silently rewriting it), containment is re-proved after
each created directory (so a subdirectory that’s secretly a symlink is caught),
and the batch is capped at the file count and total size it declared. A folder
arriving as `photos` de-duplicates to `photos (1)` with its tree intact.

This also forced some honest performance work that the comments still carry:
history writes were batched (a folder of thousands of files had been doing one
`open()` of the history file per file, mid-transfer), the history trim became
amortized instead of `O(N²)`, and a **keepalive** was added so hashing a large
file on a slow disk doesn’t look like a stalled peer and get dropped.

## Phase 8 — polish (`bd3ab77`)

Accumulated refinements across the GUI and engine — the kind of work that
doesn’t change the protocol but makes the tool feel finished.

## Phase 9 — from HMAC to PAKE (`583b208`)

By now the one thing the security model kept having to *apologize* for was this:
the HMAC challenge-response, however well channel-bound, **reveals an HMAC
computed with the shared secret**. Anyone who can lure you into connecting to
them learns that transcript and can attack it **offline** — guessing the secret
at full speed. With a generated ~128-bit secret that’s hopeless for them; with a
short human-chosen one it isn’t.

The fix was to replace the handshake with a **PAKE — SPAKE2** (the same library
magic-wormhole uses). A PAKE’s defining property is exactly the property that
was missing: observing, or even participating in, a run reveals **nothing** that
speeds up an offline guess. An impostor is reduced to one *online* guess per
connection — which the receiver’s existing auth throttle already rate-limits.

SPAKE2 turns the shared secret into a strong key *only if both sides hold the
same secret*; a mismatch yields two unrelated keys and no error. So a **key
confirmation** step was added on top — and, keeping the idea that already worked,
each confirmation MAC is bound to the receiver’s TLS certificate fingerprint.
That’s what preserves the man-in-the-middle defence on top of the new primitive.

Two more hardening changes rode along:

- **TLS cipher pinning.** Keep TLS 1.2 as the floor and TLS 1.3 whenever both
  peers support it, but pin the 1.2 cipher list to forward-secret AEAD suites
  (ECDHE + AES-GCM / ChaCha20-Poly1305) so a legacy static-RSA or CBC suite can
  never be negotiated.
- **Continuous integration.** A GitHub Actions workflow runs the test suite
  *and* the loopback self-test on every push and pull request, across Python
  3.8–3.12 on Linux, Windows and macOS — so “it works on my machine” becomes “it
  works on fifteen.”

## Phase 10 — closing the last offline door (`e4f58a3`)

Moving the transfer handshake to a PAKE left one asymmetry: **discovery** still
authenticated its UDP query/reply with an HMAC keyed directly on the secret. A
passive eavesdropper who captured a single discovery packet could still attack
*that* offline. Discovery is a one-shot broadcast with no room for a round-trip
key agreement, so a PAKE doesn’t fit there.

The answer was to make each offline guess **expensive** instead of impossible:
derive the discovery HMAC key from the secret with **scrypt** (`n=2¹⁵, r=8,
p=1`) rather than using the secret directly. Verifying one guessed secret
against a captured packet now costs a full scrypt evaluation instead of a single
SHA-256 — turning a fast search into a slow one. The derived key is computed
once and cached, so the honest side pays that cost a single time and never on the
packet path. The protocol magic bumped `v2 → v3` to make the incompatible keying
explicit rather than fail an opaque MAC check against an old peer.

---

## What the history taught

A few threads run through all ten phases:

- **Real networks break clean models.** The single most important correctness
  fix (Phase 5) was discovering that “private IP” and “my network” are different
  questions. Multiple interfaces, VPNs, and split subnets are the normal case,
  not the exception.
- **Silence is the worst error message.** A huge amount of the work (Phase 6)
  went into converting “nothing happened” into “here’s specifically what’s
  wrong,” because on a LAN the failures don’t raise exceptions.
- **The security model improved by naming its own weaknesses.** Each phase’s
  README carried an honest “limitations” section, and the later phases are
  literally those limitations being retired: the offline-attack caveat drove the
  move to SPAKE2 (Phase 9) and then scrypt discovery (Phase 10).
- **Untrusted input is untrusted at every layer.** Names, sizes, paths, and
  peer-supplied display text are each sanitized where they’re used, and the
  receiver — never the sender — decides what lands on disk.

The result is still, deliberately, *“reasonably secure”* software for a
home/office LAN rather than a hardened product for a hostile one. But every
version has known exactly where that line sits, and said so.
