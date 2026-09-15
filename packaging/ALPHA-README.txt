LANShare 1.0.0a1 (alpha)
========================

Send files straight from one of your computers to another over your own Wi-Fi.
No cloud account, no USB stick. Every transfer is encrypted, and nothing is
written to disk until the person receiving it says yes.

This zip contains everything needed -- there is nothing to install and no
Python required.

  LANShare.exe       the app (double-click this one)
  lanshare-cli.exe   the same thing for the command line, if you prefer


Getting started (5 minutes, once)
---------------------------------
Both devices need the same "shared secret" -- that is what proves they are
allowed to talk to each other.

1. On the first PC, run LANShare.exe. The setup wizard names the device and
   generates the shared secret. Copy it, and note the six-character SECRET ID
   shown underneath.

2. On the second device, open LANShare and go to
   Settings -> "Pair with another device's secret" -> paste -> Set.
   (On Linux, install from source -- see the project README.)

3. Check the Dashboard on both machines shows the SAME Secret ID. If they
   differ, the secret did not paste correctly. This is by far the most common
   reason two devices cannot see each other.

4. Turn on "Receiving" on whichever machine is receiving. A device is
   invisible to everyone while Receiving is off.

5. On the other machine: Send Files -> pick the device -> pick files -> Send.

Stuck? The Dashboard has a "Why can't I see my other device?" button that
checks the network, ports and firewall and tells you what is wrong.


Windows will warn you the first time
------------------------------------
These alpha builds are not code-signed yet, so SmartScreen shows
"Windows protected your PC". Click "More info" -> "Run anyway".

The first time you switch Receiving on, Windows asks whether to allow
LANShare through the firewall. Say yes, for PRIVATE networks.


Where your data lives
---------------------
Settings, your device identity and the transfer history are kept in
  %LOCALAPPDATA%\LANShare
Received files go to your Downloads folder by default (changeable in
Settings). To uninstall, delete the .exe files and that folder.


Known alpha limitations
-----------------------
  * Not code-signed, so the SmartScreen warning above is expected.
  * No auto-update -- new builds have to be downloaded by hand.
  * Both devices must be on the same local network. This is on purpose:
    LANShare refuses to talk to anything off your own subnet.
  * First launch takes a couple of seconds while the bundle unpacks.

Please report anything that breaks, with what you were doing when it did.
