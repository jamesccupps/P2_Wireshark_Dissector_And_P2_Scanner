# Security policy

This policy covers the repository: the scanner (`p2_scanner.py`, `p2_gui.py`), the Wireshark dissector (`p2.lua`), `analyze_pcap.py`, the virtual panel (`virtual_pxc/`) and the protocol reference. The BACnet bridge has its own policy, in [`bridge/SECURITY.md`](bridge/SECURITY.md).

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner/security/advisories/new>). Only the maintainer sees it.
If you'd rather use email, write to jamesccupps@proton.me with `[P2 SECURITY]` at the start of the subject.

Include:
- what an attacker could do with it;
- the steps to reproduce (a capture, or a fixture for the virtual panel);
- the release or commit, and for the scanner, `p2_scanner.__version__`.

You should hear back within a week. Fixes are credited in the changelog unless you'd rather not be named.

## What counts

- **The scanner doing something destructive.** It is read-oriented by design and doesn't implement cold or warm start, flash erase or node eviction (see [Scope & ethics](README.md#scope--ethics)). A path that sends one of those, writes a point, or talks to a host or BLN you didn't give it is in scope.
- **Hostile input.** Panels, pushes and captures are untrusted. A frame or capture that crashes or hangs Wireshark through `p2.lua`, or that crashes, hangs or runs code in the scanner, its push listener or `analyze_pcap.py`, is in scope.
- **The virtual panel** answering another computer when it was started with its default bind address (127.0.0.1).
- **Real site data in the repository.** The sample capture is synthetic, and `reference_shapes.json` has lengths and contents stripped. If you find a real site's BLN, node names or addresses anywhere in the tree, please report it privately rather than in an issue.

## What doesn't

- **P2 itself.** P2 has no authentication and no encryption, and the BLN name travels in cleartext on every frame. These are properties of the protocol, which [`PROTOCOL.md`](PROTOCOL.md) documents; they're why the README says to keep P2 on a segmented automation network.
- **The scanner's footprint.** A correct-BLN handshake leaves a node-table entry on the panel, and a point read arms a change-of-value subscription for the session. That is how P2 works, and the README says so.
- **Vulnerabilities in Siemens APOGEE or Desigo products.** Report those to Siemens [ProductCERT](mailto:productcert@siemens.com).

## Supported versions

The latest release and `main`.
