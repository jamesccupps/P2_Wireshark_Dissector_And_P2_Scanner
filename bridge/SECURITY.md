# Security policy

## Scope

P2_BACnet_Bridge exposes Siemens APOGEE P2 field controllers as BACnet/IP objects, read-only. It does not implement BACnet `WriteProperty` handlers and does not issue P2 write opcodes. The threat model:

- An operator running the bridge to read APOGEE PXCs from a BACnet supervisor (Desigo CC, Niagara, EBI, etc.) on their own building network.
- A site integrator using it during a Siemens-to-BACnet migration.

The bridge speaks on two network surfaces — TCP/5033 (P2, outbound to PXCs it's configured to talk to) and UDP/47808 (BACnet/IP, inbound from the local BACnet broadcast domain). Both should be on operator-controlled VLANs.

## Reporting a vulnerability

If you find a security issue in the bridge code — a path that could trigger a P2 write opcode, a BACnet message that could crash the bridge, a way to make the bridge talk to an unintended P2 host, or a credential / identifier leak — please report it privately.

- **Contact:** jamesccupps@proton.me
- **Subject prefix:** `[P2_BACnet_Bridge SECURITY]`
- **Please include:** affected file/line, reproduction steps, bridge version (`p2_bridge.__version__`), bacpypes3 version, and whether you've shared the report with anyone else.

Do not file public GitHub issues for security reports.

## What is in scope

- Any code path in the bridge that could result in a P2 write being issued to a PXC. The bridge is read-only by design; if you find a way to trick it into writing, that's a defect.
- BACnet input handling — malformed frames that crash the bridge or its host.
- Bridge configuration that could cause it to connect to unintended P2 hosts (e.g. host-injection through the manifest).
- Credential/peer-list/state leaks from the bridge's log or BACnet object surface.

## What is out of scope

- Vulnerabilities in the Siemens APOGEE / Desigo stack — report those to [ProductCERT@siemens.com](mailto:ProductCERT@siemens.com).
- Issues in `bacpypes3` itself — report those to [the bacpypes3 maintainers](https://github.com/JoelBender/BACpypes3/issues).
- Issues in the P2 Scanner library itself (`p2_scanner.py` and its siblings in the repository root) — those affect the scanner, its GUI and `analyze_pcap.py` as well, so report them against the repository as a whole rather than as a bridge issue.

## Response

Acknowledgement target: 7 days. Triage and remediation timeline depends on severity and complexity. Credit in release notes is offered by default; opt out in your report if you'd prefer not to be named.
