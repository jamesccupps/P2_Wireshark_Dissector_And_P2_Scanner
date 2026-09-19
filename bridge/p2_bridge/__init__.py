"""
p2_bridge — A P2-to-BACnet bridge built on the P2 Scanner library.

Reads APOGEE PXC controllers over P2 (TCP/5033), exposes every point as a
BACnet/IP object so any BACnet supervisor (Desigo CC, Niagara, EBI, ENTELI-NET,
etc.) can read them as native BACnet.

Read-only by design — matches the safety stance of the underlying P2 Scanner.
"""

__version__ = "0.4.0"
