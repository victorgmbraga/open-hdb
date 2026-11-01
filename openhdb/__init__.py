"""open-hdb: cliente HDB (Huawei Device/Data Bridge) aberto."""

from .client import Hdb, ProbeResult, connect, probe
from .protocol import Message, parse_banner
from .transport import HdbConnection, Stream
from .usb import Interface, TransportError, UsbTransport, find_interfaces

__version__ = "0.1.0"
__all__ = [
    "Hdb", "ProbeResult", "connect", "probe", "Message", "parse_banner",
    "HdbConnection", "Stream", "Interface", "TransportError", "UsbTransport",
    "find_interfaces", "__version__",
]
