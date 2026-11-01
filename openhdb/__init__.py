"""open-hdb: cliente USB experimental para Huawei Debug Bridge."""

from .client import Hdb, ProbeResult, connect, probe
from .protocol import Message, parse_banner
from .transport import HdbConnection, ServiceAuthRequired, Stream
from .usb import Interface, TransportError, TransportTimeout, UsbTransport, find_interfaces

__version__ = "0.2.0"
__all__ = [
    "Hdb", "ProbeResult", "connect", "probe", "Message", "parse_banner",
    "HdbConnection", "Stream", "Interface", "TransportError", "UsbTransport",
    "find_interfaces", "ServiceAuthRequired", "TransportTimeout", "__version__",
]
