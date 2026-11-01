from types import SimpleNamespace as NS

import pytest

from openhdb import cli, client
from openhdb.usb import TransportError


def interface(subclass, serial="test", address=1):
    return NS(intf=NS(bInterfaceSubClass=subclass),
              device=NS(serial_number=serial, bus=1, address=address))


def test_hdb_default_never_falls_back_to_adb(monkeypatch):
    monkeypatch.setattr(client, "find_interfaces", lambda: [interface(0x42)])
    with pytest.raises(TransportError, match="HDB"):
        client.connect()


def test_serial_selects_physical_device(monkeypatch):
    a, b = interface(0x48, "a", 1), interface(0x48, "b", 2)
    monkeypatch.setattr(client, "find_interfaces", lambda: [a, b])
    assert client._candidates(serial="b") == [b]
    with pytest.raises(TransportError, match="mais de um"):
        client.connect()


def test_connect_claim_error_cleanup_and_no_fallback(monkeypatch):
    closed = []
    selected = []
    class BrokenUsb:
        def __init__(self, intf):
            selected.append(intf)
        def open(self):
            raise TransportError("HDB busy")
        def close(self):
            closed.append(True)
    hdb, adb = interface(0x48), interface(0x42)
    monkeypatch.setattr(client, "find_interfaces", lambda: [adb, hdb])
    monkeypatch.setattr(client, "UsbTransport", BrokenUsb)
    with pytest.raises(TransportError, match="HDB busy"):
        client.connect(kind="auto")
    assert selected == [hdb] and closed == [True]


def test_probe_passive_does_not_open_usb(monkeypatch):
    monkeypatch.setattr(client, "find_interfaces", lambda: [interface(0x48)])
    monkeypatch.setattr(client, "UsbTransport", lambda *a, **kw: pytest.fail("passive probe opened USB"))
    results = client.probe()
    assert len(results) == 1 and results[0].banner is None


def test_no_approval_by_adb():
    with pytest.raises(ValueError, match="removida"):
        client.connect(approve=True)


@pytest.mark.parametrize("args", [
    ["--kind", "hdb", "-s", "x", "banner"],
    ["banner", "--kind", "hdb", "-s", "x"],
])
def test_cli_options_before_or_after_command(monkeypatch, args):
    seen = []
    monkeypatch.setattr(cli, "cmd_device", lambda a: seen.append(a) or 0)
    assert cli.main(args) == 0
    assert seen[0].kind == "hdb" and seen[0].serial == "x"


@pytest.mark.parametrize("args", [["pull", "/x", "local"], ["push", "local", "/x"]])
def test_cli_file_commands_and_hdb_default(monkeypatch, args):
    seen = []
    monkeypatch.setattr(cli, "cmd_device", lambda a: seen.append(a) or 0)
    assert cli.main(args) == 0
    assert seen[0].kind == "hdb"


def test_cli_blocks_adb_auto_approval():
    with pytest.raises(SystemExit) as exc:
        cli.main(["banner", "--auto-approve"])
    assert exc.value.code == 2


def test_cli_error_is_nonzero_without_traceback(monkeypatch, capsys):
    def fail(args):
        raise TransportError("HDB AUTHENTICEXABORT")
    monkeypatch.setattr(cli, "cmd_device", fail)
    assert cli.main(["shell", "id"]) == 1
    err = capsys.readouterr().err
    assert "AUTHENTICEXABORT" in err and "Traceback" not in err
