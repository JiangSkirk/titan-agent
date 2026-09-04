"""Linux SO_PEERCRED must not be confused with Darwin LOCAL_PEERCRED."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from js.orind.daemon_net import peer_credentials


def test_linux_probe_does_not_use_darwin_local_peercred_constant() -> None:
    source = Path(__file__).resolve().parents[2] / "js/orind/daemon_net.py"
    linux_block = source.read_text(encoding="utf-8").split('system.startswith("linux")', 1)[1]
    linux_block = linux_block.split("return None", 1)[0]
    assert "SO_PEERCRED" in linux_block
    assert "getsockopt(socket.SOL_SOCKET, LOCAL_PEERCRED" not in linux_block


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="SO_PEERCRED is Linux-only")
def test_linux_so_peercred_roundtrip(tmp_path: Path) -> None:
    sock_path = tmp_path / "peercred.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(sock_path))
    peer, _addr = server.accept()
    try:
        creds = peer_credentials(peer)
        assert creds is not None
        euid, pid = creds
        assert euid == os.geteuid()
        assert pid == os.getpid()
    finally:
        peer.close()
        client.close()
        server.close()
