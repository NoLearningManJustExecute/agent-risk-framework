"""Test-wide guarantees: no network, repo-relative paths available.

The network guard is installed in `pytest_configure`, before collection, so even
import-time code in test modules is covered. It blocks:

- outbound `connect` / `connect_ex` / `sendto` on Python-level sockets, including
  loopback, so no test can reach a local Ollama server by accident;
- DNS lookups (`getaddrinfo`) for anything but loopback names.

`socket.socketpair()` stays usable: on Windows it is built from a loopback
connect, and asyncio's event loop needs it. Best-effort scope: sockets created
directly through the C `_socket` module and child processes are not covered.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LOOPBACK_NAMES = frozenset({None, "localhost", "127.0.0.1", "::1", b"localhost"})

_real = {
    "connect": socket.socket.connect,
    "connect_ex": socket.socket.connect_ex,
    "sendto": socket.socket.sendto,
    "getaddrinfo": socket.getaddrinfo,
    "socketpair": socket.socketpair,
}
_state = threading.local()


class NetworkBlockedError(OSError):
    """An OSError, so socket helpers clean up exactly as on a refused connection."""


def _allowed() -> bool:
    return getattr(_state, "in_socketpair", False)


def _guard(name: str):  # type: ignore[no-untyped-def]
    real = _real[name]

    def guarded(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if _allowed() or self.family == getattr(socket, "AF_UNIX", object()):
            return real(self, *args, **kwargs)
        raise NetworkBlockedError(f"socket.{name} is disabled in tests")

    guarded.__name__ = f"blocked_{name}"
    return guarded


def _guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
    if host in LOOPBACK_NAMES:
        return _real["getaddrinfo"](host, *args, **kwargs)
    raise NetworkBlockedError(f"DNS lookup of {host!r} is disabled in tests")


def _guarded_socketpair(*args, **kwargs):  # type: ignore[no-untyped-def]
    _state.in_socketpair = True
    try:
        return _real["socketpair"](*args, **kwargs)
    finally:
        _state.in_socketpair = False


def pytest_configure(config: pytest.Config) -> None:
    socket.socket.connect = _guard("connect")  # type: ignore[method-assign]
    socket.socket.connect_ex = _guard("connect_ex")  # type: ignore[method-assign]
    socket.socket.sendto = _guard("sendto")  # type: ignore[method-assign]
    socket.getaddrinfo = _guarded_getaddrinfo
    socket.socketpair = _guarded_socketpair


def pytest_unconfigure(config: pytest.Config) -> None:
    socket.socket.connect = _real["connect"]  # type: ignore[method-assign]
    socket.socket.connect_ex = _real["connect_ex"]  # type: ignore[method-assign]
    socket.socket.sendto = _real["sendto"]  # type: ignore[method-assign]
    socket.getaddrinfo = _real["getaddrinfo"]
    socket.socketpair = _real["socketpair"]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT
