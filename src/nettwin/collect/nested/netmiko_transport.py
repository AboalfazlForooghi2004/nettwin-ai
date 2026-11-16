"""Production transports for nested IOS sessions (Phase 2.3).

Two factories, both lazy-importing netmiko so the core install stays free of
SSH libraries:

``netmiko_root_session(host, username, password, ...)``
    Workstation -> seed device, a plain netmiko ``ConnectHandler``.

``netmiko_nested_transport(parent=...)``
    Neighbour reached **through** the seed. The bytes are forwarded over the
    parent's already-open SSH channel by ``ssh -l user <ip>`` typed on the
    device itself — the exact path the lab uses
    (``Ubuntu -> R2-1 -> R2-2 -> R2-4``). No ProxyJump, no second local
    socket: the child conversation travels inside the parent's session.

Why a forwarding transport rather than a fresh socket: R2-2/R2-4 are only
reachable *from inside* the lab. A local ``ConnectHandler`` would need a route
the workstation does not have.

The class is deliberately small — it only moves bytes. All prompt logic lives
in :mod:`nettwin.collect.nested.session`, which is fully testable offline.
"""

from __future__ import annotations

from typing import Any

from nettwin.collect.nested.session import (
    IosShellSession,
    SessionLimits,
    SessionTimeoutError,
)


class NetmikoChannelTransport:
    """Expose a netmiko channel as the minimal ``Transport`` protocol."""

    def __init__(self, channel: Any, *, read_timeout: float = 0.2) -> None:
        self._channel = channel
        self._read_timeout = read_timeout
        self._closed = False

    def read(self, timeout: float) -> str:
        if self._closed:
            return ""
        self._channel.settimeout(min(timeout, self._read_timeout))
        try:
            data = self._channel.recv(65535)
        except TimeoutError:
            return ""
        except Exception:  # noqa: BLE001 - channel errors surface as EOF
            self._closed = True
            return ""
        if not data:
            self._closed = True
            return ""
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    def write(self, data: str) -> None:
        if self._closed:
            raise RuntimeError("transport closed")
        self._channel.sendall(data.encode("utf-8"))

    def close(self) -> None:
        self._closed = True


class ForwardedTransport:
    """A nested device's channel, multiplexed over the parent's session.

    IOS multiplexes the nested ssh inside the parent's terminal, so the child
    transport reads from, and writes to, the *same* channel as the parent. The
    session layer distinguishes them by which prompt it is waiting for
    (password prompt vs. the child's hostname prompt), which is why the parent
    must not be used concurrently — Phase 2.3 walks breadth-first for exactly
    this reason.
    """

    def __init__(self, parent_transport: Any, *, name: str = "forwarded") -> None:
        self._parent = parent_transport
        self.name = name
        self._closed = False

    def read(self, timeout: float) -> str:
        if self._closed:
            return ""
        return self._parent.read(timeout)

    def write(self, data: str) -> None:
        if self._closed:
            raise RuntimeError(f"{self.name}: transport closed")
        self._parent.write(data)

    def close(self) -> None:
        # Closing a forwarded channel must NOT close the parent's SSH session;
        # only the child's terminal stream ends.
        self._closed = True


def netmiko_root_session(
    host: str,
    password: str,
    *,
    username: str,
    port: int = 22,
    limits: SessionLimits | None = None,
) -> IosShellSession:
    """Open the workstation -> seed session with netmiko."""
    try:
        from netmiko import ConnectHandler  # noqa: PLC0415 - optional dependency
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise SessionTimeoutError(
            "netmiko is not installed; install the optional extra: "
            'pip install -e ".[collect]"'
        ) from exc

    limits = limits or SessionLimits()
    try:
        connection = ConnectHandler(
            device_type="cisco_ios",
            host=host,
            username=username,
            password=password,
            port=port,
            conn_timeout=int(limits.connect_timeout),
            fast_cli=False,
        )
    except Exception as exc:  # netmiko raises a family of socket/auth errors
        # Never include the password in the message.
        message = str(exc).replace(password, "***") if password else str(exc)
        raise SessionTimeoutError(f"connect to {host} failed: {message}") from None

    transport = NetmikoChannelTransport(connection.channel)
    session = IosShellSession(
        host=host,
        transport=transport,
        limits=limits,
        username=username,
        password=password,
    )
    # The connection object must stay referenced so the SSH channel is not
    # garbage-collected while the session is in use.
    session._netmiko_connection = connection  # noqa: SLF001 - documented pairing
    return session


def netmiko_nested_transport(*, parent: IosShellSession | None = None, **_: Any):
    """Return a transport for a child opened from ``parent``.

    The bytes share the parent's channel (see :class:`ForwardedTransport`).
    """
    if parent is None:
        raise ValueError("a nested transport requires the parent session")
    return ForwardedTransport(parent._transport, name=f"forwarded:{parent.host}")  # noqa: SLF001
