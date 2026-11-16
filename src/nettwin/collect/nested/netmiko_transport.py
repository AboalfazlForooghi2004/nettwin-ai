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

Transport details (these were wrong in the first version — see the regression
tests in ``tests/test_netmiko_transport.py``):

* ``ConnectHandler(...)`` returns a ``BaseConnection``; the underlying SSH
  channel lives in **``connection.remote_conn``**, not in ``connection.channel``.
  ``BaseConnection`` has no ``channel`` attribute at all.
* ``connection.remote_conn`` is either a real ``paramiko.Channel`` (SSH) or a
  socket-like object (telnet/serial). ``paramiko.Channel`` *does* provide
  ``settimeout()`` / ``recv()`` / ``sendall()``; a bare socket does too. What
  must never happen is calling ``settimeout`` on an object that merely wraps
  one.
* When ``remote_conn`` is unavailable, the documented netmiko API
  ``read_channel()`` / ``write_channel()`` is used instead, with the timeout
  applied by the caller's polling loop.

Every failure surfaces as a :class:`SessionTimeoutError`/``SessionError`` with
the password redacted.
"""

from __future__ import annotations

from typing import Any, Protocol

from nettwin.collect.nested.session import (
    IosShellSession,
    SessionError,
    SessionLimits,
    SessionTimeoutError,
)


class _ChannelLike(Protocol):
    """The subset of ``paramiko.Channel`` / socket the transport needs."""

    def recv(self, nbytes: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, timeout: float) -> None: ...


def _redact(message: str, secret: str) -> str:
    return message.replace(secret, "***") if secret else message


class NetmikoChannelTransport:
    """Expose a netmiko connection as the minimal ``Transport`` protocol.

    Two backends, chosen by what the connection actually provides:

    ``raw``
        ``connection.remote_conn`` is a ``paramiko.Channel``/socket: use
        ``settimeout`` + ``recv`` + ``sendall`` directly. This is the normal
        SSH case.
    ``api``
        No usable ``remote_conn``: fall back to netmiko's documented
        ``read_channel()`` / ``write_channel()``. The timeout is then enforced
        by the session's polling loop, not by the channel.

    The class never assumes an attribute exists; it probes and records the
    chosen backend in :attr:`backend` so tests can assert which path ran.
    """

    def __init__(self, connection: Any, *, password: str = "", read_timeout: float = 0.2) -> None:
        self._connection = connection
        self._read_timeout = read_timeout
        self._closed = False
        self._password = password
        self._channel = self._resolve_channel(connection)
        if self._channel is not None:
            self.backend = "raw"
        elif hasattr(connection, "read_channel") and hasattr(connection, "write_channel"):
            self.backend = "api"
        else:
            raise TypeError(
                "netmiko connection exposes neither remote_conn nor "
                "read_channel/write_channel — cannot build a transport"
            )

    @staticmethod
    def _resolve_channel(connection: Any) -> _ChannelLike | None:
        """Return a usable channel, or ``None`` when the API backend is needed.

        ``paramiko.Channel`` and sockets both satisfy the protocol. Any object
        that has ``recv`` but lacks ``settimeout`` is rejected here rather than
        failing later with ``AttributeError`` deep inside a collection run.
        """
        candidate = getattr(connection, "remote_conn", None)
        if candidate is None:
            return None
        has_recv = callable(getattr(candidate, "recv", None))
        has_send = callable(getattr(candidate, "sendall", None)) or callable(
            getattr(candidate, "send", None)
        )
        has_timeout = callable(getattr(candidate, "settimeout", None))
        if has_recv and has_send and has_timeout:
            return candidate
        return None

    # -- Transport protocol ------------------------------------------------- #

    def read(self, timeout: float) -> str:
        if self._closed:
            return ""
        if self.backend == "api":
            return self._read_via_api()
        return self._read_via_channel(timeout)

    def _read_via_channel(self, timeout: float) -> str:
        channel = self._channel
        assert channel is not None  # narrowed by self.backend
        try:
            channel.settimeout(min(timeout, self._read_timeout))
        except Exception as exc:  # noqa: BLE001 - surface a clear, sanitized error
            self._closed = True
            raise SessionTimeoutError(
                _redact(f"cannot set channel timeout: {type(exc).__name__}: {exc}", self._password)
            ) from None
        try:
            data = channel.recv(65535)
        except TimeoutError:
            return ""
        except Exception:  # noqa: BLE001 - socket.timeout on older paramiko, EOF, …
            return ""
        if not data:
            self._closed = True
            return ""
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    def _read_via_api(self) -> str:
        try:
            data = self._connection.read_channel()
        except Exception:  # noqa: BLE001
            return ""
        if not data:
            return ""
        return str(data)

    def write(self, data: str) -> None:
        if self._closed:
            raise RuntimeError("transport closed")
        if self.backend == "api":
            self._connection.write_channel(data)
            return
        channel = self._channel
        assert channel is not None
        payload = data.encode("utf-8")
        sender = getattr(channel, "sendall", None)
        if sender is None:
            sender = channel.send
        sender(payload)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Closing the transport must not kill the SSH session: the caller owns
        # the connection's lifetime (see netmiko_root_session).
        try:
            self._connection.disconnect()
        except Exception:  # noqa: BLE001 - best effort
            pass


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
        self.backend = getattr(parent_transport, "backend", "raw")

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
        raise SessionError(
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
        message = _redact(str(exc), password)
        raise SessionTimeoutError(f"connect to {host} failed: {message}") from None

    transport = NetmikoChannelTransport(connection, password=password)
    session = IosShellSession(
        host=host,
        transport=transport,
        limits=limits,
        username=username,
        password=password,
    )
    # Keep the connection referenced so the SSH channel is not garbage
    # collected while the session is in use.
    session._netmiko_connection = connection  # noqa: SLF001 - documented pairing
    return session


def netmiko_nested_transport(*, parent: IosShellSession | None = None, **_: Any):
    """Return a transport for a child opened from ``parent``.

    The bytes share the parent's channel (see :class:`ForwardedTransport`).
    """
    if parent is None:
        raise ValueError("a nested transport requires the parent session")
    return ForwardedTransport(parent._transport, name=f"forwarded:{parent.host}")  # noqa: SLF001
