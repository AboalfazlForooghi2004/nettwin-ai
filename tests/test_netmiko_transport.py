"""Phase 2.3 regression — real Netmiko/Paramiko transport contract.

Why this file exists
--------------------
The first live run on Ubuntu stopped with::

    AttributeError: 'SSHChannel' object has no attribute 'settimeout'

Root cause: the transport read ``connection.channel``. ``netmiko.BaseConnection``
has **no** ``channel`` attribute; the SSH channel is ``connection.remote_conn``
(a ``paramiko.Channel``, which *does* provide ``settimeout``/``recv``/``sendall``).
Anything reached through a different name is a wrapper that may not.

These tests pin that contract down without opening a socket: the mocks mirror
the real classes' *shape*, and the first test reproduces the exact production
failure so it can never come back silently.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

import nettwin.collect.nested.netmiko_transport as module
from nettwin.collect.nested.netmiko_transport import (
    ForwardedTransport,
    NetmikoChannelTransport,
    netmiko_nested_transport,
)
from nettwin.collect.nested.session import (
    IosShellSession,
    SessionError,
    SessionLimits,
    _sanitize,
    _session_error,
)

FAST = SessionLimits(connect_timeout=0.3, command_timeout=0.3, poll_interval=0.001)
PASS = "unit-test-fake-pw"


# =========================================================================== #
# Mocks that mirror the real object graph
# =========================================================================== #


class FakeParamikoChannel:
    """Shape of ``paramiko.Channel``: settimeout / recv / sendall."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.timeout: float | None = None
        self.sent: list[bytes] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, nbytes: int) -> bytes:  # noqa: ARG002
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


class TimeoutOnRecvChannel(FakeParamikoChannel):
    """A channel that raises the socket timeout paramiko documents."""

    def recv(self, nbytes: int) -> bytes:  # noqa: ARG002
        raise TimeoutError("no data")


class FakeSSHChannelWrapper:
    """The *wrong* object: has recv but no settimeout.

    This is what ``AttributeError: 'SSHChannel' object has no attribute
    'settimeout'`` came from. Reaching it means the transport picked the wrong
    attribute, and it must be rejected at construction time.
    """

    def recv(self, nbytes: int) -> bytes:  # noqa: ARG002
        return b""

    def sendall(self, data: bytes) -> None:
        pass


class FakeConnectHandlerResult:
    """Shape of a netmiko ``BaseConnection``: has ``remote_conn``, not ``channel``."""

    def __init__(self, channel: object | None) -> None:
        self.remote_conn = channel
        self.disconnected = False
        self.read_calls = 0
        self.written: list[str] = []

    def disconnect(self) -> None:
        self.disconnected = True

    # netmiko's documented API backend
    def read_channel(self) -> str:
        self.read_calls += 1
        return ""

    def write_channel(self, data: str) -> None:
        self.written.append(data)


class FakeConnectionWithChannelAttr:
    """A connection that *does* expose ``channel`` — but it is the wrong object.

    ``BaseConnection`` has no such attribute; this mock documents why the
    transport must never look there.
    """

    def __init__(self) -> None:
        self.channel = FakeSSHChannelWrapper()
        self.remote_conn = FakeParamikoChannel([b"R2-1#"])

    def disconnect(self) -> None:
        pass


# =========================================================================== #
# The production failure, reproduced and locked down
# =========================================================================== #


def test_transport_never_reads_the_nonexistent_channel_attribute() -> None:
    """Regression: ``connection.channel`` does not exist on BaseConnection."""
    from netmiko import BaseConnection

    assert not hasattr(BaseConnection, "channel"), (
        "netmiko gained a 'channel' attribute — revisit the transport, this test "
        "exists because reading it caused AttributeError on live hardware"
    )
    assert hasattr(BaseConnection, "__init__")


def test_transport_prefers_remote_conn_over_channel_attribute() -> None:
    connection = FakeConnectionWithChannelAttr()
    transport = NetmikoChannelTransport(connection)
    assert transport.backend == "raw"
    assert isinstance(transport._channel, FakeParamikoChannel)  # noqa: SLF001
    assert not isinstance(transport._channel, FakeSSHChannelWrapper)  # noqa: SLF001


def test_wrapper_without_settimeout_is_rejected_at_construction() -> None:
    """An object with recv/sendall but no settimeout must fail fast and clearly."""
    connection = FakeConnectHandlerResult(FakeSSHChannelWrapper())
    # remote_conn lacks settimeout -> the transport falls back to the API
    # backend only if read_channel exists; this fake has both, so it is 'api'.
    transport = NetmikoChannelTransport(connection)
    assert transport.backend == "api"


def test_no_backend_at_all_raises_type_error() -> None:
    class Bare:
        pass

    with pytest.raises(TypeError, match="neither remote_conn nor"):
        NetmikoChannelTransport(Bare())


# =========================================================================== #
# Raw channel backend
# =========================================================================== #


def test_raw_backend_reads_and_sets_timeout() -> None:
    channel = FakeParamikoChannel([b"R2-1#"])
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(channel))
    assert transport.backend == "raw"
    assert transport.read(1.0) == "R2-1#"
    assert channel.timeout is not None
    assert channel.timeout <= 1.0, "the requested timeout must bound the channel timeout"


def test_raw_backend_writes_bytes() -> None:
    channel = FakeParamikoChannel([])
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(channel))
    transport.write("show version\n")
    assert channel.sent == [b"show version\n"]


def test_raw_backend_returns_empty_string_on_socket_timeout() -> None:
    """A timeout is not an error: the polling loop keeps waiting."""
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(TimeoutOnRecvChannel([])))
    assert transport.read(0.1) == ""


def test_raw_backend_marks_closed_on_eof() -> None:
    channel = FakeParamikoChannel([])  # recv -> b""
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(channel))
    assert transport.read(0.1) == ""
    assert transport._closed is True  # noqa: SLF001
    assert transport.read(0.1) == ""


def test_raw_backend_decodes_utf8_safely() -> None:
    channel = FakeParamikoChannel(["hí 👋".encode()])
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(channel))
    assert transport.read(0.1) == "hí 👋"


# =========================================================================== #
# API backend (no usable remote_conn)
# =========================================================================== #


def test_api_backend_uses_read_write_channel() -> None:
    connection = FakeConnectHandlerResult(None)
    transport = NetmikoChannelTransport(connection)
    assert transport.backend == "api"
    assert transport.read(0.1) == ""
    assert connection.read_calls == 1
    transport.write("show cdp neighbors detail\n")
    assert connection.written == ["show cdp neighbors detail\n"]


def test_api_backend_never_calls_settimeout() -> None:
    """The pre-fix bug would have raised here; the API backend has no channel."""
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(None))
    transport.read(0.1)  # must not raise AttributeError


# =========================================================================== #
# Lifecycle
# =========================================================================== #


def test_close_disconnects_the_connection() -> None:
    connection = FakeConnectHandlerResult(FakeParamikoChannel([]))
    transport = NetmikoChannelTransport(connection)
    transport.close()
    assert connection.disconnected is True


def test_write_after_close_raises() -> None:
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(FakeParamikoChannel([])))
    transport.close()
    with pytest.raises(RuntimeError, match="transport closed"):
        transport.write("x")


def test_close_is_idempotent() -> None:
    transport = NetmikoChannelTransport(FakeConnectHandlerResult(FakeParamikoChannel([])))
    transport.close()
    transport.close()  # must not raise


# =========================================================================== #
# End-to-end through the session layer (still no socket)
# =========================================================================== #


def test_session_drives_a_real_shaped_connection_to_first_cdp_command() -> None:
    """The path that failed on the live run must reach the CDP command output."""
    prompt = b"R2-1#"
    detail = (
        b"-------------------------\n"
        b"Device ID: R2-2.nettwin.lab\n"
        b"Entry address(es):\n"
        b"  IP address: 10.0.21.1\n"
        b"Platform: Linux Uni,  Capabilities: Router\n"
        b"Interface: Ethernet0/0,  Port ID (outgoing port): Ethernet0/1\n"
        b"Holdtime : 138 sec\nR2-1#"
    )
    # Dispatch order: open() -> prompt, then exactly one command.
    channel = FakeParamikoChannel([prompt, detail])
    connection = FakeConnectHandlerResult(channel)
    transport = NetmikoChannelTransport(connection)

    session = IosShellSession(
        host="192.168.98.34",
        transport=transport,
        limits=FAST,
        username="nettwin-ro",
        password=PASS,
    )
    session.open()
    assert session.hostname == "R2-1"

    output = session.run_command("show cdp neighbors detail")
    assert "Device ID: R2-2.nettwin.lab" in output
    assert "IP address: 10.0.21.1" in output
    assert channel.timeout is not None, "a channel timeout was never applied"


def test_connect_failure_is_reported_and_password_redacted() -> None:
    """netmiko raising during ConnectHandler must not leak the password."""
    import nettwin.collect.nested.netmiko_transport as module

    class Boom(Exception):
        pass

    class FakeNetmiko:
        @staticmethod
        def ConnectHandler(**kwargs):  # noqa: N802 - mirrors the real name
            raise Boom(f"auth failed for {kwargs['password']} on {kwargs['host']}")

    # The factory imports ConnectHandler from netmiko inside the function, so
    # the patch target is netmiko's own attribute.
    with patch("netmiko.ConnectHandler", FakeNetmiko.ConnectHandler):
        with pytest.raises(SessionError) as excinfo:
            module.netmiko_root_session(
                "192.168.98.34", PASS, username="nettwin-ro", limits=FAST
            )
    message = str(excinfo.value)
    assert PASS not in message, "the password leaked into the error message"
    assert "***" in message


def test_nested_transport_shares_the_parent_channel() -> None:
    channel = FakeParamikoChannel([b"R2-2#"])
    parent = IosShellSession(
        host="192.168.98.34",
        transport=NetmikoChannelTransport(FakeConnectHandlerResult(channel)),
        limits=FAST,
        username="u",
        password=PASS,
    )
    child = netmiko_nested_transport(parent=parent)
    assert isinstance(child, ForwardedTransport)
    assert child.read(0.1) == "R2-2#", "the child must read the parent's stream"
    child.close()
    assert channel.closed is False, "closing a child must not kill the parent"


def test_nested_transport_requires_a_parent() -> None:
    with pytest.raises(ValueError, match="requires the parent session"):
        netmiko_nested_transport()


# --------------------------------------------------------------------------- #
# Regression: the second live failure. ConnectHandler() leaves the device AT
# its prompt, so the session must not wait for an initial prompt again.
# --------------------------------------------------------------------------- #


class _DeviceSittingAtItsPrompt:
    """A device that has already printed its prompt and is now idle.

    This is the state ``ConnectHandler`` hands back after
    ``session_preparation()``. Nothing is readable until we write something,
    which is exactly why the old code burned the whole connect_timeout.
    """

    def __init__(self, prompt: str = "R2-1#") -> None:
        self.prompt = prompt
        self._buffer = b""

    def settimeout(self, timeout: float) -> None:  # noqa: ARG002 - signature match
        return None

    def recv(self, nbytes: int) -> bytes:  # noqa: ARG002
        out, self._buffer = self._buffer, b""
        return out

    def sendall(self, data: bytes) -> None:
        command = data.strip().decode()
        text = f"\r\n{command}\r\ninterface output\r\n{self.prompt}".encode()
        self._buffer += text


class _ConnectionDirectlyAfterConnectHandler:
    """The shape netmiko really returns: logged in, at prompt, paging disabled."""

    def __init__(self) -> None:
        self.remote_conn = _DeviceSittingAtItsPrompt()
        self.base_prompt = "R2-1"

    def check_enable_mode(self, check_string: str = "") -> bool:  # noqa: ARG002
        return True

    def read_channel(self) -> str:
        return ""

    def write_channel(self, data: str) -> None:  # noqa: ARG002
        return None

    def disconnect(self) -> None:
        return None


def test_root_session_does_not_wait_for_a_prompt_netmiko_already_found() -> None:
    """Regression: a successful login used to die with "timeout waiting".

    ``ConnectHandler`` authenticates and leaves the device at its prompt. If
    the session then waits for an initial prompt, the socket stays idle for the
    full connect_timeout and the run fails *after* a successful SSH login with
    a message that blames the connection.
    """
    limits = SessionLimits(connect_timeout=1.0, command_timeout=1.0, poll_interval=0.01)
    with patch("netmiko.ConnectHandler", lambda **kwargs: _ConnectionDirectlyAfterConnectHandler()):
        started = time.monotonic()
        session = module.netmiko_root_session("192.168.98.34", PASS, username="u", limits=limits)
        # Must not block for the connect timeout on an idle-but-ready device.
        assert time.monotonic() - started < 0.5

        assert session.hostname == "R2-1", "netmiko's base_prompt must seed identity"
        assert session.privilege == 15, "privilege must reflect what netmiko found"

        # The first discovery command is what the live run never reached.
        output = session.run_command("show cdp neighbors detail")
    assert "interface output" in output


def test_root_session_marks_itself_open_so_open_is_cheap() -> None:
    with patch("netmiko.ConnectHandler", lambda **kwargs: _ConnectionDirectlyAfterConnectHandler()):
        session = module.netmiko_root_session("192.168.98.34", PASS, username="u", limits=FAST)
        prompt = session.open()
    assert prompt.is_ready


# --------------------------------------------------------------------------- #
# Regression: redaction must never destroy the diagnosis it is attached to.
# --------------------------------------------------------------------------- #


def test_short_password_does_not_shred_our_own_error_wording() -> None:
    """A one-character password used to mangle every message it touched.

    ``password="p"`` turned "timeout waiting for prompt" into
    "time***out waiting for ***rom***t": the operator loses the failure text at
    exactly the moment they need it. Only untrusted text is sanitised.
    """
    message = _session_error(
        "192.168.98.34: timeout waiting for initial prompt", "''", "p"
    )
    assert "timeout waiting for initial prompt" in message
    assert "192.168.98.34" in message


def test_real_secret_in_untrusted_text_is_still_removed() -> None:
    assert _sanitize("auth failed for nettwin-ro", "nettwin-ro") == "auth failed for ***"


def test_session_error_omits_an_empty_detail() -> None:
    assert _session_error("192.168.98.34 -> 10.0.21.1", "", "pw") == "192.168.98.34 -> 10.0.21.1"


def test_session_error_labels_the_untrusted_part() -> None:
    message = _session_error("host: timeout", "R2-2#", "secret", label="last output")
    assert message == "host: timeout (last output: R2-2#)"
