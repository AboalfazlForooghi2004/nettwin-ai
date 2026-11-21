"""Normalisation of raw Cisco IOS CLI text for *parsing*.

A terminal stream is not a clean document. IOS (and the transport in between)
emits cursor-motion controls that a terminal renders but a line-based parser
reads as ordinary characters:

* ``0x08`` (BS) — move the cursor one column left. IOS uses it for overstrike
  and, more importantly, for pagination redraws, which is how a live OSPF
  capture came back with
  ``\\x08\\x08\\x08…        \\x08\\x08\\x08…    Link connected to: …``
  in front of a link marker.
* ``0x0d`` (CR) — return the cursor to column zero.
* ``0x09`` (HT) — advance to the next multiple-of-8 tab stop.

**Backspace does not delete.** It only moves the cursor. The character under
the cursor survives until something overwrites it. So ``abc\\b`` renders as
``abc``, not ``ab``; ``abc\\b\\bX`` renders as ``aXc``, not ``aX``. Removing the
byte is therefore wrong in two different ways: it keeps text the terminal
erased *and* destroys text the terminal kept.

This module replays a real character buffer with a cursor — overwrite at the
cursor, append past the end — which reproduces exactly what the operator saw.
That rendered text is what the parser must interpret.

This is deliberately *pure text*, not OSPF: every parser consuming raw
transport text faces the same stream, so the renderer lives here and is applied
where text is turned into structure.

The raw text is never modified. ``raw_evidence.yaml`` records what the device
sent, verbatim, control characters included — an artefact that silently
laundered its own input could not be audited.
"""

from __future__ import annotations

import re

#: Control characters with cursor semantics we implement explicitly.
BS = "\x08"
HT = "\x09"
LF = "\n"
CR = "\r"

#: Terminal tab stop width (DEC/IOS standard).
TAB_WIDTH = 8

#: Zero-width noise that never renders and carries no cursor meaning.
_NOISE_RE = re.compile(r"[\x00\x07]")

#: C0 controls we have no safe, defined rendering for. Dropped *after* the
#: cursor pass, and deliberately excluded from BS/HT/CR/LF which are handled
#: above. ESC starts a CSI/OSC sequence; the consuming regexes for recognised
#: sequences run first, so anything left here is a stray control byte.
_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]"      # CSI: colours, cursor moves
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: titles, terminated by BEL or ST
    r"|[@-Z\\-_])"                     # other two-character escapes
)
_RESIDUAL_CONTROL_RE = re.compile(r"[\x01-\x06\x0b\x0c\x0e-\x1f\x7f]")


class _LineRenderer:
    """A single terminal line: a character buffer plus a cursor column.

    Characters overwrite the cell at the cursor, or extend the buffer when the
    cursor is past its end. Nothing is ever deleted except by overwriting.
    """

    __slots__ = ("_cells", "_cursor")

    def __init__(self) -> None:
        self._cells: list[str] = []
        self._cursor = 0

    def put(self, char: str) -> None:
        if self._cursor < len(self._cells):
            self._cells[self._cursor] = char
        else:
            # Cursor is past the end: the gap a cursor skip left behind is
            # blank, exactly as the terminal filled it with spaces.
            if self._cursor > len(self._cells):
                self._cells.extend(" " * (self._cursor - len(self._cells)))
            self._cells.append(char)
        self._cursor += 1

    def backspace(self) -> None:
        """Move left one column, bounded at column zero. Deletes nothing."""
        if self._cursor > 0:
            self._cursor -= 1

    def carriage_return(self) -> None:
        """Move to column zero. Deletes nothing."""
        self._cursor = 0

    def tab(self) -> None:
        """Advance to the next tab stop, blank-filling as the terminal does."""
        target = ((self._cursor // TAB_WIDTH) + 1) * TAB_WIDTH
        if target > len(self._cells):
            self._cells.extend(" " * (target - len(self._cells)))
        self._cursor = target

    def render(self) -> str:
        return "".join(self._cells)


def render_terminal_line(line: str) -> str:
    """Render one line through a character buffer and cursor.

    ``0x08`` moves left without deleting; ``0x0d`` returns to column zero
    without deleting; ``0x09`` advances to the next 8-column tab stop. Printable
    characters overwrite the cell at the cursor or extend the line.
    """
    if not any(ch in line for ch in (BS, HT, CR)):
        return line

    state = _LineRenderer()
    for char in line:
        if char == BS:
            state.backspace()
        elif char == CR:
            state.carriage_return()
        elif char == HT:
            state.tab()
        else:
            state.put(char)
    return state.render()


#: Backwards-compatible alias; the semantics are now a full line render.
collapse_terminal_overstrike = render_terminal_line


def normalise_cli_text(text: str) -> str:
    """Return a parse-ready copy of raw CLI output. The input is not modified.

    Order matters:

    1. Remove recognised ANSI escape sequences — they are instructions, not
       content, recognised by pattern rather than by deleting bytes that might
       be data. This runs first because an OSC sequence is terminated by BEL.
    2. Strip zero-width noise (NUL, BEL) left over — it never renders.
    3. Split on newlines, so cursor state cannot leak between lines. A CRLF
       pair is a line ending, not a redraw.
    4. Render each line through the cursor buffer.
    5. Drop any residual control byte with no defined rendering.

    Indentation is preserved: it is structural in IOS output, where an LSA body
    is indented under its header.
    """
    if not text:
        return ""
    # ANSI first: an OSC sequence is *terminated* by BEL, so stripping noise
    # first would remove the terminator and leave the payload behind.
    cleaned = _ANSI_RE.sub("", text)
    cleaned = _NOISE_RE.sub("", cleaned)
    # A CR immediately before LF is a line terminator, not a carriage return.
    cleaned = cleaned.replace("\r\n", "\n")
    lines = cleaned.split("\n")
    rendered = "\n".join(render_terminal_line(line) for line in lines)
    return _RESIDUAL_CONTROL_RE.sub("", rendered)


#: US spelling alias, for callers that prefer it.
normalize_cli_text = normalise_cli_text
