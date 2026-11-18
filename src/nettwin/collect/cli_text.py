"""Normalisation of raw Cisco IOS CLI text for *parsing*.

A terminal stream is not a clean document. IOS (and the transport in between)
emits cursor-motion controls that a terminal renders but a line-based parser
reads as ordinary characters:

* ``0x08`` (BS) — move the cursor back one column, *erasing* whatever was
  there. IOS uses it for overstrike and, more importantly, pagination
  redraws, which is how a live OSPF capture came back with
  ``\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08        \\x08…    Link connected to: …``
  in front of a link marker.
* ``0x0d`` (CR) — return to column zero and overwrite the line.
* ``0x07`` (BEL), ``0x00`` (NUL) — noise with no rendering effect.

**Backspace is not deletion of a character in the text; it is cursor motion.**
Stripping the bytes with ``str.replace`` would leave the erased characters
behind — turning ``L\\x08Li\\x08i\\x08n\\x08n\\x08k`` into ``LLiinnkk`` instead of
``Link``. The collapse below replays the cursor: each ``0x08`` removes the
character before it, which is what the terminal did.

This module is deliberately *pure text*, not OSPF. Other CLI parsers in this
package face the same transport, so the function lives here and is applied
where text is turned into structure.

The raw text is never modified. ``raw_evidence.yaml`` records what the device
sent, verbatim, including the control characters — an artefact that silently
laundered its own input could not be audited.
"""

from __future__ import annotations

import re

#: Control characters that only move the cursor and never appear as glyphs.
_BS = "\x08"
_CR = "\r"

#: Zero-width noise that carries no rendering effect at all.
_NOISE_RE = re.compile(r"[\x00\x07]")

#: Any remaining C0 control character except tab and newline. Kept out of the
#: parse stream so a stray one cannot split a token.
_OTHER_CONTROL_RE = re.compile(r"[\x01-\x06\x0b\x0c\x0e-\x1f\x7f]")


def collapse_terminal_overstrike(line: str) -> str:
    """Apply terminal backspace/CR semantics to a single line.

    ``0x08`` erases the character before it; ``0x0d`` returns to column zero.
    Both are *rendering* operations, so replaying them reproduces exactly what
    the operator saw on screen — which is the text the parser must interpret.

    Characters surviving an erase attempt at column zero are dropped, matching
    a real terminal (there is nothing to erase).
    """
    if _BS not in line and _CR not in line:
        return line

    out: list[str] = []
    for char in line:
        if char == _BS:
            if out:
                out.pop()
        elif char == _CR:
            out.clear()
        else:
            out.append(char)
    return "".join(out)


def normalise_cli_text(text: str) -> str:
    """Return a parse-ready copy of raw CLI output. The input is not modified.

    Line endings are preserved as ``\\n``; only cursor-motion controls and
    zero-width noise are resolved. Whitespace is otherwise left alone, because
    indentation is meaningful in IOS output (an LSA body is indented under its
    header).
    """
    if not text:
        return ""
    cleaned = _NOISE_RE.sub("", text)
    # Work line by line: overstrike resolution is per line by definition.
    lines = cleaned.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    resolved = [collapse_terminal_overstrike(line) for line in lines]
    joined = "\n".join(resolved)
    return _OTHER_CONTROL_RE.sub("", joined)


#: Backwards-compatible alias used by parsers.
normalize_cli_text = normalise_cli_text
