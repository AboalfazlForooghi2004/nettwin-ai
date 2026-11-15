"""NetTwin AI application entry point.

The MVP entry point only verifies that the application package is importable
and reports its version. Diagnostic and MCP functionality is added in later
tasks.
"""

from __future__ import annotations

import logging

from nettwin import __version__

logger = logging.getLogger("nettwin")


def main() -> int:
    """Run the NetTwin AI application entry point.

    Returns:
        Process exit code (0 on success).
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logger.info("NetTwin AI v%s starting", __version__)
    logger.info("Startup OK — package imports and entry point are healthy")
    print(f"NetTwin AI v{__version__} — startup OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
