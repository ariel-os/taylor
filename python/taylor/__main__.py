"""Entry point for the ``taylor`` command and ``python -m taylor``."""

import signal
import sys

from . import _taylor


def main() -> None:
    # Python's default SIGINT handler can't interrupt the Rust call, so let Ctrl+C kill it.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    # A fixed program name keeps clap's usage and error messages independent of how it was run.
    sys.exit(_taylor.run_cli(["taylor", *sys.argv[1:]]))


if __name__ == "__main__":
    main()
