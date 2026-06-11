#!/usr/bin/env python3
"""One-command Aegis Foundry demo runner.

Runs the full nine-agent detection pipeline offline against the bundled
fixtures - zero credentials required. Thin wrapper around the real CLI
(``aegis_foundry.cli``); supports ``--auto-approve`` and ``--fp-budget``
passthrough for the judged demo.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aegis_foundry.cli import main  # noqa: E402


def run() -> int:
    """Parse demo flags, force mock mode by default, invoke the CLI."""
    parser = argparse.ArgumentParser(
        description="Run the Aegis Foundry demo pipeline (offline by default).")
    parser.add_argument("--auto-approve", action="store_true",
                        help="let the Governor auto-approve instead of prompting")
    parser.add_argument("--fp-budget", type=float, default=None,
                        help="max acceptable expected alerts/week per rule")
    args = parser.parse_args()

    mode = os.environ.get("AEGIS_MODE", "mock").strip().lower()
    if mode != "live":
        mode = "mock"
        print("Running in offline mock mode - set AEGIS_MODE=live for a real "
              "Splunk deployment")

    cli_args = ["run", "--mode", mode]
    if args.auto_approve:
        cli_args.append("--auto-approve")
    if args.fp_budget is not None:
        cli_args.extend(["--fp-budget", str(args.fp_budget)])
    return main(cli_args)


if __name__ == "__main__":
    sys.exit(run())
