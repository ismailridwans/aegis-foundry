#!/usr/bin/env python3
"""Package the Aegis Foundry Splunk app into ``dist/aegis_foundry.spl``.

A .spl file is a gzipped tarball whose single top-level directory is the app
id (``aegis_foundry/``). This script builds it with the standard-library
``tarfile`` module, excluding development artifacts (``__pycache__``,
``*.pyc``, editor swap files) and any ``local/`` directory (shipping local/
is an AppInspect failure), and normalizes ownership/permissions inside the
archive so the package is reproducible across machines.

Usage:
    python scripts/package_app.py

Prints the absolute path of the built .spl on success.
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "splunk_app" / "aegis_foundry"
DIST_DIR = REPO_ROOT / "dist"
APP_ID = "aegis_foundry"

EXCLUDED_DIRS = {"__pycache__", "local", ".git", ".svn"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".swp", ".swo", ".bak", ".orig")
EXCLUDED_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}


def _filter_member(info: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
    """Exclude dev artifacts and normalize archive metadata.

    Returns None to drop a member. Surviving members get root ownership and
    canonical modes (0755 for directories and bin/ scripts, 0644 otherwise)
    so the archive content does not depend on the packaging host.
    """
    parts = PurePosixPath(info.name).parts
    if any(part in EXCLUDED_DIRS for part in parts):
        return None
    basename = parts[-1] if parts else ""
    if basename in EXCLUDED_NAMES or basename.endswith(EXCLUDED_SUFFIXES):
        return None

    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if info.isdir():
        info.mode = 0o755
    elif len(parts) >= 2 and parts[1] == "bin":
        info.mode = 0o755  # alert action / scripted input entry points
    else:
        info.mode = 0o644
    return info


def build() -> Path:
    """Build dist/aegis_foundry.spl and return its absolute path."""
    if not APP_DIR.is_dir():
        raise FileNotFoundError(f"app directory not found: {APP_DIR}")
    required = APP_DIR / "default" / "app.conf"
    if not required.is_file():
        raise FileNotFoundError(f"missing {required}; refusing to package an invalid app")

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DIST_DIR / f"{APP_ID}.spl"
    if out_path.exists():
        out_path.unlink()

    with tarfile.open(out_path, "w:gz") as archive:
        archive.add(str(APP_DIR), arcname=APP_ID, filter=_filter_member)
    return out_path.resolve()


def main() -> int:
    try:
        out_path = build()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
