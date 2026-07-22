"""Vendor the normative Auditable MCP spec artifacts into this repository.

The JSON Schema (`schema/`) and golden conformance vectors (`vectors/`) have a single source of
truth in the separate `mcp-audit-extension` spec repository. This SDK is published standalone, so
those artifacts are vendored under `spec/` and this script keeps the copy honest.

Usage:
    python scripts/sync_spec.py            # copy source -> vendored spec/
    python scripts/sync_spec.py --check    # verify vendored == source (CI drift gate); no writes

The source location resolves in this order: `--source` argument, `AMCP_SPEC_SRC` environment
variable, then the default sibling checkout `../mcp-audit-extension/spec`.
"""

import argparse
import filecmp
import logging
import os
import shutil
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('sync_spec')

# Subdirectories of the spec that are normative and must be reproduced byte-for-byte.
VENDORED_SUBDIRS = ('schema', 'vectors')

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VENDORED_SPEC_DIR = _REPO_ROOT / 'spec'
_DEFAULT_SOURCE = _REPO_ROOT.parent / 'mcp-audit-extension' / 'spec'


def resolve_source(cli_source: str | None) -> Path:
    """Resolve the source spec directory from CLI arg, env var, then the default sibling checkout.

    Args:
        cli_source: The `--source` argument value, or None.

    Returns:
        The resolved absolute path to the source spec directory.

    Raises:
        FileNotFoundError: If the resolved directory does not exist.
    """
    raw = cli_source or os.environ.get('AMCP_SPEC_SRC') or str(_DEFAULT_SOURCE)
    source = Path(raw).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f'spec source directory not found: {source}')
        # end if
    return source
    # end def


def _iter_files(base: Path) -> list[Path]:
    """Return the sorted relative paths of every JSON file under the vendored subdirectories."""
    files: list[Path] = []
    for subdir in VENDORED_SUBDIRS:
        root = base / subdir
        if not root.is_dir():
            continue
            # end if
        for path in sorted(root.rglob('*.json')):
            files.append(path.relative_to(base))
            # end for
        # end for
    return sorted(files)
    # end def


def check(source: Path) -> bool:
    """Verify the vendored spec matches the source byte-for-byte.

    Args:
        source: The source spec directory.

    Returns:
        True if the vendored copy is in sync, False otherwise.
    """
    source_files = _iter_files(source)
    vendored_files = _iter_files(_VENDORED_SPEC_DIR)
    ok = True

    missing = set(source_files) - set(vendored_files)
    extra = set(vendored_files) - set(source_files)
    for rel in sorted(missing):
        logger.error('missing in vendored spec: %s', rel)
        ok = False
        # end for
    for rel in sorted(extra):
        logger.error('stale file in vendored spec (not in source): %s', rel)
        ok = False
        # end for

    for rel in sorted(set(source_files) & set(vendored_files)):
        if not filecmp.cmp(source / rel, _VENDORED_SPEC_DIR / rel, shallow=False):
            logger.error('content drift: %s', rel)
            ok = False
            # end if
        # end for

    if ok:
        logger.info('vendored spec is in sync (%d files)', len(source_files))
        # end if
    return ok
    # end def


def sync(source: Path) -> int:
    """Copy the normative subdirectories from source into the vendored spec directory.

    Args:
        source: The source spec directory.

    Returns:
        The number of files copied.
    """
    copied = 0
    for subdir in VENDORED_SUBDIRS:
        src_dir = source / subdir
        dst_dir = _VENDORED_SPEC_DIR / subdir
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
            # end if
        if not src_dir.is_dir():
            continue
            # end if
        for src_path in sorted(src_dir.rglob('*.json')):
            dst_path = dst_dir / src_path.relative_to(src_dir)
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst_path)
            copied += 1
            # end for
        # end for
    logger.info('vendored %d files from %s', copied, source)
    return copied
    # end def


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector for testing; defaults to sys.argv.

    Returns:
        A process exit code (0 on success, 1 on drift/failure).
    """
    parser = argparse.ArgumentParser(description='Vendor the normative Auditable MCP spec artifacts.')
    parser.add_argument('--check', action='store_true', help='verify sync without writing (CI gate)')
    parser.add_argument('--source', default=None, help='source spec directory (overrides AMCP_SPEC_SRC)')
    args = parser.parse_args(argv)

    source = resolve_source(args.source)
    if args.check:
        return 0 if check(source) else 1
        # end if
    sync(source)
    return 0
    # end def


if __name__ == '__main__':
    sys.exit(main())
    # end if
