#!/usr/bin/env python3
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Script to automatically generate documentation using inline shell commands.

This is a generic & repeatable way to insert generated/rendered content into
documentation files, which is used to populate files that are then checked
into the repository.

CMDGEN blocks are declared within a file as follows:

```
<!-- BEGIN CMDGEN util/selfdoc.py reggen -->
                  ^^^^^^^^^^^^^^^^^^^^^^ the command is specified here

[... generated content will appear here ...]

<!-- END CMDGEN -->
```
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Sequence

logger: logging.Logger = logging.getLogger(Path(__file__).stem)

LOG_FORMAT: str = "%(levelname)s [%(name)s]: %(message)s"
LOG_LEVELS: list[str] = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

REPO_ROOT: Path = Path(__file__).resolve().parents[1]

CMDGEN_BLOCK_RE: re.Pattern = re.compile(
    r"""
    (?P<start>^[ \t]*<!--\s*BEGIN\s+CMDGEN(?P<command>[^>]+)\s*-->[ \t]*$)  # Start marker
    (?P<content>[\s\S]*?)                                                # Generated content
    (?P<end>^[ \t]*<!--\s*END\s+CMDGEN\s*-->[ \t]*$)                     # End marker
    """,
    re.MULTILINE | re.VERBOSE,
)


def cmdgen_file(path: Path, *, dry_run: bool = False, update: bool = False) -> bool:
    """Find all CMDGEN blocks in a file and check their content is up-to-date.

    Find all CMDGEN blocks in a file and optionally replace their content
    with the result of running each specified shell command.

    Args:
        filepath: The path to the file to check.
        dry_run: Log commands instead of running them.
        update: Overwrite the file if the generated contents do not match.

    Returns:
        A boolean: true if there was a mismatch, false if not.
    """
    relative_path = path.relative_to(REPO_ROOT)
    content = path.read_text(encoding="utf-8", errors="backslashreplace")

    # Line number are 1-indexed. We keep track of the last result to
    # avoid quadratic O(nm) scanning of lines for multiple matches.
    prev_lineno, prev_index = 1, 0

    def transform(match: re.Match) -> str:
        """Regex substitution function for CMDGEN blocks."""
        # Determine which line we've matched on
        nonlocal prev_lineno, prev_index, content
        lineno = prev_lineno + content.count("\n", prev_index, match.start())
        prev_index = match.start()
        prev_lineno = lineno

        command = match.group("command").strip()
        if dry_run:
            logger.info("%s:%d: `%s`", relative_path, lineno, command)
            return match.group(0)
        else:
            logger.debug("%s:%d: `%s`", relative_path, lineno, command)

        # Run the command in a sub-shell
        res = subprocess.run(
            command,
            shell=True,
            text=True,
            encoding="utf-8",
            errors="backslashreplace",
            capture_output=True,
            cwd=REPO_ROOT,
            check=False,
        )
        if res.stderr:
            logger.warning(
                "%s:%d: `%s` output the following error messages:\n%s",
                relative_path,
                lineno,
                command,
                res.stderr,
            )
        if res.returncode != 0:
            logger.error(
                "%s:%d: `%s` had a non-zero return code of %d",
                relative_path,
                lineno,
                command,
                res.returncode,
            )
            return match.group(0)

        # Wrap the final result in the start and end markers and return it
        start, end = match.group("start"), match.group("end")
        return f"{start}\n{res.stdout}\n{end}"

    new_content = CMDGEN_BLOCK_RE.sub(transform, content)
    modified = new_content != content

    # Only update the file if it has been requested, and we actually made changes
    if modified and update:
        path.write_text(new_content, encoding="utf-8")

    return modified


def cmdgen_files(
    files: Sequence[Path], max_workers: int = 1, *, dry_run: bool = False, update: bool = False
) -> int:
    """Find CMDGEN blocks in a list of files, and check their contents are up-to-date.

    Uses a ThreadPool to process multiple files for CMDGEN blocks in parallel.
    Their contents are optionally replaced with the results of running the
    shell commands that they specify.

    Args:
        files: The list of paths to files to be processed.
        max_workers: The maximum number of threadpool workers. Set to 1 (default) for
          serial processing.
        dry_run: Log commands instead of running them.
        update: Overwrite the file if the generated contents do not match.

    Returns:
        The integer number of files that had content mismatches after CMDGEN.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(cmdgen_file, file, dry_run=dry_run, update=update) for file in files
        ]
        return sum(future.result() for future in as_completed(futures))


def main(argv: list[str] | None = None) -> int:
    """Either check or update all CMDGEN blocks found in the given files."""
    parser = argparse.ArgumentParser(
        prog="cmdgen", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "globs",
        nargs="+",
        type=str,
        metavar="file",
        help="File(s) to check with paths relative to the repository root. "
        "These can be given as glob patterns.",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        help="Log commands but do not execute them.",
        action="store_true",
    )
    parser.add_argument(
        "-u",
        "--update",
        help="Update any out-of-date content. If this is not set, any files "
        "that are out-of-date are treated as an error.",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        help="Number of parallel workers processing files. Set to 1 to execute "
        "sequentially, in case commands might conflict if run in parallel.",
    )
    parser.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        default="INFO",
        help="Set the log level (defaults to INFO).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level, stream=sys.stderr, format=LOG_FORMAT)

    if args.workers is not None and args.workers <= 0:
        logger.error("Cannot have %d workers: must have at least 1", args.workers)
        sys.exit(1)
    try:
        args.workers = len(os.sched_getaffinity(0))
    except (AttributeError, NotImplementedError, OSError):
        args.workers = os.cpu_count()
    if not args.workers:
        args.workers = 1

    start_time = time.perf_counter()
    files = [file for glob in args.globs for file in REPO_ROOT.glob(glob)]
    files_changed = cmdgen_files(
        files, max_workers=args.workers, dry_run=args.dry_run, update=args.update
    )
    execution_time = time.perf_counter() - start_time
    logger.info(
        "Processed %d files in %.2f seconds: %d %s modified",
        len(files),
        execution_time,
        files_changed,
        "were" if args.update else "would have been",
    )

    return 1 if files_changed and not args.update else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
