"""
Simple Windows File System Monitoring tool for Malware Analysis

Monitors file creation, modification, and deletion events along with hashes.
Automatically requests Administrator privileges if not elevated.
"""

import argparse
import ctypes
import fnmatch
import hashlib
import logging
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


HASH_DELAY_SECONDS = 1.0


def is_running_as_admin() -> bool:
    """
    Check if the script is running with Administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except OSError:
        return False


def relaunch_as_admin():
    """
    Relaunch the current script with Administrator privileges.
    """
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )
    sys.exit(0)


def compute_sha256(file_path: Path) -> Optional[str]:
    """
    Compute SHA-256 hash of a file.

    Returns None if file cannot be read.
    """
    try:
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


class ExclusionRules:
    def __init__(
        self,
        exclude_paths: List[str],
        exclude_wildcards: List[str],
        exclude_extensions: List[str],
    ):
        self.exclude_paths = [Path(p).resolve() for p in exclude_paths]
        self.exclude_wildcards = exclude_wildcards
        self.exclude_extensions = [ext.lower() for ext in exclude_extensions]

    def is_excluded(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return True

        for base in self.exclude_paths:
            if resolved.is_relative_to(base):
                return True

        for pattern in self.exclude_wildcards:
            if fnmatch.fnmatch(str(resolved), pattern):
                return True

        if resolved.suffix.lower() in self.exclude_extensions:
            return True

        return False


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, exclusions: ExclusionRules):
        self.exclusions = exclusions

    def on_created(self, event):
        if event.is_directory:
            return
        self._log_event("CREATED", Path(event.src_path), hash_file=False)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._log_event("MODIFIED", Path(event.src_path), hash_file=True)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._log_event("DELETED", Path(event.src_path), hash_file=False)

    def _log_event(self, action: str, path: Path, hash_file: bool):
        if self.exclusions.is_excluded(path):
            return

        sha256 = None

        if hash_file and path.exists():
            try:
                if path.stat().st_size > 0:
                    time.sleep(HASH_DELAY_SECONDS)
                    sha256 = compute_sha256(path)
            except OSError:
                pass

        logging.info(
            "%s | %s | SHA256=%s",
            action,
            path,
            sha256 if sha256 else "N/A",
        )


def setup_logging(log_file: str):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Windows File System Monitor for Malware Analysis"
    )

    parser.add_argument(
        "--path",
        required=True,
        help="Directory path to monitor",
    )

    parser.add_argument(
        "--log",
        default="file_changes.log",
        help="Log file path",
    )

    parser.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="Exclude directory path (repeatable)",
    )

    parser.add_argument(
        "--exclude-wildcard",
        action="append",
        default=[],
        help="Exclude wildcard path (e.g. C:\\Windows\\*)",
    )

    parser.add_argument(
        "--exclude-extension",
        action="append",
        default=[],
        help="Exclude file extension (e.g. .log)",
    )

    return parser.parse_args()


def main():
    if os.name != "nt":
        print("This tool is Windows-only.")
        sys.exit(1)

    if not is_running_as_admin():
        print("Administrator privileges required. Requesting elevation...")
        relaunch_as_admin()
        return

    args = parse_args()
    watch_path = Path(args.path).resolve()

    if not watch_path.exists():
        print("Path does not exist")
        sys.exit(1)

    setup_logging(args.log)

    exclusions = ExclusionRules(
        exclude_paths=args.exclude_path,
        exclude_wildcards=args.exclude_wildcard,
        exclude_extensions=args.exclude_extension,
    )

    event_handler = FileChangeHandler(exclusions)
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)

    logging.info("Monitoring started on %s", watch_path)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
    logging.info("Monitoring stopped")


if __name__ == "__main__":
    main()
