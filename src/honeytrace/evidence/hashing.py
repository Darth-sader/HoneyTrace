"""Evidence hashing, bounded diffs and redaction helpers.

Sensitive-data minimization lives here so every evidence path uses the same
routines: any text that becomes durable evidence first passes
`redact_text()`.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# Patterns redacted before anything is written to durable storage.
REDACT_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|pass)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|apikey|secret|token|auth)[-_=:\s]+[A-Za-z0-9_\-./+=]{8,}"),
    re.compile(r"(?i)authorization\s*:\s*\S+"),
    re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S+"),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)", re.S),
]
REDACTED = "REDACTED"

# Diffs are evidence; keep them bounded.
MAX_DIFF_BYTES = 8 * 1024
MAX_DIFF_LINES = 120
MAX_DIFFABLE_FILE_BYTES = 2 * 1024 * 1024
DIFFABLE_SUFFIXES = {".txt", ".csv", ".log", ".json", ".yml", ".yaml", ".md", ".conf", ".sh", ".xml"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="surrogateescape"))


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> Optional[str]:
    """Streaming SHA-256 of a file. Returns None when unreadable."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def redact_text(text: str) -> str:
    """Redact credential-shaped substrings before durable storage."""
    for pattern in REDACT_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}" if m.lastindex else REDACTED, text)
    return text


def is_diffable(path: Path, size: Optional[int] = None) -> bool:
    """Whether a bounded text diff is appropriate for this file."""
    if path.suffix.lower() not in DIFFABLE_SUFFIXES:
        return False
    try:
        actual = size if size is not None else path.stat().st_size
    except OSError:
        return False
    return actual <= MAX_DIFFABLE_FILE_BYTES


def bounded_diff(before: str, after: str, context: int = 3) -> str:
    """Unified diff, redacted and hard-bounded in size."""
    before = redact_text(before)
    after = redact_text(after)
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile="before",
        tofile="after",
        n=context,
    )
    out: List[str] = []
    total = 0
    for line in diff:
        out.append(line)
        total += len(line.encode("utf-8", errors="replace"))
        if total >= MAX_DIFF_BYTES or len(out) >= MAX_DIFF_LINES:
            out.append(f"... diff truncated (bound {MAX_DIFF_BYTES} bytes / {MAX_DIFF_LINES} lines)")
            break
    return "".join(out)


def diff_files_if_appropriate(old_path: Path, new_path: Optional[Path] = None) -> Optional[str]:
    """Produce a bounded redacted diff between two versions of a file.

    new_path=None means the file was deleted (diff against empty).
    Returns None when the file type/size makes diffs inappropriate.
    """
    if not is_diffable(old_path):
        return None
    try:
        before = old_path.read_text(errors="replace")
        after = new_path.read_text(errors="replace") if new_path and new_path.exists() else ""
    except OSError:
        return None
    return bounded_diff(before, after)


def hash_pair(path: Path) -> Tuple[Optional[str], Optional[int]]:
    """Convenience: (sha256, size) for a path, tolerant of races."""
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    return sha256_file(path), size


def batch_hashes(paths: Iterable[Path]) -> dict:
    return {str(p): sha256_file(p) for p in paths}
