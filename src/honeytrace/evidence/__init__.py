"""Evidence blackbox: journal, hashing, manifest, verification and export.

The journal is the single ingestion point for incident evidence. Reports
read it; nothing else writes it.
"""

from honeytrace.evidence.hashing import (
    bounded_diff,
    diff_files_if_appropriate,
    is_diffable,
    redact_text,
    sha256_bytes,
    sha256_file,
    sha256_text,
)
from honeytrace.evidence.journal import JournalWriter, iter_raw_events, journal_segments, read_events
from honeytrace.evidence.manifest import ArtifactManifest
from honeytrace.evidence.verification import verify_event_ids_unique, verify_journal

__all__ = [
    "bounded_diff",
    "diff_files_if_appropriate",
    "is_diffable",
    "redact_text",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "JournalWriter",
    "iter_raw_events",
    "journal_segments",
    "read_events",
    "ArtifactManifest",
    "verify_event_ids_unique",
    "verify_journal",
]
