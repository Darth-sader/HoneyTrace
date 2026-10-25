"""Unit tests: artifact manifest, hashing helpers and bounded diffs."""

from __future__ import annotations

from pathlib import Path

from honeytrace.evidence.hashing import (
    bounded_diff,
    diff_files_if_appropriate,
    is_diffable,
    redact_text,
    sha256_bytes,
    sha256_file,
)
from honeytrace.evidence.manifest import ArtifactManifest


def test_sha256_file_streaming(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello honeytrace")
    assert sha256_file(p) == sha256_bytes(b"hello honeytrace")


def test_sha256_missing_file_is_none(tmp_path):
    assert sha256_file(tmp_path / "nope.bin") is None


def test_redact_text_in_diffs():
    before = "password=hunter2\nline2\n"
    after = "password=newpass123\nline2 changed\n"
    diff = bounded_diff(before, after)
    assert "hunter2" not in diff
    assert "newpass123" not in diff
    assert diff.startswith("---")


def test_diff_is_bounded():
    # Every line changes so the unified diff is genuinely large.
    before = "\n".join(f"line {i} " + "y" * 50 for i in range(500))
    after = "\n".join(f"LINE {i} " + "z" * 50 for i in range(500))
    diff = bounded_diff(before, after)
    assert len(diff) <= 12 * 1024  # hard cap with margin
    assert "truncated" in diff


def test_is_diffable_by_suffix_and_size(tmp_path):
    txt = tmp_path / "a.txt"
    txt.write_text("x" * 10)
    assert is_diffable(txt)
    big = tmp_path / "b.txt"
    big.write_text("x" * (3 * 1024 * 1024))
    assert not is_diffable(big)
    exe = tmp_path / "c.bin"
    exe.write_bytes(b"\x00" * 10)
    assert not is_diffable(exe)


def test_diff_files_deletion(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("alpha\nbeta\n")
    d = diff_files_if_appropriate(p, None)
    assert d is not None and "-alpha" in d and "-beta" in d


def test_manifest_add_verify_and_prune(tmp_path):
    m = ArtifactManifest(tmp_path / "manifests")
    art = tmp_path / "art.pcap"
    art.write_bytes(b"pcapbytes")

    entry = m.add(art, "pcap", source="pcap", related_event_ids=["ev-1"])
    assert entry and entry["sha256"] == sha256_bytes(b"pcapbytes")

    report = m.verify_all()
    assert report["verified"] == 1
    assert report["mismatched"] == 0

    # Tamper: rewrite artifact -> mismatch detected.
    art.write_bytes(b"tampered")
    report = m.verify_all()
    assert report["mismatched"] == 1

    # Missing artifact -> prune removes the stale entry.
    art.unlink()
    assert m.prune_missing() == 1
    assert m.entries() == []


def test_manifest_find_by_event(tmp_path):
    m = ArtifactManifest(tmp_path / "manifests")
    a = tmp_path / "x.jsonl"
    a.write_text("{}")
    m.add(a, "journal", source="export", related_event_ids=["e-42"])
    assert m.find_by_event("e-42")
    assert not m.find_by_event("e-43")
