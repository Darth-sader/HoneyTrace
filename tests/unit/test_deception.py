"""Unit tests: decoy generation (all types produce valid files), tokens, inventory."""

from __future__ import annotations

import io
import zipfile

import pytest

from honeytrace.deception.generator import DecoyGenerator
from honeytrace.deception.inventory import DecoyInventory
from honeytrace.deception.tokens import TokenRegistry
from honeytrace.deception.workspace import DeceptionWorkspace, WorkspaceError
from honeytrace.evidence.hashing import sha256_file


@pytest.fixture()
def registry():
    return TokenRegistry()


@pytest.fixture()
def gen(registry):
    return DecoyGenerator(registry, seed=42)


def test_tokens_unique_and_resolvable():
    r = TokenRegistry()
    t1 = r.issue("DCY-1")
    t2 = r.issue("DCY-2")
    assert t1["token"] != t2["token"]
    resolved = r.resolve(t1["token"])
    assert resolved and resolved["decoy_id"] == "DCY-1"
    assert r.resolve("no-such-token") is None


def test_token_expiry():
    r = TokenRegistry()
    entry = r.issue("DCY-X", ttl_hours=-1)
    resolved = r.resolve(entry["token"])
    assert resolved and resolved.get("expired") is True


def _assert_zip(payload: bytes):
    zf = zipfile.ZipFile(io.BytesIO(payload))
    assert zf.testzip() is None


def test_generate_pdf_magic(gen, tmp_path):
    d = gen.generate(tmp_path, "pdf", "invoice_{n}.pdf", "invoice")
    assert d.payload.startswith(b"%PDF-")
    assert b"%%EOF" in d.payload


def test_generate_zip_valid(gen, tmp_path):
    d = gen.generate(tmp_path, "zip", "archive_{n}.zip", "archive")
    _assert_zip(d.payload)


def test_generate_docx_valid(gen, tmp_path):
    d = gen.generate(tmp_path, "docx", "notes_{n}.docx", "notes")
    _assert_zip(d.payload)  # OOXML is a zip container
    zf = zipfile.ZipFile(io.BytesIO(d.payload))
    assert "word/document.xml" in zf.namelist()


def test_generate_xlsx_valid(gen, tmp_path):
    d = gen.generate(tmp_path, "xlsx", "budget_{n}.xlsx", "budget")
    _assert_zip(d.payload)
    zf = zipfile.ZipFile(io.BytesIO(d.payload))
    assert "xl/workbook.xml" in zf.namelist()


def test_generate_csv_txt_content(gen, tmp_path):
    csv_d = gen.generate(tmp_path, "csv", "salary_{n}.csv", "salary")
    assert b"annual_salary_eur" in csv_d.payload
    txt_d = gen.generate(tmp_path, "txt", "creds_{n}.txt", "credentials")
    assert b"Sample-NotReal-" in txt_d.payload   # obviously synthetic by design
    assert b"beacon" in txt_d.payload


def test_deterministic_content_with_seed(registry, tmp_path):
    g1 = DecoyGenerator(registry, seed=99)
    g2 = DecoyGenerator(registry, seed=99)
    c1 = g1._csv("salary")
    c2 = g2._csv("salary")
    assert c1 == c2


def test_inventory_register_and_cleanup(tmp_path, gen):
    inv = DecoyInventory(tmp_path / "data")
    d = gen.generate(tmp_path, "txt", "bait.txt", "notes", decoy_id="DCY-C1")
    d.write()
    inv.register("DCY-C1", d.path, "txt", "notes", sha256_file(d.path))
    assert inv.by_path(str(d.path))["decoy_id"] == "DCY-C1"

    # Unmodified decoy is removed; manifest stays consistent.
    report = inv.cleanup()
    assert report["removed"] == [str(d.path)]
    assert not d.path.exists()
    assert inv.all() == []


def test_inventory_preserves_modified_decoy(tmp_path, gen):
    inv = DecoyInventory(tmp_path / "data")
    inv = DecoyInventory(tmp_path / "data")
    d = gen.generate(tmp_path, "txt", "bait2.txt", "notes", decoy_id="DCY-C2")
    d.write()
    inv.register("DCY-C2", d.path, "txt", "notes", sha256_file(d.path))
    d.path.write_text("attacker modified this\n")  # tamper

    report = inv.cleanup(force=False)
    assert report["removed"] == [] and report["preserved"]
    assert d.path.exists()  # potential evidence stays

    report = inv.cleanup(force=True)
    assert report["removed"] == [str(d.path)]


def test_workspace_refuses_outside_boundaries(tmp_path, settings):
    from tests.conftest import make_settings

    s = make_settings(tmp_path)
    inv = DecoyInventory(s.data_dir)
    reg = TokenRegistry()
    ws = DeceptionWorkspace(s, inv, reg)
    ws.set_boundaries(s.decoys_dir, s.monitored_paths())
    with pytest.raises(WorkspaceError):
        ws._validate_target(tmp_path / "elsewhere")   # outside boundaries
    with pytest.raises(WorkspaceError):
        ws._validate_target("/etc")                   # system path
    # Inside boundaries is fine.
    assert ws._validate_target(s.decoys_dir) == s.decoys_dir.resolve()


def test_workspace_deploy_transactional(settings, tmp_path):
    inv = DecoyInventory(settings.data_dir)
    reg = TokenRegistry()
    ws = DeceptionWorkspace(settings, inv, reg)
    lab_dir = settings.root / "lab" / "docs"
    lab_dir.mkdir(parents=True, exist_ok=True)
    ws.set_boundaries(lab_dir, [])
    # Give honeylist a group targeting the lab dir for the test.
    from honeytrace.config import DecoyGroup, DecoyItem, HoneylistConfig

    settings.honeylist = HoneylistConfig(
        decoy_groups=[
            DecoyGroup(
                name="test",
                directory=str(lab_dir),
                items=[DecoyItem(type="txt", name="bait_{n}.txt", count=2, content_profile="notes")],
            )
        ]
    )
    report = ws.deploy_from_honeylist()
    assert report["placed"], "decoys should be placed"
    assert not report["failed"], report["failed"]
    # Every placed decoy is registered with a hash.
    for d in report["placed"]:
        entry = inv.by_path(d["path"])
        assert entry and entry["sha256"]
