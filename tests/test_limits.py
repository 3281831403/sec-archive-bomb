"""Contract tests for the ten archive-bomb defects and five baselines.

Every archive is an in-memory descriptor.  No archive is created, no payload
is written, and no production filesystem is touched.  The only filesystem
operation in this module is path-string construction for the confinement
checks.
"""

from __future__ import annotations

import os

from arc import (
    archive_batch,
    budget_check,
    depth_check,
    extract_plan,
    inspect,
    path_check,
    ratio_check,
    validate_policy,
)

ROOT = os.path.abspath(os.path.join("sandbox", "out"))


def _entry(name, declared, compressed=None, actual=None, nested=None):
    """Build one in-memory archive member descriptor."""
    if compressed is None:
        compressed = declared
    item = {
        "name": name,
        "declared_size": declared,
        "compressed_size": compressed,
    }
    if actual is not None:
        item["actual_size"] = actual
    if nested is not None:
        item["nested"] = nested
    return item


def _archive(*entries):
    """Build one in-memory archive descriptor."""
    return {"entries": list(entries)}


def _policy(**overrides):
    """Build a compliant policy, allowing individual fields to be changed."""
    policy = {
        "root": ROOT,
        "budget": 1_000_000,
        "max_ratio": 100,
        "max_depth": 2,
        "max_entries": 64,
        "max_name_length": 255,
    }
    policy.update(overrides)
    return policy


def test_defect_01_inspect_includes_nested_entries():
    nested = _archive(_entry("inner/deep.txt", 7, 2))
    outer = _archive(
        _entry("top.txt", 5, 1),
        _entry("inner.zip", 11, 3, nested=nested),
    )

    report = inspect(outer)

    assert [item["name"] for item in report["entries"]] == [
        "top.txt",
        "inner.zip",
        "inner/deep.txt",
    ]
    assert report["entry_count"] == 3
    assert report["total_size"] == 23
    assert report["max_depth"] == 1


def test_defect_02_inspect_checks_declared_against_actual():
    report = inspect(
        _archive(_entry("claimed.bin", 12, 4, actual=4096))
    )

    assert report["size_mismatches"] == ["claimed.bin"]
    assert report["total_declared_size"] == 12
    assert report["total_size"] == 4096


def test_defect_03_ratio_check_uses_ratio_not_sum():
    assert ratio_check(100, 1, 100) is True
    assert ratio_check(101, 1, 100) is False


def test_defect_04_budget_equality_is_allowed():
    assert budget_check(4096, 4096) is True
    assert budget_check(4097, 4096) is False


def test_defect_05_depth_check_counts_all_levels():
    level_two = _entry("level-two.tar", 10, 2)
    level_two["nested"] = _archive(_entry("leaf.txt", 1, 1))
    level_one = _entry("level-one.tar", 20, 3, nested=_archive(level_two))

    assert depth_check(level_one, 1) is False
    assert depth_check(level_one, 2) is True


def test_defect_06_path_check_rejects_drive_paths():
    drive = os.path.splitdrive(ROOT)[0]
    drive_absolute = drive + os.sep + os.path.join("Windows", "win.ini")
    drive_relative = drive + "relative.txt"

    assert path_check(drive_absolute, ROOT) is False
    assert path_check(drive_relative, ROOT) is False
    assert path_check("safe/report.txt", ROOT) is True


def test_defect_07_path_check_normalizes_dot_segments():
    assert path_check("reports/../../escape.txt", ROOT) is False
    assert path_check("reports/../inside.txt", ROOT) is True


def test_defect_08_extract_plan_limits_entries_and_name_length():
    many = _archive(
        _entry("one.txt", 1, 1),
        _entry("two.txt", 1, 1),
        _entry("three.txt", 1, 1),
    )
    count_plan = extract_plan(
        many,
        _policy(max_entries=2, max_depth=0),
    )

    assert count_plan["accepted"] is False
    assert "条目数超限" in count_plan["reasons"]

    long_name = "a" * 12 + ".txt"
    long_plan = extract_plan(
        _archive(_entry(long_name, 1, 1)),
        _policy(max_name_length=8, max_depth=0),
    )

    assert long_plan["accepted"] is False
    assert "文件名过长" in long_plan["reasons"]


def test_defect_09_policy_validation_requires_ratio():
    issues = validate_policy({"budget": 1000, "max_depth": 2})

    assert issues == ["缺少压缩比上限"]


def test_defect_10_batch_does_not_reuse_manifest():
    big = _archive(_entry("big.bin", 900, 90))
    small = _archive(_entry("small.bin", 10, 5))

    batch = archive_batch(
        {"big-first": big, "small-second": small},
        _policy(budget=500, max_depth=0),
    )

    assert batch["accepted"] is False
    assert batch["plans"]["big-first"]["accepted"] is False
    assert batch["plans"]["small-second"]["accepted"] is True


def test_normal_archive_is_accepted():
    normal = _archive(
        _entry("docs/readme.txt", 120, 40),
        _entry("docs/data/report.csv", 300, 60),
    )

    plan = extract_plan(normal, _policy())

    assert plan["accepted"] is True
    assert plan["reasons"] == []
    assert plan["entry_count"] == 2
    assert plan["total_size"] == 420
    assert plan["total_compressed"] == 100
    assert [item["name"] for item in plan["entries"]] == [
        "docs/readme.txt",
        "docs/data/report.csv",
    ]


def test_ratio_bomb_is_rejected():
    bomb = _archive(_entry("bomb.bin", 10_000_000, 1_000))

    plan = extract_plan(
        bomb,
        _policy(budget=20_000_000, max_ratio=100, max_depth=0),
    )

    assert plan["accepted"] is False
    assert "压缩比超限" in plan["reasons"]


def test_over_budget_archive_is_rejected():
    oversized = _archive(
        _entry("part-a.bin", 1024, 512),
        _entry("part-b.bin", 1024, 512),
    )

    plan = extract_plan(oversized, _policy(budget=2000, max_depth=0))

    assert plan["accepted"] is False
    assert "总量预算超限" in plan["reasons"]


def test_traversal_archive_is_rejected():
    traversal = _archive(
        _entry("docs/readme.txt", 10, 5),
        _entry("../escape.sh", 10, 5),
    )

    plan = extract_plan(traversal, _policy(max_depth=0))

    assert plan["accepted"] is False
    assert "条目路径越界" in plan["reasons"]


def test_batch_matches_individual_checks():
    archives = {
        "clean": _archive(_entry("docs/readme.txt", 100, 20)),
        "bomb": _archive(_entry("bomb.bin", 10_000_000, 1_000)),
        "escape": _archive(_entry("../escape.sh", 10, 5)),
    }
    policy = _policy(budget=20_000_000, max_depth=0)

    batch = archive_batch(archives, policy)

    for label, archive in archives.items():
        individual = extract_plan(archive, policy)
        assert batch["plans"][label] == individual