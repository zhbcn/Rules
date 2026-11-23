#!/usr/bin/env python3
"""Compile all zhbcn/Rules bundles into five-client native dist/ artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from emitters import (  # noqa: E402
    compile_bundles,
    emit_egern,
    emit_loon,
    emit_mihomo_stash,
    emit_quantumultx,
    find_mihomo_bin,
)
from emitters.common import write_text_lf  # noqa: E402


ROOT = SCRIPTS_DIR.parent


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_to_dir(root: Path, dist_dir: Path, mihomo_bin: Path) -> tuple[dict, dict]:
    """Build all bundles into ``dist_dir`` and return (manifest, build_report)."""
    bundles_doc, bundles = compile_bundles(root)
    raw_base = bundles_doc["raw_base"].rstrip("/")

    # Clean stale artifacts inside target subdirs before emitting fresh output
    for sub in ("mihomo-stash", "mihomo-classical", "stash-classical", "egern", "loon", "quantumultx"):
        sub_path = dist_dir / sub
        if sub_path.exists():
            shutil.rmtree(sub_path)
        sub_path.mkdir(parents=True, exist_ok=True)

    manifest_bundles: dict[str, dict] = {}
    report_bundles: dict[str, dict] = {}
    totals = {
        client: {"emitted": 0, "adapted": 0, "skipped": 0}
        for client in ("mihomo", "stash", "egern", "loon", "quantumultx")
    }

    for bundle in bundles:
        mihomo_stats, stash_stats = emit_mihomo_stash(bundle, dist_dir, mihomo_bin)
        egern_stats = emit_egern(bundle, dist_dir)
        loon_stats = emit_loon(bundle, dist_dir)
        qx_stats = emit_quantumultx(bundle, dist_dir)

        client_stats = {
            "mihomo": mihomo_stats,
            "stash": stash_stats,
            "egern": egern_stats,
            "loon": loon_stats,
            "quantumultx": qx_stats,
        }
        for cname, st in client_stats.items():
            totals[cname]["emitted"] += st.emitted
            totals[cname]["adapted"] += st.adapted
            totals[cname]["skipped"] += st.skipped

        manifest_bundles[bundle.id] = {
            "id": bundle.id,
            "description": bundle.meta.get("description", ""),
            "category": bundle.meta.get("category", ""),
            "platform": bundle.meta.get("platform", "all"),
            "dns_bound": bool(bundle.meta.get("dns_bound", False)),
            "source_count": len(bundle.meta.get("sources") or []),
            "canonical_rule_count": bundle.ruleset.count(),
            "artifacts": {
                cname: dict(st.artifacts) for cname, st in client_stats.items()
            },
        }

        report_bundles[bundle.id] = {
            "canonical_rule_count": bundle.ruleset.count(),
            "excluded_count": bundle.excluded_count,
            "patches_applied": bundle.patch_log,
            "clients": {cname: st.to_dict() for cname, st in client_stats.items()},
        }

    manifest = {
        "schema": "zhbcn-manifest/v1",
        "raw_base": raw_base,
        "bundle_count": len(bundles),
        "bundles": manifest_bundles,
    }
    report = {
        "schema": "zhbcn-build-report/v1",
        "bundle_count": len(bundles),
        "totals": totals,
        "bundles": report_bundles,
    }

    write_text_lf(dist_dir / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    write_text_lf(dist_dir / "build-report.json", json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return manifest, report


def _snapshot_hashes(base: Path) -> dict[str, str]:
    if not base.is_dir():
        return {}
    return {
        p.relative_to(base).as_posix(): _sha256(p)
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }


def check_dist_up_to_date(root: Path, mihomo_bin: Path) -> list[str]:
    """Rebuild into a temp directory and compare every file hash against dist/."""
    dist_dir = root / "dist"
    with tempfile.TemporaryDirectory(prefix="zhbcn_dist_check_") as tmp:
        tmp_dist = Path(tmp) / "dist"
        build_to_dir(root, tmp_dist, mihomo_bin)
        expected = _snapshot_hashes(tmp_dist)
        actual = _snapshot_hashes(dist_dir)

    errors: list[str] = []
    for rel in sorted(expected.keys() - actual.keys()):
        errors.append(f"DIST MISSING: dist/{rel}")
    for rel in sorted(actual.keys() - expected.keys()):
        errors.append(f"DIST EXTRA: dist/{rel}")
    for rel in sorted(expected.keys() & actual.keys()):
        if expected[rel] != actual[rel]:
            errors.append(f"DIST OUTDATED: dist/{rel} (run python scripts/build.py)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile zhbcn/Rules bundles into dist/")
    parser.add_argument("--mihomo-bin", help="Explicit path to mihomo / verge-mihomo binary")
    parser.add_argument("--check", action="store_true", help="Verify dist/ matches freshly built output")
    args = parser.parse_args()

    mihomo_bin = find_mihomo_bin(args.mihomo_bin)
    if args.check:
        errors = check_dist_up_to_date(ROOT, mihomo_bin)
        if errors:
            for err in errors:
                print(err, file=sys.stderr)
            return 1
        print("dist/ is up to date.")
        return 0

    manifest, report = build_to_dir(ROOT, ROOT / "dist", mihomo_bin)
    print(f"Built {manifest['bundle_count']} bundles using {mihomo_bin}")
    for client, stats in report["totals"].items():
        print(
            f"  {client:12s}: emitted={stats['emitted']:6d}  "
            f"adapted={stats['adapted']:3d}  skipped={stats['skipped']:3d}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
