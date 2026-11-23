#!/usr/bin/env python3
"""Sync read-only upstream rule sources into canonical upstream/*.yaml files.

Supports both:
  1. Remote pinned-commit fetch via GitHub Raw (--remote, with optional --update-commits)
  2. Local snapshot directories (--v2fly-data, --bm7-dir, --sukka-dir, --qingrex-dir)

All outputs are normalized to zhbcn-rules/v1 with PROCESS-* stripped and logged.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from convert_v2fly import V2FlyConverter  # noqa: E402
from schema import (  # noqa: E402
    MIHOMO_TO_CANONICAL,
    PROCESS_TYPES,
    RuleSet,
    dump_source_file,
)


ROOT = SCRIPTS_DIR.parent
V2FLY_PREFIX_MAP = {
    "domain": "domain_suffix",
    "full": "domain",
    "keyword": "domain_keyword",
    "regexp": "domain_regex",
}
SIMPLE_V2FLY_REF_RE = re.compile(r"^[a-z0-9!_-]+$")


def _http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "zhbcn-Rules-sync/1.0"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8-sig")


def update_provider_commits(sources_path: Path) -> dict[str, tuple[str, str]]:
    """Query GitHub API for latest commit SHA on each provider's branch."""
    doc = json.loads(sources_path.read_text(encoding="utf-8-sig"))
    changes: dict[str, tuple[str, str]] = {}
    for name, info in (doc.get("providers") or {}).items():
        repo = info["repo"]
        branch = info.get("branch", "main")
        api_url = f"https://api.github.com/repos/{repo}/commits/{branch}"
        payload = json.loads(_http_get(api_url))
        new_sha = payload["sha"]
        old_sha = info.get("commit", "")
        if new_sha != old_sha:
            info["commit"] = new_sha
            changes[name] = (old_sha, new_sha)
    if changes:
        sources_path.write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return changes


def parse_clash_or_list_lines(lines: list[str]) -> tuple[RuleSet, list[str]]:
    """Parse Clash classical YAML payload lines or Surge/Loon plain-text lines."""
    rs = RuleSet()
    stripped_process: list[str] = []

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        # Handle inline comments outside regexes
        if line.startswith("- "):
            line = line[2:].strip().strip("'\"")
        kind, sep, rest = line.partition(",")
        if not sep:
            # Pure domain-list line (e.g. Sukka domainset)
            if line.startswith("+."):
                rs.add("domain_suffix", line[2:])
            elif line.startswith("."):
                rs.add("domain_suffix", line[1:])
            elif re.fullmatch(r"[a-zA-Z0-9._-]+", line):
                rs.add("domain", line)
            continue

        kind_u = kind.strip().upper()
        if kind_u in PROCESS_TYPES:
            stripped_process.append(line)
            continue

        if kind_u == "AND":
            # Strip trailing policy if Surge/sgmodule style: AND,((...)),REJECT
            expr = rest.strip()
            if expr.startswith("((") and not expr.endswith("))"):
                # Trim trailing ,POLICY
                last_paren = expr.rfind("))")
                if last_paren != -1:
                    expr = expr[: last_paren + 2]
            rs.add("and", expr)
            continue

        if kind_u == "DOMAIN-REGEX":
            # Regexes may contain commas inside {2,6}; strip only known trailing policy/option if present
            rs.add("domain_regex", rest.strip())
            continue

        if kind_u == "URL-REGEX":
            rs.add("url_regex", rest.strip())
            continue

        canonical = MIHOMO_TO_CANONICAL.get(kind_u)
        if not canonical:
            continue

        parts = [p.strip() for p in rest.split(",")]
        val = parts[0]
        if not val:
            continue
        rs.add(canonical, val)

    rs.dedupe_and_sort()
    return rs, stripped_process


def parse_clash_yaml_text(text: str) -> tuple[RuleSet, list[str]]:
    doc = yaml.safe_load(text)
    if isinstance(doc, dict) and isinstance(doc.get("payload"), list):
        return parse_clash_or_list_lines([str(x) for x in doc["payload"]])
    return parse_clash_or_list_lines(text.splitlines())


def parse_sgmodule_text(text: str) -> tuple[RuleSet, list[str]]:
    in_rule = False
    rule_lines: list[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            in_rule = s.lower() == "[rule]"
            continue
        if in_rule:
            # QingRex sgmodules only contribute native domain/IP/AND rules;
            # URL-REGEX / USER-AGENT require MITM and are intentionally excluded.
            if s.upper().startswith(("URL-REGEX,", "USER-AGENT,")):
                continue
            rule_lines.append(raw)
    return parse_clash_or_list_lines(rule_lines)


def _fetch_v2fly_remote(raw_base: str, list_name: str, stack: tuple[str, ...] = ()) -> RuleSet:
    if list_name in stack:
        raise ValueError(f"V2Fly include cycle: {' -> '.join((*stack, list_name))}")
    url = f"{raw_base}/{quote(list_name)}"
    text = _http_get(url)
    rs = RuleSet()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        body = next((t for t in tokens if not t.startswith(("@", "&"))), "")
        if not body:
            continue
        if body.startswith("include:"):
            inc = body.removeprefix("include:").strip()
            rs.merge(_fetch_v2fly_remote(raw_base, inc, (*stack, list_name)))
            continue
        prefix, sep, val = body.partition(":")
        if sep and prefix in V2FLY_PREFIX_MAP:
            rs.add(V2FLY_PREFIX_MAP[prefix], val.strip())
        else:
            rs.add("domain_suffix", body)
    rs.dedupe_and_sort()
    return rs


def sync_source_entry(
    root: Path,
    providers: dict,
    entry: dict,
    *,
    remote: bool = False,
    v2fly_data: Path | None = None,
    bm7_dir: Path | None = None,
    sukka_dir: Path | None = None,
    qingrex_dir: Path | None = None,
    check_only: bool = False,
) -> tuple[str, int, list[str]]:
    """Sync one entry from sources.json. Returns (status, rule_count, stripped_process)."""
    provider = entry["provider"]
    ref = entry["ref"]
    target_path = root / entry["target"]

    if provider not in providers:
        return "skipped_non_upstream", 0, []

    pinfo = providers[provider]
    commit = pinfo["commit"]
    raw_base = pinfo["raw_base"].format(commit=commit)

    rs: RuleSet | None = None
    stripped: list[str] = []

    if provider == "v2fly":
        if not SIMPLE_V2FLY_REF_RE.fullmatch(ref):
            return "skipped_composite_ref", 0, []
        if v2fly_data:
            conv = V2FlyConverter(v2fly_data)
            rules = conv.read(ref)
            rs = RuleSet()
            for r in rules:
                rs.add(V2FLY_PREFIX_MAP[r.kind], r.value)
            rs.dedupe_and_sort()
        elif remote:
            rs = _fetch_v2fly_remote(raw_base, ref)
        else:
            return "skipped_no_input", 0, []

    elif provider == "blackmatrix7":
        if bm7_dir:
            src_file = bm7_dir / ref
            if not src_file.is_file():
                raise FileNotFoundError(f"Missing local bm7 file: {src_file}")
            rs, stripped = parse_clash_yaml_text(src_file.read_text(encoding="utf-8-sig"))
        elif remote:
            url = f"{raw_base}/{quote(ref, safe='/')}"
            rs, stripped = parse_clash_yaml_text(_http_get(url))
        else:
            return "skipped_no_input", 0, []

    elif provider == "sukka":
        if sukka_dir:
            src_file = sukka_dir / ref
            if not src_file.is_file():
                raise FileNotFoundError(f"Missing local sukka file: {src_file}")
            rs, stripped = parse_clash_or_list_lines(src_file.read_text(encoding="utf-8-sig").splitlines())
        elif remote:
            url = f"{raw_base}/{quote(ref, safe='/')}"
            rs, stripped = parse_clash_or_list_lines(_http_get(url).splitlines())
        else:
            return "skipped_no_input", 0, []

    elif provider == "qingrex":
        if qingrex_dir:
            src_file = qingrex_dir / ref
            if not src_file.is_file():
                raise FileNotFoundError(f"Missing local qingrex file: {src_file}")
            rs, stripped = parse_sgmodule_text(src_file.read_text(encoding="utf-8-sig"))
        elif remote:
            url = f"{raw_base}/{quote(ref, safe='/')}"
            rs, stripped = parse_sgmodule_text(_http_get(url))
        else:
            return "skipped_no_input", 0, []

    assert rs is not None
    source_meta = {"provider": provider, "ref": ref, "commit": commit}
    if check_only:
        existing = target_path.read_text(encoding="utf-8-sig") if target_path.is_file() else ""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_file = Path(tmp) / "out.yaml"
            generated = dump_source_file(
                tmp_file,
                name=entry["name"],
                kind="upstream",
                source=source_meta,
                ruleset=rs,
            )
        status = "up_to_date" if existing == generated else "outdated"
        return status, rs.count(), stripped

    dump_source_file(
        target_path,
        name=entry["name"],
        kind="upstream",
        source=source_meta,
        ruleset=rs,
    )
    return "synced", rs.count(), stripped


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync upstream rule sources into upstream/*.yaml")
    parser.add_argument("--remote", action="store_true", help="Fetch from pinned commits on GitHub Raw")
    parser.add_argument("--update-commits", action="store_true", help="Update pinned commits in sources.json via GitHub API")
    parser.add_argument("--v2fly-data", type=Path, help="Local v2fly/domain-list-community/data directory")
    parser.add_argument("--bm7-dir", type=Path, help="Local blackmatrix7/ios_rule_script root directory")
    parser.add_argument("--sukka-dir", type=Path, help="Local SukkaLab/ruleset.skk.moe/List directory")
    parser.add_argument("--qingrex-dir", type=Path, help="Local QingRex/LoonKissSurge/Surge/Beta directory")
    parser.add_argument("--source", action="append", help="Sync only specified source id(s)")
    parser.add_argument("--check", action="store_true", help="Check if upstream/*.yaml matches synced output")
    args = parser.parse_args()

    sources_path = ROOT / "sources.json"
    if args.update_commits:
        changes = update_provider_commits(sources_path)
        if changes:
            for pname, (old, new) in changes.items():
                print(f"Updated {pname}: {old[:10]} -> {new[:10]}")
        else:
            print("All provider commits are already at latest.")

    doc = json.loads(sources_path.read_text(encoding="utf-8-sig"))
    providers = doc["providers"]
    entries = doc["sources"]
    if args.source:
        wanted = set(args.source)
        entries = [e for e in entries if e["id"] in wanted]
        if not entries:
            print(f"No matching sources for: {sorted(wanted)}", file=sys.stderr)
            return 1

    outdated = 0
    synced = 0
    for entry in entries:
        status, count, stripped = sync_source_entry(
            ROOT,
            providers,
            entry,
            remote=args.remote,
            v2fly_data=args.v2fly_data,
            bm7_dir=args.bm7_dir,
            sukka_dir=args.sukka_dir,
            qingrex_dir=args.qingrex_dir,
            check_only=args.check,
        )
        if status == "synced":
            synced += 1
            extra = f" (stripped {len(stripped)} PROCESS-* rules)" if stripped else ""
            print(f"[SYNCED] {entry['id']}: {count} rules{extra}")
        elif status == "outdated":
            outdated += 1
            print(f"[OUTDATED] {entry['id']} -> {entry['target']}", file=sys.stderr)

    print(f"Done: synced={synced}, outdated={outdated}")
    return 1 if outdated else 0


if __name__ == "__main__":
    raise SystemExit(main())
