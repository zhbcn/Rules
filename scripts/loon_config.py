#!/usr/bin/env python3
"""Build/check a private native Loon candidate from Egern, without any network access.

Remote resources and subscriptions are disabled until publication and response-format
verification. This tool never interprets a URL as a local resource or fetches it.
"""
from __future__ import annotations

import argparse
import fnmatch
from pathlib import Path
import re
from urllib.parse import urlsplit

if __package__:
    from .convert_loon import Converter, Rule, disjuncts, format_rule, load_yaml, manifest, parse_native, source_expression, split_fields
else:
    from convert_loon import Converter, Rule, disjuncts, format_rule, load_yaml, manifest, parse_native, source_expression, split_fields


REMOTE_BASE = "https://raw.githubusercontent.com/zhbcn/Rules/main/Ruleset/Loon/"
PRIVATE_LOCAL_INDICES = {4, 5, 13, 14, 25, 54}
GENERAL_FIELDS = {
    "ip-mode", "ipv6-vif", "dns-server", "doh-server", "bypass-tun", "skip-proxy",
    "real-ip", "hijack-dns", "allow-wifi-access", "wifi-access-http-port",
    "wifi-access-socks5-port", "disconnect-on-policy-change", "disable-stun",
    "udp-fallback-mode", "domain-reject-mode", "sni-sniffing", "interface-mode",
    "geoip-url", "ipasn-url", "proxy-test-url", "internet-test-url",
}


def quote(value: str) -> str:
    if any(c in value for c in "\r\n"):
        raise ValueError("Newline in native argument")
    return '"' + value.replace('"', '\\"') + '"'


def combine_filter(all_nodes: str, region: str | None = None) -> str:
    def body(value: str) -> str:
        return value.removeprefix("(?i)")
    if region is None:
        result = all_nodes
    else:
        term = body(region)
        search = term if term.startswith("^") else ".*(?:" + term + ")"
        result = "(?i)(?=" + body(all_nodes) + ")(?=" + search + ").+"
    re.compile(result)
    return result


def domain_matches(rule: Rule, hostname: str) -> bool:
    value, host = rule.value.lower(), hostname.lower()
    if rule.kind == "DOMAIN":
        return host == value
    if rule.kind == "DOMAIN-SUFFIX":
        return host == value or host.endswith("." + value)
    if rule.kind == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(host, value)
    return False


def build_hosts(document: dict, root: Path) -> tuple[dict[str, str], list[str]]:
    converter = Converter(root)
    rows: list[tuple[Rule, str]] = []
    gaps = []
    for rule in document["dns"]["forward"]:
        kind, spec = next(iter(rule.items()))
        if spec.get("disabled") or (kind == "domain_wildcard" and spec["match"] == "*"):
            continue
        if kind == "proxy_rule_set" and not spec["match"].startswith("https://raw.githubusercontent.com/zhbcn/Rules/main/"):
            gaps.append("ChinaMax remote DNS set has no native Host-list binding; no bulk download")
            continue
        node = converter.expression(source_expression(rule))
        for atom in disjuncts(node):
            if atom.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
                rows.append((atom, spec["value"]))
            elif atom.kind not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
                gaps.append("DNS condition has no Host representation: " + atom.kind)
    upstreams = document["dns"]["upstreams"]
    primary = {"system": "system", "China": next(x for x in upstreams["China"] if x.startswith("https://"))}
    primary.update({name: values[0] for name, values in upstreams.items() if name != "China"})
    hosts = {}
    for atom, group in rows:
        keys = [atom.value] + (["*." + atom.value] if atom.kind == "DOMAIN-SUFFIX" else [])
        for key in keys:
            if key in hosts:
                continue
            # Materialize Egern's earlier broader system exceptions before narrower later maps.
            effective = group if atom.kind == "DOMAIN-WILDCARD" else next(value for condition, value in rows if domain_matches(condition, key.removeprefix("*.")))
            hosts[key] = primary[effective]
    if any("[" in key or "]" in key for key in hosts):
        raise ValueError("Host Map documentation does not specify character classes")
    # Remove redundant descendants only when the nearest enclosing wildcard has the same endpoint.
    # Retain conflicting children and both the apex and wildcard when they have different scopes.
    for key in sorted(list(hosts), key=len, reverse=True):
        host = key.removeprefix("*.")
        parts = host.split(".")
        for i in range(1, len(parts)):
            parent = "*." + ".".join(parts[i:])
            if parent in hosts:
                if hosts[parent] == hosts[key]:
                    del hosts[key]
                break
    return hosts, list(dict.fromkeys(gaps + converter.notes))


def local_line(rule: Rule, policy: str) -> str:
    text = format_rule(rule)
    if rule.no_resolve:
        return text.removesuffix(",no-resolve") + "," + policy + ",no-resolve"
    return text + "," + policy


def build_config(document: dict, root: Path, *, remote_rules: bool = False,
                 subscriptions: bool = False) -> tuple[str, dict]:
    resources = manifest(root)
    expected_indices = {r["source_index"] for r in resources}
    if expected_indices | PRIVATE_LOCAL_INDICES != set(range(1, len(document["rules"]) + 1)):
        raise ValueError("Egern layout changed; review public routing manifest")
    for item in resources:
        actual = source_expression(document["rules"][item["source_index"] - 1])
        if actual != item["expression"]:
            raise ValueError("Egern public rule changed; review manifest index " + str(item["source_index"]))
    external = [g["external"] for g in document["policy_groups"] if "external" in g]
    if len(external) != 1 or external[0].get("type") != "select":
        raise ValueError("Expected one manual subscription pool")
    urls = external[0]["urls"]
    if len(urls) != 2:
        raise ValueError("Subscription source count changed; review labels and DNS")
    labels = ["Ash", "吹雪云"]
    if urlsplit(urls[0]).hostname != "static01.flowaccess.org":
        raise ValueError("Ash source host changed; review source order")
    hosts, gaps = build_hosts(document, root)
    out = ["# Loon native configuration built from the current main Egern configuration.",
           "# Native Loon only: [Remote Proxy] subscriptions parsed by Loon itself (no resource parser),",
           "# policy-free remote rule lists bound here, native [Host] DNS maps. No Tailscale node.",
           "# Requires Build 1008+ for native DOMAIN-WILDCARD and Build 996+ for subscription server-dns.",
           "# Loon evaluates domain rules before IP rules and local rules before remote rules, unlike Egern.",
           "# DNS Host maps choose one endpoint; ChinaMax DNS sets and DNS egress remain unverified.",
           "# Never update Ash merely to test this file; no subscription was requested while building it.", "", "[General]"]
    general = {
        "ip-mode": "dual" if document["ipv6"] else "v4-only",
        "ipv6-vif": "auto" if document["ipv6"] else "off",
        "dns-server": ",".join(document["dns"]["bootstrap"]),
        "doh-server": ",".join(document["dns"]["upstreams"]["Global"]),
        "bypass-tun": ",".join(document["bypass_tunnel_proxy"]),
        "skip-proxy": "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,*.lan",
        "real-ip": ",".join(document["real_ip_domains"]),
        "hijack-dns": ",".join(document["hijack_dns"]),
        "allow-wifi-access": str(document["allow_external_connections"]).lower(),
        "wifi-access-http-port": str(document["http_port"]),
        "wifi-access-socks5-port": str(document["socks_port"]),
        "disconnect-on-policy-change": str(document["close_connections_on_policy_change"]).lower(),
        "disable-stun": "false", "udp-fallback-mode": "REJECT", "domain-reject-mode": "Request",
        "sni-sniffing": "true", "interface-mode": "auto",
        "geoip-url": document["geoip_db_url"], "ipasn-url": document["asn_db_url"],
        "proxy-test-url": document["proxy_latency_test_url"],
        "internet-test-url": document["direct_latency_test_url"],
    }
    out += [key + " = " + value for key, value in general.items()]
    # Loon adaptation drops local proxies: the source's only local node is Tailscale, which is
    # intentionally not carried over. No cached provider nodes are emitted either.
    for proxy in document["proxies"]:
        if len(proxy) != 1 or "tailscale" not in proxy:
            raise ValueError("Local proxy types changed; no automatic protocol substitution")
    omitted = {proxy["tailscale"]["name"] for proxy in document["proxies"]}
    out += ["", "[Remote Proxy]", "# Native Loon subscription parsing; response format is not pre-verified."]
    for label, url in zip(labels, urls):
        dns = document["dns"]["upstreams"]["Ash" if label == "Ash" else "China"]
        out += [label + " = " + url + ",parser-enabled=false,udp=default,block-quic=default,fast-open=default,skip-cert-verify=default,enabled=" + str(subscriptions).lower() + ",server-dns=" + quote(",".join(dns))]
    out += ["", "[Remote Filter]"]
    filters = {}
    for item in document["policy_groups"]:
        kind, group = next(iter(item.items()))
        if kind == "external" or group.get("flatten"):
            name = "筛选-" + group["name"]
            pattern = combine_filter(external[0]["filter"], group.get("filter") if kind != "external" else None)
            filters[group["name"]] = name
            out += [name + " = NameRegex," + ",".join(labels) + ",FilterKey=" + quote(pattern)]
    out += ["", "[Proxy Group]"]
    for item in document["policy_groups"]:
        kind, group = next(iter(item.items()))
        if kind == "external" or group.get("flatten"):
            members = [filters[group["name"]]]
        else:
            members = list(group["policies"])
            if group["name"] == "Public network":
                members = ["日本"] + [x for x in members if x != "日本"]
            members = [x for x in members if x not in omitted]
            if not members:
                raise ValueError("Policy group only referenced omitted local proxies: " + group["name"])
        out += [group["name"] + " = select," + ",".join(members) + (",img-url=" + group["icon"] if group.get("icon") else "")]
    out += ["", "[Rule]", "# Only private bootstrap, explicit resolver egress, personal IPs and FINAL stay local.",
            "# Exclude STUN here: source STUN routing precedes every private local exception."]
    converter = Converter(root)
    local_count = 0
    for index, source in enumerate(document["rules"], 1):
        if index not in PRIVATE_LOCAL_INDICES:
            continue
        kind, spec = next(iter(source.items()))
        if kind == "default":
            out += ["FINAL," + spec["policy"]]
        else:
            for rule in disjuncts(converter.expression(source_expression(source))):
                guarded = Rule("AND", children=(Rule("NOT", children=(Rule("PROTOCOL", "STUN"),)), rule))
                out += [local_line(guarded, spec["policy"])]
                local_count += 1
    out += ["", "[Remote Rule]", "# Policy is bound here; the public rule lists carry no policy. Order follows Egern.",
            "# enabled=" + str(remote_rules).lower() + " is a builder flag, not a runtime availability check."]
    for item in resources:
        policy = next(iter(document["rules"][item["source_index"] - 1].values()))["policy"]
        out += [REMOTE_BASE + item["file"] + ",policy=" + policy + ",tag=" + Path(item["file"]).stem + ",enabled=" + str(remote_rules).lower()]
    out += ["", "[Host]", "# Materialized explicit business DNS; redundant same-endpoint descendants removed."]
    out += [key + " = server:" + value for key, value in hosts.items()]
    # No [MitM] section: Loon keeps MITM off unless hostname/ca-p12 are configured.
    return "\n".join(out) + "\n", {"remote_resources": len(resources), "subscriptions": len(urls), "local_rules_without_final": local_count,
                              "host_maps": len(hosts), "dns_gaps": gaps, "cached_provider_nodes": 0,
                              "omitted_local_proxies": sorted(omitted),
                              "remote_rules_enabled": remote_rules, "subscriptions_enabled": subscriptions}


def sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("[") and value.endswith("]"):
            current = value[1:-1]
            if current in result:
                raise ValueError("Duplicate Loon section")
            result[current] = []
        elif current is None:
            raise ValueError("Loon entry outside a section")
        else:
            result[current].append(value)
    return result


def check_config(text: str, root: Path) -> list[str]:
    """Structural native checks; never include private line contents in diagnostics."""
    errors = []
    try:
        area = sections(text)
        required = {"General", "Remote Proxy", "Remote Filter", "Proxy Group", "Rule", "Remote Rule", "Host"}
        optional = {"Proxy", "MitM", "MITM"}
        if not required <= set(area) or set(area) - required - optional:
            raise ValueError("Unexpected section set")
        if {x.split("=", 1)[0].strip() for x in area["General"]} != GENERAL_FIELDS:
            raise ValueError("Unexpected General fields")
        names = {x.split("=", 1)[0].strip() for key in ("Proxy", "Remote Proxy", "Remote Filter", "Proxy Group") if key in area for x in area[key]}
        expected_count = sum(len(area[x]) for x in ("Proxy", "Remote Proxy", "Remote Filter", "Proxy Group") if x in area)
        if len(names) != expected_count:
            raise ValueError("Duplicate policy/filter/node name")
        dependencies = {}
        for line in area["Proxy Group"]:
            name, value = line.split("=", 1)
            fields = split_fields(value)
            if fields[0] != "select":
                raise ValueError("Only manual groups are permitted")
            dependencies[name.strip()] = [x for x in fields[1:] if "=" not in x]
        for line in area["Remote Filter"]:
            name, value = line.split("=", 1)
            fields = split_fields(value)
            if fields[0] != "NameRegex":
                raise ValueError("Expected native NameRegex filter")
            dependencies[name.strip()] = [x for x in fields[1:] if "=" not in x]
            pattern = next(x.split("=", 1)[1].strip().strip('"') for x in fields if x.startswith("FilterKey="))
            re.compile(pattern)
        def visit(name: str, trail: set[str]) -> None:
            if name in trail:
                raise ValueError("Policy reference cycle")
            for child in dependencies.get(name, []):
                if child not in names | {"DIRECT", "REJECT"}:
                    raise ValueError("Unknown policy reference")
                visit(child, trail | {name})
        for name in dependencies:
            visit(name, set())
        for line in area["Rule"]:
            fields = split_fields(line)
            if fields[0] == "FINAL":
                policy = fields[-1]
            else:
                nr = fields[-1] == "no-resolve"
                policy = fields[-2] if nr else fields[-1]
                condition = ",".join(fields[:-2] if nr else fields[:-1]) + (",no-resolve" if nr else "")
                parse_native(condition)
            if policy not in names | {"DIRECT", "REJECT"}:
                raise ValueError("Unknown local policy")
        if not area["Rule"][-1].startswith("FINAL,"):
            raise ValueError("FINAL must be last local rule")
        expected_paths = {x["file"] for x in manifest(root)}
        actual_paths = []
        for line in area["Remote Rule"]:
            fields = split_fields(line)
            if not fields[0].startswith(REMOTE_BASE):
                raise ValueError("Unreviewed remote rules URL")
            actual_paths.append(fields[0][len(REMOTE_BASE):])
            options = dict(x.split("=", 1) for x in fields[1:])
            if options["policy"] not in names | {"DIRECT", "REJECT"} or options["enabled"] not in {"true", "false"}:
                raise ValueError("Invalid remote binding")
        if set(actual_paths) != expected_paths or actual_paths != [x["file"] for x in manifest(root)]:
            raise ValueError("Remote rules omitted, duplicated or reordered")
        for line in area["Remote Proxy"]:
            _, value = line.split("=", 1)
            fields = split_fields(value)
            url = urlsplit(fields[0])
            if url.scheme != "https" or not url.hostname:
                raise ValueError("Invalid subscription URL")
            options = dict(x.split("=", 1) for x in fields[1:])
            if options.get("parser-enabled") != "false" or options.get("skip-cert-verify") != "default" or options.get("udp") != "default":
                raise ValueError("Subscription must preserve node settings without parser")
            if not options.get("server-dns", "").startswith('"'):
                raise ValueError("Node DNS list must be quoted")
        mitm = area.get("MitM") or area.get("MITM")
        if mitm:
            for line in mitm:
                if line.split("=", 1)[0].strip() not in {"hostname", "ca-p12", "ca-passphrase", "skip-server-cert-verify"}:
                    raise ValueError("Unreviewed MITM setting")
        for line in area["Host"]:
            key, value = line.split("=", 1)
            if not key.strip() or not value.strip().startswith("server:"):
                raise ValueError("Invalid Host DNS mapping")
    except (ValueError, KeyError, StopIteration):
        errors.append("Loon native config structure/reference check failed; inspect locally without printing secrets")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--enable-remote-rules", action="store_true", help="Only after separate publication verification")
    parser.add_argument("--enable-subscriptions", action="store_true", help="Only after separately authorized native response verification")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.output.resolve().is_relative_to(root.resolve()) or args.source.resolve().is_relative_to(root.resolve()):
        parser.error("Private input/output must stay outside the public Rules repository")
    try:
        text, summary = build_config(load_yaml(args.source), root, remote_rules=args.enable_remote_rules, subscriptions=args.enable_subscriptions)
        errors = check_config(text, root)
        if args.check and (not args.output.is_file() or args.output.read_text(encoding="utf-8-sig") != text):
            errors.append("Private Loon candidate differs from current source; regenerate after review")
        if errors:
            print("\n".join(errors))
            return 1
        if not args.check:
            args.output.write_text(text, encoding="utf-8", newline="\n")
        print("OK: native Loon " + ("candidate checked" if args.check else "candidate written") +
              f"; {summary['subscriptions']} unverified subscriptions, {summary['remote_resources']} planned rule resources, " +
              f"{summary['host_maps']} Host maps; no network requests")
        return 0
    except (ValueError, KeyError, OSError):
        print("FAILED: source/manifest mismatch or unsupported native setting; inspect private source locally")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
