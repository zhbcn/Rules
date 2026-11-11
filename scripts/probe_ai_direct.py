#!/usr/bin/env python3
"""Manually probe public AI entry points through a specified physical Windows NIC.

Uses IP_UNICAST_IF for both pinned AliDNS DoH and HTTPS, verifies TLS, rejects
private/fake DNS addresses, follows only reviewed-host redirects, reads at most
16 KiB per response, and never sends credentials or invokes model generation.
A successful public page is NOT a successful login or model/API call.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import http.client
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urljoin, urlsplit


def decode_a(data: bytes, ident: int) -> list[str]:
    if len(data) < 12:
        raise ValueError('Truncated DNS header')
    header = struct.unpack('!6H', data[:12])
    if header[0] != ident or not header[1] & 0x8000 or header[1] & 0x020F:
        raise ValueError('Invalid, truncated or unsuccessful DNS response')
    def skip(pos: int) -> int:
        while data[pos]:
            if data[pos] & 0xC0 == 0xC0:
                return pos + 2
            if data[pos] & 0xC0:
                raise ValueError('Invalid DNS label')
            pos += data[pos] + 1
        return pos + 1
    pos = 12
    for _ in range(header[2]):
        pos = skip(pos) + 4
    ips = []
    for _ in range(header[3]):
        pos = skip(pos)
        typ, cls, _, size = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        if typ == 1 and cls == 1 and size == 4:
            ips.append(socket.inet_ntoa(data[pos:pos + size]))
        pos += size
    if not ips or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip) in ipaddress.ip_network('198.18.0.0/15') for ip in ips):
        raise ValueError('No public A records; reject private, loopback and fake-IP answers')
    return list(dict.fromkeys(ips))


def classification(status: int, body: str) -> str:
    if any(x in body.lower() for x in ['unsupported country', 'not available in your region', 'not available in your country', 'geo-restricted', 'cf-chl-']):
        return 'restricted_or_challenged'
    if status in (200, 206):
        return 'public_entry_reachable'
    if status == 401:
        return 'authentication_required_only'
    if status == 403:
        return 'forbidden_not_validated'
    if status == 404:
        return 'server_reachable_path_not_validated'
    if 300 <= status < 400:
        return 'redirect_not_completed'
    return 'http_error_not_validated'


class DirectProbe:
    def __init__(self, interface: int, source: str, timeout: float, allowed: set[str]):
        self.interface, self.source, self.timeout, self.allowed = interface, source, timeout, allowed

    def connect(self, ip: str, host: str) -> ssl.SSLSocket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(self.timeout)
            s.setsockopt(socket.IPPROTO_IP, 31, struct.pack('!I', self.interface))
            s.bind((self.source, 0))
            s.connect((ip, 443))
            return ssl.create_default_context().wrap_socket(s, server_hostname=host)
        except Exception:
            s.close()
            raise

    def resolve(self, host: str) -> list[str]:
        ident = secrets.randbelow(65536)
        query = struct.pack('!6H', ident, 0x100, 1, 0, 0, 0)
        query += b''.join(bytes([len(label)]) + label.encode('idna') for label in host.split('.')) + b'\0' + struct.pack('!2H', 1, 1)
        conn = http.client.HTTPConnection('dns.alidns.com', timeout=self.timeout)
        try:
            conn.sock = self.connect('223.5.5.5', 'dns.alidns.com')
            encoded = base64.urlsafe_b64encode(query).decode().rstrip('=')
            conn.request('GET', '/dns-query?dns=' + encoded, headers={'Accept': 'application/dns-message', 'Connection': 'close'})
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError(f'DoH HTTP {response.status}')
            return decode_a(response.read(4096), ident)
        finally:
            conn.close()

    def probe(self, url: str) -> dict:
        started = time.monotonic()
        result = {'host': urlsplit(url).hostname, 'path': urlsplit(url).path, 'hops': []}
        try:
            for _ in range(4):
                parsed = urlsplit(url)
                if parsed.scheme != 'https' or parsed.hostname not in self.allowed or parsed.port not in (None, 443) or parsed.username or parsed.password:
                    raise ValueError('Redirect outside reviewed HTTPS endpoints; review manually')
                ips = self.resolve(parsed.hostname)
                error = None
                for ip in ips[:2]:
                    conn = http.client.HTTPConnection(parsed.hostname, timeout=self.timeout)
                    try:
                        conn.sock = self.connect(ip, parsed.hostname)
                        path = parsed.path or '/'
                        if parsed.query:
                            path += '?' + parsed.query
                        headers = {'User-Agent': 'Mozilla/5.0 Rules-maintenance', 'Connection': 'close'}
                        if path.endswith(('.exe', '.dmg', '.zip')):
                            headers['Range'] = 'bytes=0-4095'
                        conn.request('GET', path, headers=headers)
                        response = conn.getresponse()
                        body = response.read(16384).decode('utf-8', errors='replace')
                        status, location = response.status, response.getheader('Location')
                        break
                    except (OSError, ValueError, http.client.HTTPException) as exc:
                        error = exc
                    finally:
                        conn.close()
                else:
                    raise error or ValueError('No reachable IP')
                hop = {'host': parsed.hostname, 'path': parsed.path or '/', 'status': status, 'dns_ips': ips}
                result['hops'].append(hop)
                result['classification'] = classification(status, body)
                if status in (301, 302, 303, 307, 308) and location:
                    url = urljoin(url, location)
                    target = urlsplit(url)
                    hop['redirect_host'] = target.hostname
                    hop['redirect_path'] = target.path
                    continue
                title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
                result['title'] = re.sub(r'\s+', ' ', title[1])[:160] if title else ''
                break
            else:
                result['classification'] = 'redirect_limit_not_validated'
        except (OSError, ValueError, IndexError, struct.error, http.client.HTTPException) as exc:
            result.update(classification='transport_or_dns_not_validated', error=f'{type(exc).__name__}: {exc}')
        result['seconds'] = round(time.monotonic() - started, 2)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface-index', type=int, required=True)
    parser.add_argument('--source-ip', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--service', action='append', default=[])
    parser.add_argument('--include-exceptions', action='store_true', help='Also probe the catalogued proxy exceptions; never changes their policies')
    parser.add_argument('--timeout', type=float, default=7)
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('Windows IP_UNICAST_IF is required; no unbound fallback')
    if args.interface_index <= 0 or args.timeout <= 0:
        parser.error('Interface index and timeout must be positive')
    ipaddress.IPv4Address(args.source_ip)
    manifest = json.loads(Path(__file__).with_name('ai_services.json').read_text(encoding='utf-8'))
    services = manifest['services']
    unknown = set(args.service) - {s['name'] for s in services}
    if unknown:
        parser.error('Unknown service: ' + ', '.join(sorted(unknown)))
    urls = list(dict.fromkeys(u for s in services if not args.service or s['name'] in args.service for u in s['probe_urls']))
    if args.include_exceptions:
        urls = list(dict.fromkeys(urls + manifest.get('exception_probe_urls', [])))
    allowed = {urlsplit(u).hostname for s in services for u in s['probe_urls']}
    allowed.update(urlsplit(u).hostname for u in manifest.get('exception_probe_urls', []))
    probe = DirectProbe(args.interface_index, args.source_ip, args.timeout, allowed)
    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(probe.probe, urls))
    assert len(rows) == len(urls)
    report = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'transport': 'Windows IP_UNICAST_IF physical interface; pinned AliDNS DoH; verified TLS', 'scope': 'Public entry points only; no authenticated requests or model calls; no automatic routing decisions', 'count': len(rows), 'results': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    for row in rows:
        print(row['host'], row['path'], row['classification'], [h['status'] for h in row['hops']])
    print(f'Saved {len(rows)} results to {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
