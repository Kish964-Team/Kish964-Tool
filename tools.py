#!/usr/bin/env python3
"""
Kish964 v3.0 – Advanced Origin IP Discovery Framework
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Multi-vector WAF bypass and origin IP discovery with HTTP verification,
cloud provider awareness, ASN enrichment, and deep OSINT integration.

New in v3.0 vs v2.0:
  ✦ HTTP origin verification  – probe IPs with Host: header to confirm
    they actually serve the target site (title/content fingerprint match)
  ✦ Cloud provider CIDRs      – AWS, GCP, Azure, DigitalOcean, Linode,
    Vultr, Hetzner added alongside existing WAF vendors
  ✦ Zone transfer (AXFR)      – attempt DNS zone transfers on discovered
    NS servers; silently skipped on failure
  ✦ Wildcard detection        – auto-detect wildcard DNS and filter noise
  ✦ ASN / GeoIP enrichment    – tag each origin IP with org, ASN, country
  ✦ Reverse DNS               – PTR lookup on every discovered IP
  ✦ Direct IP SSL cert grab   – pull CN + SANs from IP:443 to find more
    subdomains without going through the CDN
  ✦ Additional OSINT sources  – URLScan.io, BufferOver.run, AlienVault OTX
  ✦ SPF flattening            – recursively resolve SPF include: chains
  ✦ Exponential back-off retry on transient errors
  ✦ Rate-limit / 429 handling with automatic pause & resume
  ✦ Rich scan summary with origin confidence scores
  ✦ Config file support       – ~/.kish964.toml

Usage:
  python3 kish964.py example.com -w wordlist.txt
  python3 kish964.py example.com -w subs.txt --historical --verify-http --check-favicon
  python3 kish964.py example.com -w subs.txt --shodan-key YOUR_KEY -o out.json -f json
  python3 kish964.py example.com -w subs.txt --axfr --wildcard-check --asn-lookup
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# ── Third-party (pip install aiohttp aiodns rich pyfiglet mmh3 tomli) ───────
try:
    import aiohttp
    import aiodns
    import pyfiglet
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
except ImportError as exc:
    print(
        f"[ERROR] Missing dependency: {exc}\n"
        "Install with: pip install aiohttp aiodns rich pyfiglet mmh3"
    )
    sys.exit(1)

try:
    import mmh3  # type: ignore
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

# tomli for config files (Python < 3.11 doesn't have tomllib in stdlib)
try:
    import tomllib  # type: ignore  (Python 3.11+)
    _HAS_TOML = True
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
        _HAS_TOML = True
    except ImportError:
        _HAS_TOML = False

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Version
# ─────────────────────────────────────────────────────────────────────────────
VERSION = "3.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# MurmurHash3 pure-Python fallback (32-bit signed, matches Shodan)
# ─────────────────────────────────────────────────────────────────────────────

def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h = seed
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    tail_size = length & 3
    if tail_size >= 3:
        k ^= tail[2] << 16
    if tail_size >= 2:
        k ^= tail[1] << 8
    if tail_size >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return struct.unpack("i", struct.pack("I", h))[0]


def favicon_hash(data: bytes) -> int:
    b64 = base64.encodebytes(data).decode()
    if _HAS_MMH3:
        return mmh3.hash(b64)
    return _murmur3_32(b64.encode())


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

class OutputFormat(Enum):
    NORMAL = "normal"
    JSON   = "json"
    CSV    = "csv"


@dataclass
class IPMeta:
    """Enrichment data for a single IP address."""
    ip: str
    ptr:          Optional[str]  = None   # Reverse DNS
    asn:          Optional[str]  = None   # e.g. "AS13335"
    org:          Optional[str]  = None   # e.g. "Cloudflare, Inc."
    country:      Optional[str]  = None   # e.g. "US"
    city:         Optional[str]  = None
    ssl_cns:      list[str]      = field(default_factory=list)   # SANs from direct TLS
    http_verified: bool          = False  # Did HTTP probe confirm origin?
    http_status:  Optional[int]  = None
    http_title:   Optional[str]  = None
    confidence:   int            = 0      # 0-100 confidence this is origin


@dataclass
class DNSResult:
    domain:     str
    ipv4:       list[str] = field(default_factory=list)
    ipv6:       list[str] = field(default_factory=list)
    mx:         list[str] = field(default_factory=list)
    txt:        list[str] = field(default_factory=list)
    ns:         list[str] = field(default_factory=list)
    status:     str       = "unknown"
    waf_ips:    list[str] = field(default_factory=list)
    waf_vendor: dict[str, str] = field(default_factory=dict)
    cloud_ips:  list[str] = field(default_factory=list)
    cloud_vendor: dict[str, str] = field(default_factory=dict)
    ip_meta:    dict[str, IPMeta] = field(default_factory=dict)
    error:      Optional[str] = None

    @property
    def all_ips(self) -> list[str]:
        return self.ipv4 + self.ipv6

    @property
    def origin_ips(self) -> list[str]:
        protected = set(self.waf_ips)
        return [ip for ip in self.all_ips if ip not in protected]

    @property
    def has_origin_ip(self) -> bool:
        return bool(self.origin_ips)

    @property
    def all_waf(self) -> bool:
        if not self.all_ips:
            return False
        return all(ip in self.waf_ips for ip in self.all_ips)

    @property
    def verified_origin_ips(self) -> list[str]:
        return [
            ip for ip in self.origin_ips
            if self.ip_meta.get(ip, IPMeta(ip)).http_verified
        ]


@dataclass
class OSINTEntry:
    source: str
    domain: str
    ip:     Optional[str] = None
    extra:  Optional[str] = None


@dataclass
class ZoneTransferResult:
    nameserver: str
    domain:     str
    success:    bool
    records:    list[str] = field(default_factory=list)
    error:      Optional[str] = None


@dataclass
class ScanReport:
    target:       str
    scan_date:    str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_checked: int = 0
    found:          list[DNSResult]         = field(default_factory=list)
    waf_protected:  list[DNSResult]         = field(default_factory=list)
    not_found:      list[DNSResult]         = field(default_factory=list)
    errors:         list[DNSResult]         = field(default_factory=list)
    osint:          list[OSINTEntry]        = field(default_factory=list)
    mail_leaks:     list[DNSResult]         = field(default_factory=list)
    zone_transfers: list[ZoneTransferResult] = field(default_factory=list)
    wildcard_ips:   list[str]               = field(default_factory=list)
    favicon_hash:       Optional[int] = None
    favicon_shodan_query: Optional[str] = None
    crt_subdomains:     list[str]     = field(default_factory=list)
    scan_duration:      float         = 0.0

    @property
    def summary(self) -> dict:
        verified = sum(1 for r in self.found if r.verified_origin_ips)
        return {
            "found_origin":      len(self.found),
            "verified_origin":   verified,
            "waf_protected":     len(self.waf_protected),
            "not_found":         len(self.not_found),
            "errors":            len(self.errors),
            "osint_entries":     len(self.osint),
            "mail_leaks":        len(self.mail_leaks),
            "zone_transfers_ok": sum(1 for z in self.zone_transfers if z.success),
        }

    def to_dict(self) -> dict:
        def _dns(r: DNSResult) -> dict:
            d = asdict(r)
            # ip_meta dataclass keys → plain dicts
            d["ip_meta"] = {k: asdict(v) for k, v in r.ip_meta.items()}
            return d

        return {
            "target":       self.target,
            "scan_date":    self.scan_date,
            "scan_duration_s": round(self.scan_duration, 2),
            "total_checked": self.total_checked,
            "summary":      self.summary,
            "wildcard_ips": self.wildcard_ips,
            "favicon_hash": self.favicon_hash,
            "favicon_shodan_query": self.favicon_shodan_query,
            "crt_subdomains": self.crt_subdomains,
            "dns_results": {
                "found_origin":  [_dns(r) for r in self.found],
                "waf_protected": [_dns(r) for r in self.waf_protected],
                "not_found":     [_dns(r) for r in self.not_found],
                "errors":        [_dns(r) for r in self.errors],
            },
            "mail_leaks":     [asdict(r) for r in self.mail_leaks],
            "zone_transfers": [asdict(z) for z in self.zone_transfers],
            "osint":          [asdict(e) for e in self.osint],
        }


# ─────────────────────────────────────────────────────────────────────────────
# WAF + Cloud CIDR Manager
# ─────────────────────────────────────────────────────────────────────────────

class CIDRManager:
    """
    Fetches and caches CIDR ranges for WAF vendors AND cloud providers.
    Falls back to embedded static lists if network requests fail.
    Cloud IPs are informational (not treated as WAF); WAF IPs are filtered
    from origin candidate lists.
    """

    # ── Cloudflare ──────────────────────────────────────────────────────────
    CF_V4_URL = "https://www.cloudflare.com/ips-v4"
    CF_V6_URL = "https://www.cloudflare.com/ips-v6"
    CF_V4_FALLBACK = [
        "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
        "104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
        "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15",
        "172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
        "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
    ]
    CF_V6_FALLBACK = [
        "2400:cb00::/32","2606:4700::/32","2803:f800::/32",
        "2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
    ]

    # ── Akamai ──────────────────────────────────────────────────────────────
    AKAMAI_V4 = [
        "23.32.0.0/11","23.192.0.0/11","23.64.0.0/14",
        "72.246.0.0/15","92.122.0.0/15","95.100.0.0/15",
        "96.16.0.0/15","96.6.0.0/15",
    ]

    # ── Fastly ──────────────────────────────────────────────────────────────
    FASTLY_URL = "https://api.fastly.com/public-ip-list"
    FASTLY_V4_FALLBACK = [
        "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24",
        "103.245.222.0/23","104.156.80.0/20","140.248.64.0/18",
        "140.248.128.0/17","146.75.0.0/16","151.101.0.0/16",
        "157.52.64.0/18","167.82.0.0/17","172.111.64.0/18",
        "185.31.16.0/22","199.27.72.0/21","199.232.0.0/16",
    ]

    # ── Incapsula / Imperva ─────────────────────────────────────────────────
    INCAPSULA_V4 = [
        "199.83.128.0/21","198.143.32.0/19","149.126.72.0/21",
        "103.28.248.0/22","45.64.64.0/22","185.11.124.0/22",
        "192.230.64.0/18","107.154.0.0/16","45.60.0.0/16",
        "45.223.0.0/16",
    ]

    # ── AWS (sampled; full list from ip-ranges.amazonaws.com) ───────────────
    AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    AWS_V4_FALLBACK = [
        "3.0.0.0/9","13.32.0.0/15","13.224.0.0/14","13.248.0.0/16",
        "15.177.0.0/18","18.64.0.0/10","34.192.0.0/10",
        "35.152.0.0/13","52.0.0.0/8","54.0.0.0/8","99.77.128.0/18",
        "143.204.0.0/16","204.246.160.0/22","205.251.192.0/19",
    ]

    # ── GCP ─────────────────────────────────────────────────────────────────
    GCP_V4_FALLBACK = [
        "8.34.208.0/20","8.35.192.0/20","23.236.48.0/20","23.251.128.0/19",
        "34.0.0.0/8","35.184.0.0/14","35.188.0.0/15","35.191.0.0/16",
        "35.192.0.0/14","35.196.0.0/15","35.198.0.0/16","35.200.0.0/14",
        "35.204.0.0/14","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19",
        "72.14.192.0/18","74.125.0.0/16","104.154.0.0/15","104.196.0.0/14",
        "107.167.160.0/19","107.178.192.0/18","108.59.80.0/20",
        "108.170.192.0/18","108.177.0.0/17","130.211.0.0/16","142.250.0.0/15",
        "162.216.148.0/22","172.217.0.0/16","173.194.0.0/16","209.85.128.0/17",
        "216.239.32.0/19","216.252.220.0/22",
    ]

    # ── Azure ────────────────────────────────────────────────────────────────
    AZURE_V4_FALLBACK = [
        "13.64.0.0/11","13.96.0.0/13","13.104.0.0/14","13.107.0.0/16",
        "20.0.0.0/6","23.96.0.0/13","40.64.0.0/10","51.4.0.0/15",
        "51.8.0.0/16","51.10.0.0/15","51.18.0.0/16","51.51.0.0/16",
        "51.53.0.0/16","51.103.0.0/16","51.104.0.0/15","51.107.0.0/16",
        "51.116.0.0/16","51.120.0.0/16","52.96.0.0/12","52.112.0.0/14",
        "52.168.0.0/13","52.184.0.0/14","65.52.0.0/14","104.40.0.0/13",
        "104.208.0.0/13","137.116.0.0/15","168.61.0.0/16","168.62.0.0/15",
        "191.232.0.0/13",
    ]

    # ── DigitalOcean ─────────────────────────────────────────────────────────
    DO_V4_FALLBACK = [
        "45.55.0.0/16","67.205.128.0/17","104.131.0.0/16","104.236.0.0/16",
        "138.197.0.0/16","138.68.0.0/16","139.59.0.0/16","157.245.0.0/16",
        "159.65.0.0/16","159.89.0.0/16","161.35.0.0/16","164.90.0.0/16",
        "165.22.0.0/16","167.71.0.0/16","167.99.0.0/16","174.138.0.0/16",
        "178.128.0.0/16","188.166.0.0/16","192.241.128.0/17",
        "198.199.64.0/18","206.81.0.0/18","209.97.128.0/17",
    ]

    # ── Hetzner ──────────────────────────────────────────────────────────────
    HETZNER_V4_FALLBACK = [
        "5.9.0.0/16","5.161.0.0/16","23.88.0.0/16","65.109.0.0/16",
        "78.46.0.0/16","88.198.0.0/16","128.140.0.0/16","159.69.0.0/16",
        "162.55.0.0/16","167.235.0.0/16","168.119.0.0/16","176.9.0.0/16",
        "178.63.0.0/16","185.11.144.0/22","195.201.0.0/16","213.133.96.0/19",
    ]

    # WAF vendors (used for origin filtering)
    _WAF_KEYS = {"Cloudflare", "Akamai", "Fastly", "Incapsula"}

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._networks:  dict[str, list[IPv4Network | IPv6Network]] = {}
        self._loaded = False

    async def load(self, session: aiohttp.ClientSession) -> None:
        if self._loaded:
            return

        cf_v4  = await self._fetch_lines(session, self.CF_V4_URL, self.CF_V4_FALLBACK)
        cf_v6  = await self._fetch_lines(session, self.CF_V6_URL, self.CF_V6_FALLBACK)
        fastly = await self._fetch_fastly(session)
        aws    = await self._fetch_aws(session)

        raw: dict[str, list[str]] = {
            "Cloudflare": cf_v4 + cf_v6,
            "Akamai":     self.AKAMAI_V4,
            "Fastly":     fastly,
            "Incapsula":  self.INCAPSULA_V4,
            "AWS":        aws,
            "GCP":        self.GCP_V4_FALLBACK,
            "Azure":      self.AZURE_V4_FALLBACK,
            "DigitalOcean": self.DO_V4_FALLBACK,
            "Hetzner":    self.HETZNER_V4_FALLBACK,
        }

        self._networks = {}
        for vendor, cidrs in raw.items():
            parsed = [self._parse(c) for c in cidrs if c]
            self._networks[vendor] = [n for n in parsed if n is not None]
        self._loaded = True

    async def _fetch_lines(
        self, session: aiohttp.ClientSession, url: str, fallback: list[str]
    ) -> list[str]:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as r:
                r.raise_for_status()
                text = await r.text()
                return [l.strip() for l in text.splitlines() if l.strip()]
        except Exception:
            return fallback

    async def _fetch_fastly(self, session: aiohttp.ClientSession) -> list[str]:
        try:
            async with session.get(
                self.FASTLY_URL, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as r:
                r.raise_for_status()
                data = await r.json(content_type=None)
                return data.get("addresses", []) + data.get("ipv6_addresses", [])
        except Exception:
            return self.FASTLY_V4_FALLBACK

    async def _fetch_aws(self, session: aiohttp.ClientSession) -> list[str]:
        """Fetch AWS CLOUDFRONT + GLOBAL_ACCELERATOR ranges from ip-ranges.json."""
        try:
            async with session.get(
                self.AWS_IP_RANGES_URL,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                r.raise_for_status()
                data = await r.json(content_type=None)
                cdn_services = {"CLOUDFRONT", "GLOBALACCELERATOR"}
                return [
                    p["ip_prefix"]
                    for p in data.get("prefixes", [])
                    if p.get("service") in cdn_services
                ]
        except Exception:
            return self.AWS_V4_FALLBACK

    @staticmethod
    def _parse(cidr: str) -> Optional[IPv4Network | IPv6Network]:
        for cls in (IPv4Network, IPv6Network):
            try:
                return cls(cidr, strict=False)
            except ValueError:
                continue
        return None

    def classify_ip(self, ip: str) -> tuple[Optional[str], bool]:
        """
        Returns (vendor_name, is_waf_vendor).
        vendor_name is None if the IP is not in any known range.
        is_waf_vendor is True only for CDN/WAF vendors (not generic cloud).
        """
        try:
            addr: IPv4Address | IPv6Address = IPv4Address(ip)
        except AddressValueError:
            try:
                addr = IPv6Address(ip)
            except AddressValueError:
                return None, False

        for vendor, nets in self._networks.items():
            for net in nets:
                try:
                    if addr in net:
                        return vendor, vendor in self._WAF_KEYS
                except TypeError:
                    continue
        return None, False

    def vendor_for_ip(self, ip: str) -> Optional[str]:
        vendor, _ = self.classify_ip(ip)
        return vendor

    def is_waf_ip(self, ip: str) -> bool:
        _, is_waf = self.classify_ip(ip)
        return is_waf


# ─────────────────────────────────────────────────────────────────────────────
# ASN / GeoIP enrichment  (uses ip-api.com free tier – no key required)
# ─────────────────────────────────────────────────────────────────────────────

class ASNEnricher:
    """
    Batch-enriches a list of IP addresses with ASN, org, country, and city data
    via the ip-api.com /batch endpoint (free; max 100 per request, 15 req/min).
    Falls back gracefully if the API is unavailable.
    """

    BATCH_URL = "http://ip-api.com/batch"
    FIELDS    = "query,org,as,countryCode,city,status"
    MAX_BATCH = 100

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        self.session = session
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._cache: dict[str, dict] = {}

    async def enrich(self, ips: list[str]) -> dict[str, dict]:
        """Return {ip: {org, asn, country, city}} for all supplied IPs."""
        unique = [ip for ip in dict.fromkeys(ips) if ip not in self._cache]
        for i in range(0, len(unique), self.MAX_BATCH):
            batch = unique[i : i + self.MAX_BATCH]
            await self._fetch_batch(batch)
            # Rate-limit: ip-api free tier allows 15 req/min
            if i + self.MAX_BATCH < len(unique):
                await asyncio.sleep(4)
        return {ip: self._cache.get(ip, {}) for ip in ips}

    async def _fetch_batch(self, ips: list[str]) -> None:
        payload = [{"query": ip, "fields": self.FIELDS} for ip in ips]
        try:
            async with self.session.post(
                self.BATCH_URL, json=payload, timeout=self.timeout
            ) as r:
                if r.status == 429:
                    await asyncio.sleep(60)
                    return
                r.raise_for_status()
                results: list[dict] = await r.json(content_type=None)
                for entry in results:
                    ip = entry.get("query", "")
                    if entry.get("status") == "success":
                        self._cache[ip] = {
                            "org":     entry.get("org", ""),
                            "asn":     entry.get("as", ""),
                            "country": entry.get("countryCode", ""),
                            "city":    entry.get("city", ""),
                        }
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Origin Verifier
# ─────────────────────────────────────────────────────────────────────────────

class HTTPVerifier:
    """
    Directly probes candidate origin IPs using:
      • HTTPS / HTTP with Host: <target_domain> header
      • Extracts <title> and a content fingerprint
      • Compares against the canonical response from the CDN-fronted domain
      • Returns a confidence score (0-100)
    
    A response is considered verified if:
      - HTTP status is 200 / 301 / 302 / 401 / 403
      - Title or content hash partially matches the canonical site
    """

    CANONICAL_TIMEOUT = 10
    PROBE_TIMEOUT     = 8
    PORTS             = [443, 80, 8443, 8080]
    _TITLE_RE         = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

    def __init__(self, session: aiohttp.ClientSession, domain: str):
        self.session   = session
        self.domain    = domain
        self._canonical_title: Optional[str]  = None
        self._canonical_hash:  Optional[str]  = None
        self._canonical_fetched = False

    async def fetch_canonical(self) -> None:
        """Fetch the canonical site response for baseline comparison."""
        if self._canonical_fetched:
            return
        self._canonical_fetched = True
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{self.domain}/"
                async with self.session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.CANONICAL_TIMEOUT),
                    allow_redirects=True,
                    ssl=False,
                ) as r:
                    body = await r.text(errors="replace")
                    m = self._TITLE_RE.search(body)
                    self._canonical_title = m.group(1).strip() if m else ""
                    # Hash first 4 KB of body (skip dynamic timestamps etc.)
                    snippet = re.sub(r"\s+", " ", body[:4096])
                    self._canonical_hash = hashlib.sha1(snippet.encode()).hexdigest()[:12]
                    return
            except Exception:
                pass

    async def verify_ip(self, ip: str) -> IPMeta:
        """Probe all ports on *ip* with Host header set to target domain."""
        meta = IPMeta(ip=ip)
        await self.fetch_canonical()

        for port in self.PORTS:
            scheme = "https" if port in (443, 8443) else "http"
            url    = f"{scheme}://{ip}:{port}/"
            headers = {
                "Host":            self.domain,
                "User-Agent":      "Mozilla/5.0 (compatible; Kish964/3.0)",
                "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection":      "close",
            }
            try:
                async with self.session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.PROBE_TIMEOUT),
                    allow_redirects=True,
                    ssl=False,
                ) as r:
                    meta.http_status = r.status
                    if r.status in (200, 206, 301, 302, 307, 308, 401, 403):
                        body = await r.text(errors="replace")
                        m = self._TITLE_RE.search(body)
                        meta.http_title = m.group(1).strip()[:120] if m else ""

                        score = self._score(r.status, body)
                        if score > meta.confidence:
                            meta.confidence = score
                        if score >= 40:
                            meta.http_verified = True
                            break
            except Exception:
                pass

        return meta

    def _score(self, status: int, body: str) -> int:
        """Compute a confidence score 0-100 that this IP is the origin."""
        score = 0
        # Status match
        if status == 200:
            score += 20
        elif status in (301, 302, 307, 308, 401, 403):
            score += 10

        # Title similarity
        if self._canonical_title and self._canonical_title.strip():
            m = self._TITLE_RE.search(body)
            title = m.group(1).strip() if m else ""
            if title and self._canonical_title:
                # Rough Jaccard similarity on words
                a = set(self._canonical_title.lower().split())
                b = set(title.lower().split())
                if a and b:
                    jaccard = len(a & b) / len(a | b)
                    score += int(jaccard * 40)

        # Content hash similarity
        if self._canonical_hash:
            snippet = re.sub(r"\s+", " ", body[:4096])
            h = hashlib.sha1(snippet.encode()).hexdigest()[:12]
            if h == self._canonical_hash:
                score += 40
            # Partial match: first 6 chars
            elif h[:6] == self._canonical_hash[:6]:
                score += 20

        return min(score, 100)


# ─────────────────────────────────────────────────────────────────────────────
# Direct IP SSL Certificate Grabber
# ─────────────────────────────────────────────────────────────────────────────

class SSLCertGrabber:
    """
    Connects directly to IP:443 (bypassing DNS) and extracts the TLS
    certificate's CN and Subject Alternative Names (SANs).
    These often reveal the real hostname / panel subdomain of the origin.
    """

    TIMEOUT = 5

    @staticmethod
    async def grab(ip: str, port: int = 443) -> list[str]:
        """Return list of CN + SAN DNS names from the certificate at ip:port."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, SSLCertGrabber._grab_sync, ip, port),
                timeout=SSLCertGrabber.TIMEOUT + 1,
            )
        except Exception:
            return []

    @staticmethod
    def _grab_sync(ip: str, port: int) -> list[str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        names: list[str] = []
        try:
            with socket.create_connection((ip, port), timeout=SSLCertGrabber.TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    # Subject CN
                    for field in cert.get("subject", []):
                        for k, v in field:
                            if k == "commonName":
                                names.append(v)
                    # SANs
                    for san_type, san_val in cert.get("subjectAltName", []):
                        if san_type == "DNS":
                            names.append(san_val)
        except Exception:
            pass
        return list(dict.fromkeys(names))  # deduplicate, preserve order


# ─────────────────────────────────────────────────────────────────────────────
# Async DNS Resolver  (with wildcard detection + AXFR)
# ─────────────────────────────────────────────────────────────────────────────

class DNSResolver:

    _DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def __init__(
        self,
        cidr_mgr: CIDRManager,
        nameservers: Optional[list[str]] = None,
    ):
        self.cidr = cidr_mgr
        self.nameservers = nameservers or self._DEFAULT_NAMESERVERS

    def _make_resolver(self, loop: asyncio.AbstractEventLoop) -> aiodns.DNSResolver:
        return aiodns.DNSResolver(loop=loop, nameservers=self.nameservers)

    # ── Wildcard detection ────────────────────────────────────────────────────

    async def detect_wildcard(self, domain: str) -> list[str]:
        """
        Resolve a random, definitely-nonexistent subdomain.
        If it resolves, the domain uses wildcard DNS — return those IPs so
        the main scan can filter them as false positives.
        """
        import random, string
        rand = "".join(random.choices(string.ascii_lowercase, k=18))
        probe = f"{rand}.{domain}"
        loop = asyncio.get_event_loop()
        resolver = self._make_resolver(loop)
        ips: list[str] = []
        try:
            answers = await resolver.query_dns(probe, "A")
            ips = [a.host for a in answers]
        except Exception:
            pass
        if ips:
            console.print(
                f"[yellow][WILDCARD] {domain} has wildcard DNS → {', '.join(ips)} "
                f"(these will be filtered from results)[/yellow]"
            )
        return ips

    # ── Zone Transfer ─────────────────────────────────────────────────────────

    async def attempt_axfr(self, domain: str) -> list[ZoneTransferResult]:
        """
        Query NS records for *domain*, then attempt an AXFR zone transfer
        against each nameserver. Results are returned regardless of success.
        """
        results: list[ZoneTransferResult] = []
        loop = asyncio.get_event_loop()
        resolver = self._make_resolver(loop)

        # Get NS records
        ns_hosts: list[str] = []
        try:
            answers = await resolver.query_dns(domain, "NS")
            ns_hosts = [a.host for a in answers]
        except Exception:
            pass

        for ns in ns_hosts:
            result = await self._try_axfr(domain, ns)
            results.append(result)
            if result.success:
                console.print(
                    f"[bright_red bold][AXFR] Zone transfer SUCCESS on {ns}! "
                    f"{len(result.records)} records[/bright_red bold]"
                )
        return results

    @staticmethod
    async def _try_axfr(domain: str, ns_host: str) -> ZoneTransferResult:
        """Attempt a TCP AXFR request and parse the raw response."""
        loop = asyncio.get_event_loop()
        try:
            ns_ip = await loop.run_in_executor(
                None, lambda: socket.gethostbyname(ns_host)
            )
        except Exception:
            return ZoneTransferResult(ns_host, domain, False, error="NS lookup failed")

        # Build minimal DNS AXFR query (RFC 5936)
        def build_axfr(name: str) -> bytes:
            tid = 0x1337
            flags = 0x0000          # Standard query
            qdcount = 1
            header = struct.pack("!HHHHHH", tid, flags, qdcount, 0, 0, 0)
            labels = b""
            for part in name.split("."):
                enc = part.encode()
                labels += bytes([len(enc)]) + enc
            labels += b"\x00"
            question = labels + struct.pack("!HH", 252, 1)  # QTYPE=AXFR, QCLASS=IN
            msg = header + question
            return struct.pack("!H", len(msg)) + msg             # TCP length prefix

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ns_ip, 53), timeout=5
            )
            writer.write(build_axfr(domain))
            await writer.drain()

            # Read raw response bytes (basic heuristic parsing)
            raw = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
                    if not chunk:
                        break
                    raw += chunk
            except asyncio.TimeoutError:
                pass
            writer.close()

            # Very basic: look for ASCII hostnames in the response
            records: list[str] = []
            text = raw.decode("latin-1", errors="replace")
            # Extract strings that look like FQDNs related to our domain
            pattern = re.compile(r"[a-zA-Z0-9._-]{3,63}\." + re.escape(domain))
            for m in pattern.finditer(text):
                rec = m.group(0).strip(".")
                if rec not in records:
                    records.append(rec)

            if records:
                return ZoneTransferResult(ns_host, domain, True, records=records)
            return ZoneTransferResult(ns_host, domain, False, error="No records extracted")

        except Exception as exc:
            return ZoneTransferResult(ns_host, domain, False, error=str(exc)[:80])

    # ── Main resolve ──────────────────────────────────────────────────────────

    async def resolve_all(
        self, fqdn: str, wildcard_ips: Optional[set[str]] = None
    ) -> DNSResult:
        result = DNSResult(domain=fqdn)
        loop = asyncio.get_event_loop()
        resolver = self._make_resolver(loop)

        a4, a6, mx, txt, ns = await asyncio.gather(
            self._safe(resolver, fqdn, "A"),
            self._safe(resolver, fqdn, "AAAA"),
            self._safe(resolver, fqdn, "MX"),
            self._safe(resolver, fqdn, "TXT"),
            self._safe(resolver, fqdn, "NS"),
        )

        # Filter wildcard IPs (false positives)
        if wildcard_ips:
            a4  = [ip for ip in a4 if ip not in wildcard_ips]
            a6  = [ip for ip in a6 if ip not in wildcard_ips]

        result.ipv4, result.ipv6, result.mx, result.txt, result.ns = a4, a6, mx, txt, ns

        # Classify each IP
        for ip in result.all_ips:
            vendor, is_waf = self.cidr.classify_ip(ip)
            if is_waf:
                result.waf_ips.append(ip)
                result.waf_vendor[ip] = vendor
            elif vendor:
                result.cloud_ips.append(ip)
                result.cloud_vendor[ip] = vendor

        # Status
        if not result.all_ips:
            result.status = "not_found"
        elif result.has_origin_ip:
            result.status = "found"
        elif result.all_waf:
            result.status = "waf"

        return result

    @staticmethod
    async def _safe(resolver: aiodns.DNSResolver, fqdn: str, rtype: str) -> list[str]:
        try:
            answers = await resolver.query_dns(fqdn, rtype)
            if rtype in ("A", "AAAA"):
                return [a.host for a in answers]
            if rtype == "MX":
                return [a.host for a in answers]
            if rtype == "NS":
                return [a.host for a in answers]
            if rtype == "TXT":
                out = []
                for a in answers:
                    if isinstance(a.text, (bytes, bytearray)):
                        out.append(a.text.decode(errors="replace"))
                    elif isinstance(a.text, list):
                        out.append(b"".join(a.text).decode(errors="replace"))
                    else:
                        out.append(str(a.text))
                return out
        except Exception:
            pass
        return []


# ─────────────────────────────────────────────────────────────────────────────
# OSINT Fetcher  (crt.sh, HackerTarget, URLScan, AlienVault OTX, BufferOver)
# ─────────────────────────────────────────────────────────────────────────────

class OSINTFetcher:

    CRT_SH_URL    = "https://crt.sh/?q={}&output=json"
    HTARGET_URL   = "https://api.hackertarget.com/hostsearch/?q={}"
    URLSCAN_URL   = "https://urlscan.io/api/v1/search/?q=domain:{}&size=100"
    OTX_URL       = "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns"
    BUFFEROVER_URL= "https://dns.bufferover.run/dns?q=.{}"
    RAPIDDNS_URL  = "https://rapiddns.io/subdomain/{}?full=1&down=1"

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 15):
        self.session = session
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    # ── crt.sh ───────────────────────────────────────────────────────────────

    async def fetch_crtsh(self, domain: str) -> list[OSINTEntry]:
        url = self.CRT_SH_URL.format(f"%.{domain}")
        entries: list[OSINTEntry] = []
        seen: set[str] = set()
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                r.raise_for_status()
                data: list[dict] = await r.json(content_type=None)
                for cert in data:
                    for name in cert.get("name_value", "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name and name not in seen and domain in name:
                            seen.add(name)
                            entries.append(OSINTEntry("crt.sh", name))
        except Exception as exc:
            console.print(f"[yellow][OSINT] crt.sh: {exc}[/yellow]")
        return entries

    # ── HackerTarget ─────────────────────────────────────────────────────────

    async def fetch_hackertarget(self, domain: str) -> list[OSINTEntry]:
        url = self.HTARGET_URL.format(domain)
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                r.raise_for_status()
                text = await r.text()
                if "API count exceeded" in text or "error" in text.lower():
                    console.print("[yellow][OSINT] HackerTarget rate limit[/yellow]")
                    return entries
                for line in text.splitlines():
                    parts = line.strip().split(",")
                    if len(parts) == 2:
                        entries.append(OSINTEntry("hackertarget", parts[0].strip(), ip=parts[1].strip()))
        except Exception as exc:
            console.print(f"[yellow][OSINT] HackerTarget: {exc}[/yellow]")
        return entries

    # ── URLScan.io ────────────────────────────────────────────────────────────

    async def fetch_urlscan(self, domain: str) -> list[OSINTEntry]:
        url = self.URLSCAN_URL.format(domain)
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                if r.status == 429:
                    console.print("[yellow][OSINT] URLScan rate limit[/yellow]")
                    return entries
                r.raise_for_status()
                data = await r.json(content_type=None)
                seen: set[str] = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    host = page.get("domain", "").lower()
                    ip   = page.get("ip", "")
                    if host and domain in host and host not in seen:
                        seen.add(host)
                        entries.append(OSINTEntry("urlscan", host, ip=ip or None))
        except Exception as exc:
            console.print(f"[yellow][OSINT] URLScan: {exc}[/yellow]")
        return entries

    # ── AlienVault OTX ───────────────────────────────────────────────────────

    async def fetch_otx(self, domain: str) -> list[OSINTEntry]:
        url = self.OTX_URL.format(domain)
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                if r.status in (429, 403):
                    return entries
                r.raise_for_status()
                data = await r.json(content_type=None)
                seen: set[str] = set()
                for rec in data.get("passive_dns", []):
                    host = rec.get("hostname", "").lower().strip()
                    ip   = rec.get("address", "")
                    if host and domain in host and host not in seen:
                        seen.add(host)
                        entries.append(OSINTEntry("otx", host, ip=ip or None))
        except Exception as exc:
            console.print(f"[yellow][OSINT] OTX: {exc}[/yellow]")
        return entries

    # ── BufferOver.run ────────────────────────────────────────────────────────

    async def fetch_bufferover(self, domain: str) -> list[OSINTEntry]:
        url = self.BUFFEROVER_URL.format(domain)
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(url, timeout=self.timeout) as r:
                if r.status in (429, 403):
                    return entries
                r.raise_for_status()
                data = await r.json(content_type=None)
                seen: set[str] = set()
                for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                    # format: "ip,hostname" or "hostname,ip"
                    parts = record.split(",")
                    if len(parts) == 2:
                        # Determine which part is IP
                        a, b = parts[0].strip(), parts[1].strip()
                        try:
                            IPv4Address(a)
                            ip, host = a, b
                        except ValueError:
                            ip, host = b, a
                        host = host.lower().rstrip(".")
                        if host and domain in host and host not in seen:
                            seen.add(host)
                            entries.append(OSINTEntry("bufferover", host, ip=ip or None))
        except Exception as exc:
            console.print(f"[yellow][OSINT] BufferOver: {exc}[/yellow]")
        return entries

    # ── Shodan SSL cert search ────────────────────────────────────────────────

    async def query_shodan_by_ssl(self, domain: str, api_key: str) -> list[OSINTEntry]:
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            "key":   api_key,
            "query": f'ssl.cert.subject.cn:"{domain}"',
            "facets": "ip",
        }
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(url, params=params, timeout=self.timeout) as r:
                if r.status == 401:
                    console.print("[red][Shodan] Invalid API key[/red]")
                    return entries
                r.raise_for_status()
                data = await r.json(content_type=None)
                for match in data.get("matches", []):
                    ip_str    = match.get("ip_str", "")
                    hostnames = match.get("hostnames", [])
                    entries.append(OSINTEntry(
                        "shodan_ssl",
                        ", ".join(hostnames) if hostnames else domain,
                        ip=ip_str,
                        extra=f"port:{match.get('port')}",
                    ))
        except Exception as exc:
            console.print(f"[yellow][Shodan] {exc}[/yellow]")
        return entries

    # ── Censys SSL cert search ────────────────────────────────────────────────

    async def query_censys_by_ssl(
        self, domain: str, api_id: str, api_secret: str
    ) -> list[OSINTEntry]:
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {
            "q": f'services.tls.certificates.leaf_data.subject.common_name="{domain}"',
            "per_page": 100,
        }
        entries: list[OSINTEntry] = []
        try:
            async with self.session.get(
                url, params=params,
                headers={"Accept": "application/json"},
                auth=aiohttp.BasicAuth(api_id, api_secret),
                timeout=self.timeout,
            ) as r:
                if r.status == 401:
                    console.print("[red][Censys] Invalid credentials[/red]")
                    return entries
                r.raise_for_status()
                data = await r.json(content_type=None)
                for hit in data.get("result", {}).get("hits", []):
                    entries.append(OSINTEntry("censys_ssl", domain, ip=hit.get("ip")))
        except Exception as exc:
            console.print(f"[yellow][Censys] {exc}[/yellow]")
        return entries


# ─────────────────────────────────────────────────────────────────────────────
# Favicon Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class FaviconAnalyzer:

    FAVICON_PATHS = ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png",
                     "/static/favicon.ico", "/assets/favicon.ico"]

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        self.session = session
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def analyze(self, domain: str) -> tuple[Optional[int], Optional[str]]:
        for path in self.FAVICON_PATHS:
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}{path}"
                h, q = await self._try_url(url)
                if h is not None:
                    return h, q
        return None, None

    async def _try_url(self, url: str) -> tuple[Optional[int], Optional[str]]:
        try:
            async with self.session.get(url, timeout=self.timeout, ssl=False) as r:
                if r.status == 200:
                    data = await r.read()
                    if len(data) > 100:
                        h = favicon_hash(data)
                        return h, f"http.favicon.hash:{h}"
        except Exception:
            pass
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# SPF Flattener
# ─────────────────────────────────────────────────────────────────────────────

class SPFFlatener:
    """
    Recursively follows SPF 'include:' directives to build a complete
    list of IP ranges authorised to send email for the domain.
    Non-WAF IPs in this list are strong origin candidates.
    """

    _SPF_IP4  = re.compile(r"ip4:([0-9./]+)")
    _SPF_IP6  = re.compile(r"ip6:([0-9a-fA-F:./]+)")
    _SPF_INC  = re.compile(r"include:([^\s]+)")
    _SPF_A    = re.compile(r"\ba:([^\s]+)")

    def __init__(self, resolver: DNSResolver, max_depth: int = 5):
        self.resolver  = resolver
        self.max_depth = max_depth
        self._visited: set[str] = set()

    async def flatten(self, domain: str, depth: int = 0) -> list[str]:
        """Return all explicit IPs from the SPF record chain for *domain*."""
        if depth > self.max_depth or domain in self._visited:
            return []
        self._visited.add(domain)

        loop = asyncio.get_event_loop()
        res  = self.resolver._make_resolver(loop)
        try:
            answers = await res.query_dns(domain, "TXT")
        except Exception:
            return []

        ips: list[str] = []
        for a in answers:
            txt = a.text
            if isinstance(txt, (bytes, bytearray)):
                txt = txt.decode(errors="replace")
            elif isinstance(txt, list):
                txt = b"".join(txt).decode(errors="replace")
            if "v=spf1" not in txt.lower():
                continue

            for ip in self._SPF_IP4.findall(txt):
                ips.append(f"ip4:{ip}")
            for ip in self._SPF_IP6.findall(txt):
                ips.append(f"ip6:{ip}")
            for include in self._SPF_INC.findall(txt):
                sub_ips = await self.flatten(include, depth + 1)
                ips.extend(sub_ips)

        return ips


# ─────────────────────────────────────────────────────────────────────────────
# Mail Leak Detector
# ─────────────────────────────────────────────────────────────────────────────

class MailLeakDetector:

    _SPF_IP4 = re.compile(r"ip4:([0-9./]+)")
    _SPF_IP6 = re.compile(r"ip6:([0-9a-fA-F:./]+)")
    _SPF_INC = re.compile(r"include:([^\s]+)")
    _SPF_A   = re.compile(r"\ba:([^\s]+)")

    def __init__(self, cidr_mgr: CIDRManager):
        self.cidr = cidr_mgr

    def analyze(self, result: DNSResult) -> list[str]:
        notes: list[str] = []
        for mx_host in result.mx:
            notes.append(f"MX host: {mx_host}")
        for txt in result.txt:
            if "v=spf1" not in txt.lower():
                continue
            for ip in self._SPF_IP4.findall(txt):
                vendor, is_waf = self.cidr.classify_ip(ip.split("/")[0])
                flag = f" [WAF:{vendor}]" if is_waf else f" [CLOUD:{vendor}]" if vendor else " [POTENTIAL ORIGIN ⭐]"
                notes.append(f"SPF ip4:{ip}{flag}")
            for ip in self._SPF_IP6.findall(txt):
                vendor, is_waf = self.cidr.classify_ip(ip.split("/")[0])
                flag = f" [WAF:{vendor}]" if is_waf else f" [CLOUD:{vendor}]" if vendor else " [POTENTIAL ORIGIN ⭐]"
                notes.append(f"SPF ip6:{ip}{flag}")
            for include in self._SPF_INC.findall(txt):
                notes.append(f"SPF include:{include}")
            for a_rec in self._SPF_A.findall(txt):
                notes.append(f"SPF a:{a_rec}")
        return notes


# ─────────────────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:

    @staticmethod
    def save(report: ScanReport, path: Path, fmt: OutputFormat) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            if fmt == OutputFormat.JSON:
                json.dump(report.to_dict(), fh, indent=2)
            elif fmt == OutputFormat.CSV:
                ReportGenerator._write_csv(report, fh)
            else:
                ReportGenerator._write_text(report, fh)
        console.print(f"[green][INFO] Report saved → {path}[/green]")

    @staticmethod
    def _write_csv(report: ScanReport, fh) -> None:
        writer = csv.writer(fh)
        writer.writerow([
            "domain","status","ipv4","ipv6","origin_ips","verified_origin",
            "waf_ips","waf_vendors","cloud_ips","cloud_vendors",
            "mx","asn","org","country","confidence","error",
        ])
        for r in report.found + report.waf_protected + report.not_found + report.errors:
            meta0 = next(iter(r.ip_meta.values()), IPMeta("")) if r.ip_meta else IPMeta("")
            writer.writerow([
                r.domain, r.status,
                ";".join(r.ipv4), ";".join(r.ipv6),
                ";".join(r.origin_ips), ";".join(r.verified_origin_ips),
                ";".join(r.waf_ips),
                ";".join(f"{ip}={v}" for ip, v in r.waf_vendor.items()),
                ";".join(r.cloud_ips),
                ";".join(f"{ip}={v}" for ip, v in r.cloud_vendor.items()),
                ";".join(r.mx),
                meta0.asn or "", meta0.org or "",
                meta0.country or "", meta0.confidence,
                r.error or "",
            ])

    @staticmethod
    def _write_text(report: ScanReport, fh) -> None:
        fh.write(f"Kish964 v{VERSION} Scan Report\n")
        fh.write("=" * 60 + "\n")
        fh.write(f"Target:   {report.target}\n")
        fh.write(f"Date:     {report.scan_date}\n")
        fh.write(f"Duration: {report.scan_duration:.1f}s\n")
        fh.write(f"Checked:  {report.total_checked}\n\n")
        if report.wildcard_ips:
            fh.write(f"[WILDCARD] {', '.join(report.wildcard_ips)}\n\n")
        if report.found:
            fh.write(f"[ORIGIN IPs] ({len(report.found)})\n")
            for r in report.found:
                fh.write(f"  {r.domain}\n")
                for ip in r.origin_ips:
                    meta = r.ip_meta.get(ip, IPMeta(ip))
                    verified = "✓ HTTP verified" if meta.http_verified else "unverified"
                    fh.write(f"    {ip}  [{verified}]  {meta.org or ''}  {meta.country or ''}  confidence:{meta.confidence}%\n")
                    if meta.ssl_cns:
                        fh.write(f"      SSL SANs: {', '.join(meta.ssl_cns[:5])}\n")
        if report.zone_transfers:
            fh.write(f"\n[ZONE TRANSFERS]\n")
            for z in report.zone_transfers:
                status = "SUCCESS" if z.success else f"FAILED ({z.error})"
                fh.write(f"  {z.nameserver}: {status}\n")
                for rec in z.records[:20]:
                    fh.write(f"    {rec}\n")
        if report.mail_leaks:
            fh.write(f"\n[MAIL LEAKS] ({len(report.mail_leaks)})\n")
            for r in report.mail_leaks:
                fh.write(f"  {r.domain}: MX={r.mx}\n")
        if report.favicon_hash:
            fh.write(f"\n[FAVICON]\n")
            fh.write(f"  Hash: {report.favicon_hash}\n")
            fh.write(f"  Shodan dork: {report.favicon_shodan_query}\n")
        if report.osint:
            fh.write(f"\n[OSINT] ({len(report.osint)})\n")
            for e in report.osint:
                fh.write(f"  [{e.source}] {e.domain} -> {e.ip or '?'}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Config loader
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load ~/.kish964.toml if present and tomllib is available."""
    if not _HAS_TOML:
        return {}
    cfg_path = Path.home() / ".kish964.toml"
    if not cfg_path.exists():
        return {}
    try:
        with open(cfg_path, "rb") as fh:
            data = tomllib.load(fh)
        console.print(f"[dim][INFO] Loaded config from {cfg_path}[/dim]")
        return data
    except Exception as exc:
        console.print(f"[yellow][WARN] Could not parse config: {exc}[/yellow]")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────────────────────────────────────

class Kish964:

    def __init__(
        self,
        domain: str,
        wordlists:       list[str],
        threads:         int  = 100,
        output:          Optional[str] = None,
        output_format:   OutputFormat  = OutputFormat.NORMAL,
        verbose:         bool = False,
        quiet:           bool = False,
        historical:      bool = False,
        check_favicon:   bool = False,
        verify_http:     bool = False,
        axfr:            bool = False,
        wildcard_check:  bool = True,
        asn_lookup:      bool = False,
        grab_ssl:        bool = False,
        shodan_key:      Optional[str] = None,
        censys_id:       Optional[str] = None,
        censys_secret:   Optional[str] = None,
        nameservers:     Optional[list[str]] = None,
    ):
        self.domain         = domain
        self.wordlists      = wordlists or []
        self.concurrency    = threads
        self.output         = Path(output) if output else None
        self.output_format  = output_format
        self.verbose        = verbose
        self.quiet          = quiet
        self.historical     = historical
        self.check_favicon  = check_favicon
        self.verify_http    = verify_http
        self.axfr           = axfr
        self.wildcard_check = wildcard_check
        self.asn_lookup     = asn_lookup
        self.grab_ssl       = grab_ssl
        self.shodan_key     = shodan_key
        self.censys_id      = censys_id
        self.censys_secret  = censys_secret
        self.nameservers    = nameservers
        self.report         = ScanReport(target=domain)

    # ── Banner ────────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        if self.quiet:
            return
        figlet_text = pyfiglet.Figlet(font="big").renderText("kish964")
        console.print(f"[bright_green]{figlet_text}[/bright_green]")
        panel_text = Text()
        panel_text.append(f"v{VERSION}  –  Advanced Origin IP Discovery Framework\n", style="bold red")
        panel_text.append('"Unmasking hidden infrastructure behind the WAF edge"\n', style="yellow")
        panel_text.append("GitHub: ", style="white")
        panel_text.append("https://github.com/Kish964-Team", style="bright_blue")
        console.print(Panel(panel_text, border_style="dim"))
        console.print()

    # ── Wordlist ──────────────────────────────────────────────────────────────

    def _load_wordlists(self) -> list[str]:
        subdomains: set[str] = set()
        for wl_path in self.wordlists:
            p = Path(wl_path)
            if not p.exists():
                console.print(f"[red][ERROR] Wordlist not found: {wl_path}[/red]")
                sys.exit(1)
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    s = line.strip().lstrip("*.")
                    if s and not s.startswith("#"):
                        subdomains.add(s)
            if not self.quiet:
                console.print(f"[yellow][INFO] Loaded {len(subdomains)} entries from {p}[/yellow]")
        return sorted(subdomains)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, result: DNSResult) -> None:
        self.report.total_checked += 1
        if result.status == "found":
            self.report.found.append(result)
            if not self.quiet:
                origin = ", ".join(result.origin_ips)
                waf_part = ""
                if result.waf_ips:
                    vendors = ", ".join(f"{ip}({result.waf_vendor[ip]})" for ip in result.waf_ips)
                    waf_part = f" | WAF: {vendors}"
                cloud_part = ""
                if result.cloud_ips:
                    cloud_part = f" | CLOUD: {', '.join(f'{ip}({result.cloud_vendor[ip]})' for ip in result.cloud_ips)}"
                console.print(
                    f"[bright_green][ORIGIN] {result.domain} → {origin}{waf_part}{cloud_part}[/bright_green]"
                )
        elif result.status == "waf":
            self.report.waf_protected.append(result)
            if self.verbose:
                vendors = ", ".join(set(result.waf_vendor.values()))
                console.print(f"[yellow][WAF:{vendors}] {result.domain} → {', '.join(result.all_ips)}[/yellow]")
        elif result.status == "not_found":
            self.report.not_found.append(result)
            if self.verbose:
                console.print(f"[dim][NX] {result.domain}[/dim]")
        elif result.error:
            self.report.errors.append(result)

    # ── Async core ────────────────────────────────────────────────────────────

    async def _async_run(self) -> None:
        start = time.monotonic()

        connector = aiohttp.TCPConnector(
            limit=300,
            ttl_dns_cache=300,
            resolver=aiohttp.resolver.ThreadedResolver(),
        )
        headers = {"User-Agent": f"Kish964/{VERSION} (+https://github.com/Kish964-Team)"}

        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:

            # 1. Load CIDR ranges
            cidr_mgr = CIDRManager()
            await cidr_mgr.load(session)
            if not self.quiet:
                vendors = list(cidr_mgr._networks.keys())
                console.print(f"[green][INFO] CIDR ranges loaded: {', '.join(vendors)}[/green]")

            dns_resolver  = DNSResolver(cidr_mgr, self.nameservers)
            osint_fetcher = OSINTFetcher(session)
            mail_detect   = MailLeakDetector(cidr_mgr)
            http_verifier = HTTPVerifier(session, self.domain) if self.verify_http else None
            asn_enricher  = ASNEnricher(session) if self.asn_lookup else None

            # 2. Wildcard detection
            wildcard_ips: set[str] = set()
            if self.wildcard_check:
                wc_ips = await dns_resolver.detect_wildcard(self.domain)
                wildcard_ips = set(wc_ips)
                self.report.wildcard_ips = list(wildcard_ips)

            # 3. Zone transfer
            if self.axfr:
                console.print("[cyan][AXFR] Attempting zone transfers on NS servers…[/cyan]")
                zt_results = await dns_resolver.attempt_axfr(self.domain)
                self.report.zone_transfers = zt_results
                if not any(z.success for z in zt_results):
                    console.print("[dim][AXFR] Zone transfers refused (expected)[/dim]")

            # 4. OSINT phase
            if self.historical:
                console.print("[cyan][OSINT] Starting multi-source passive recon…[/cyan]")

                crt, ht, us, otx, bo = await asyncio.gather(
                    osint_fetcher.fetch_crtsh(self.domain),
                    osint_fetcher.fetch_hackertarget(self.domain),
                    osint_fetcher.fetch_urlscan(self.domain),
                    osint_fetcher.fetch_otx(self.domain),
                    osint_fetcher.fetch_bufferover(self.domain),
                )
                for entries, src in [(crt, "crt.sh"), (ht, "hackertarget"),
                                     (us, "urlscan"), (otx, "otx"), (bo, "bufferover")]:
                    self.report.osint.extend(entries)
                    if not self.quiet:
                        console.print(f"[green][OSINT] {src}: {len(entries)} records[/green]")

                self.report.crt_subdomains = list({e.domain for e in crt})

            if self.shodan_key:
                console.print("[cyan][OSINT] Querying Shodan SSL certs…[/cyan]")
                sh = await osint_fetcher.query_shodan_by_ssl(self.domain, self.shodan_key)
                self.report.osint.extend(sh)
                console.print(f"[green][OSINT] Shodan: {len(sh)} matches[/green]")

            if self.censys_id and self.censys_secret:
                console.print("[cyan][OSINT] Querying Censys SSL certs…[/cyan]")
                cs = await osint_fetcher.query_censys_by_ssl(self.domain, self.censys_id, self.censys_secret)
                self.report.osint.extend(cs)
                console.print(f"[green][OSINT] Censys: {len(cs)} matches[/green]")

            # 5. Favicon
            if self.check_favicon:
                console.print("[cyan][FAVICON] Downloading and hashing favicon…[/cyan]")
                fav  = FaviconAnalyzer(session)
                h, q = await fav.analyze(self.domain)
                if h is not None:
                    self.report.favicon_hash         = h
                    self.report.favicon_shodan_query = q
                    console.print(f"[bright_green][FAVICON] Hash: {h} | Shodan dork: {q}[/bright_green]")
                else:
                    console.print("[yellow][FAVICON] Could not fetch favicon[/yellow]")

            # 6. Fetch canonical baseline for HTTP verification
            if http_verifier:
                console.print("[cyan][HTTP] Fetching canonical site baseline…[/cyan]")
                await http_verifier.fetch_canonical()
                title = http_verifier._canonical_title or "(none)"
                console.print(f"[green][HTTP] Canonical title: {title[:60]}[/green]")

            # 7. Build subdomain list
            subdomains = self._load_wordlists()

            # Merge OSINT discoveries
            osint_subs = set()
            for e in self.report.osint:
                d = e.domain.lower()
                if d.endswith(f".{self.domain}"):
                    sub = d[: -(len(self.domain) + 1)]
                    if sub:
                        osint_subs.add(sub)
            before = len(subdomains)
            subdomains = sorted(set(subdomains) | osint_subs)
            added = len(subdomains) - before
            if added > 0 and not self.quiet:
                console.print(f"[cyan][INFO] +{added} unique subdomains from OSINT[/cyan]")

            all_targets: list[Optional[str]] = [None] + subdomains
            console.print(
                f"\n[cyan][INFO] Scanning {len(all_targets)} targets "
                f"(concurrency={self.concurrency}, wildcard_filter={len(wildcard_ips)})…[/cyan]\n"
            )

            # 8. Concurrent DNS resolution
            sem = asyncio.Semaphore(self.concurrency)

            async def resolve_one(sub: Optional[str]) -> DNSResult:
                fqdn = f"{sub}.{self.domain}" if sub else self.domain
                async with sem:
                    return await dns_resolver.resolve_all(fqdn, wildcard_ips)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                disable=self.quiet,
            ) as progress:
                task_id = progress.add_task("[cyan]DNS resolving…", total=len(all_targets))

                # Gather all origin IPs for post-scan enrichment
                origin_ip_to_results: dict[str, list[DNSResult]] = {}

                coros = [resolve_one(s) for s in all_targets]
                for coro in asyncio.as_completed(coros):
                    result = await coro
                    self._dispatch(result)

                    # Mail leak detection
                    if result.mx or any("spf" in t.lower() for t in result.txt):
                        notes = mail_detect.analyze(result)
                        if notes:
                            self.report.mail_leaks.append(result)
                            if self.verbose:
                                for note in notes:
                                    console.print(f"[magenta][MAIL] {result.domain}: {note}[/magenta]")

                    # Collect origin IPs for enrichment
                    for ip in result.origin_ips:
                        origin_ip_to_results.setdefault(ip, []).append(result)

                    progress.advance(task_id)

            # 9. Post-scan enrichment on discovered origin IPs
            all_origin_ips = list(origin_ip_to_results.keys())

            if all_origin_ips:
                console.print(f"\n[cyan][INFO] Enriching {len(all_origin_ips)} origin IPs…[/cyan]")

                # 9a. ASN lookup
                asn_data: dict[str, dict] = {}
                if self.asn_lookup and asn_enricher:
                    console.print("[cyan][ASN] Fetching ASN/GeoIP data…[/cyan]")
                    asn_data = await asn_enricher.enrich(all_origin_ips)

                # 9b. Reverse DNS (PTR)
                loop = asyncio.get_event_loop()
                ptr_resolver = dns_resolver._make_resolver(loop)

                async def ptr_lookup(ip: str) -> tuple[str, str]:
                    try:
                        ans = await ptr_resolver.query_dns(ip, "PTR")
                        if ans:
                            return ip, ans[0].name
                    except Exception:
                        pass
                    return ip, ""

                ptr_results = await asyncio.gather(*[ptr_lookup(ip) for ip in all_origin_ips])
                ptr_map = dict(ptr_results)

                # 9c. Direct SSL cert grab
                ssl_map: dict[str, list[str]] = {}
                if self.grab_ssl:
                    console.print("[cyan][SSL] Grabbing certificates directly from origin IPs…[/cyan]")
                    ssl_tasks = [SSLCertGrabber.grab(ip) for ip in all_origin_ips]
                    ssl_results = await asyncio.gather(*ssl_tasks)
                    ssl_map = dict(zip(all_origin_ips, ssl_results))
                    for ip, cns in ssl_map.items():
                        if cns:
                            console.print(f"[bright_cyan][SSL] {ip} → {', '.join(cns[:4])}[/bright_cyan]")

                # 9d. HTTP verification
                http_metas: dict[str, IPMeta] = {}
                if self.verify_http and http_verifier:
                    console.print("[cyan][HTTP] Probing origin IPs with Host header…[/cyan]")
                    http_sem = asyncio.Semaphore(20)

                    async def verify_one(ip: str) -> tuple[str, IPMeta]:
                        async with http_sem:
                            return ip, await http_verifier.verify_ip(ip)

                    http_results = await asyncio.gather(*[verify_one(ip) for ip in all_origin_ips])
                    http_metas = dict(http_results)
                    verified_count = sum(1 for m in http_metas.values() if m.http_verified)
                    console.print(f"[green][HTTP] {verified_count}/{len(all_origin_ips)} IPs verified as origin[/green]")

                # 9e. Merge enrichment into DNSResult objects
                for ip, dns_results_list in origin_ip_to_results.items():
                    meta = http_metas.get(ip, IPMeta(ip=ip))
                    meta.ptr     = ptr_map.get(ip) or None
                    meta.ssl_cns = ssl_map.get(ip, [])
                    asn_info     = asn_data.get(ip, {})
                    meta.asn     = asn_info.get("asn")
                    meta.org     = asn_info.get("org")
                    meta.country = asn_info.get("country")
                    meta.city    = asn_info.get("city")

                    for dr in dns_results_list:
                        dr.ip_meta[ip] = meta

                    # Print enriched info
                    if not self.quiet:
                        parts = []
                        if meta.org:     parts.append(meta.org)
                        if meta.country: parts.append(meta.country)
                        if meta.asn:     parts.append(meta.asn)
                        if meta.ptr:     parts.append(f"PTR:{meta.ptr}")
                        if meta.http_verified:
                            parts.append(f"[bold green]✓ HTTP verified (confidence:{meta.confidence}%)[/bold green]")
                        if meta.ssl_cns:
                            parts.append(f"SSL:{meta.ssl_cns[0]}")
                        if parts:
                            console.print(f"  [dim]{ip}[/dim] → {' | '.join(parts)}")

        self.report.scan_duration = time.monotonic() - start

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        if self.quiet:
            return

        console.print()
        table = Table(title=f"Scan Summary – {self.domain}", style="bright_white", border_style="dim")
        table.add_column("Category",  style="cyan",         min_width=30)
        table.add_column("Count",     style="bright_white", justify="right")

        s = self.report.summary
        table.add_row("✅  Origin IPs found",        str(s["found_origin"]))
        table.add_row("🔍  HTTP-verified origin IPs", str(s["verified_origin"]))
        table.add_row("🛡️  WAF-protected",            str(s["waf_protected"]))
        table.add_row("❌  Not found (NXDOMAIN)",    str(s["not_found"]))
        table.add_row("⚠️  Errors",                   str(s["errors"]))
        table.add_row("📧  Mail leaks",               str(s["mail_leaks"]))
        table.add_row("🔍  OSINT entries",            str(s["osint_entries"]))
        table.add_row("🗺️  Zone transfer successes",  str(s["zone_transfers_ok"]))
        table.add_row("⏱️  Scan duration",            f"{self.report.scan_duration:.1f}s")
        console.print(table)

        if self.report.wildcard_ips:
            console.print(
                f"\n[yellow]⚡ Wildcard DNS detected → filtered: "
                f"{', '.join(self.report.wildcard_ips)}[/yellow]"
            )

        if self.report.found:
            console.print("\n[bright_green bold]── Origin IP Details ──[/bright_green bold]")
            detail = Table(show_header=True, border_style="dim")
            detail.add_column("Domain",      style="bright_green")
            detail.add_column("Origin IP",   style="white")
            detail.add_column("PTR",         style="dim")
            detail.add_column("ASN / Org",   style="cyan")
            detail.add_column("Country",     style="yellow")
            detail.add_column("Verified",    style="green")
            detail.add_column("Confidence",  justify="right")
            detail.add_column("SSL SANs",    style="dim")

            for r in self.report.found:
                for ip in r.origin_ips:
                    meta = r.ip_meta.get(ip, IPMeta(ip))
                    detail.add_row(
                        r.domain,
                        ip,
                        meta.ptr or "-",
                        f"{meta.asn or ''} {meta.org or ''}".strip() or "-",
                        meta.country or "-",
                        "✓" if meta.http_verified else "?",
                        f"{meta.confidence}%",
                        (meta.ssl_cns[0] if meta.ssl_cns else "-"),
                    )
            console.print(detail)

        if self.report.zone_transfers and any(z.success for z in self.report.zone_transfers):
            console.print("\n[bright_red bold]── Zone Transfer Records ──[/bright_red bold]")
            for z in self.report.zone_transfers:
                if z.success:
                    console.print(f"  [red]NS: {z.nameserver}[/red]")
                    for rec in z.records[:30]:
                        console.print(f"    {rec}")

        if self.report.favicon_hash:
            console.print(
                f"\n[bright_yellow]🔍 Shodan favicon dork:[/bright_yellow] "
                f"[bold]{self.report.favicon_shodan_query}[/bold]"
            )

        if self.report.mail_leaks:
            console.print("\n[magenta bold]── SPF / Mail Leaks ──[/magenta bold]")
            for r in self.report.mail_leaks[:10]:
                notes = MailLeakDetector(CIDRManager()).analyze(r)
                for note in notes:
                    console.print(f"  [magenta]{r.domain}: {note}[/magenta]")

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> ScanReport:
        self._print_banner()
        asyncio.run(self._async_run())
        self._print_summary()
        if self.output:
            ReportGenerator.save(self.report, self.output, self.output_format)
        return self.report


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args(config: dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kish964",
        description=f"Kish964 v{VERSION} – Advanced Origin IP Discovery Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 kish964.py example.com -w kish_massive_wordlist.txt

  # Full power: OSINT + HTTP verification + favicon + ASN + SSL cert grab
  python3 kish964.py example.com -w kish_massive_wordlist.txt --historical --verify-http \\
      --check-favicon --asn-lookup --grab-ssl -o report.json -f json

  # Zone transfer + wildcard detection + Shodan
  python3 kish964.py example.com -w kish_massive_wordlist.txt --axfr --wildcard-check \\
      --shodan-key YOUR_KEY

  # High-concurrency quiet CSV export
  python3 kish964.py example.com -w big.txt -t 300 -q -o found.csv -f csv
""",
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument(
        "-w", "--wordlist",
        action="append", dest="wordlists", default=[],
        metavar="FILE", help="Subdomain wordlist (repeatable)",
    )
    parser.add_argument("-t", "--threads", type=int,
                        default=config.get("threads", 100),
                        help="Max concurrent DNS slots (default: 100)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        default=config.get("output"),
                        help="Write report to file")
    parser.add_argument("-f", "--format",
                        choices=["normal", "json", "csv"],
                        default=config.get("format", "normal"),
                        help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=config.get("verbose", False),
                        help="Show WAF/NXDOMAIN results")
    parser.add_argument("-q", "--quiet", action="store_true",
                        default=config.get("quiet", False),
                        help="Suppress non-essential output")

    osint = parser.add_argument_group("OSINT & Passive Recon")
    osint.add_argument("--historical", action="store_true",
                       default=config.get("historical", False),
                       help="Fetch crt.sh, HackerTarget, URLScan, OTX, BufferOver")
    osint.add_argument("--shodan-key", metavar="KEY",
                       default=config.get("shodan_key"),
                       help="Shodan API key")
    osint.add_argument("--censys-id", metavar="ID",
                       default=config.get("censys_id"))
    osint.add_argument("--censys-secret", metavar="SECRET",
                       default=config.get("censys_secret"))

    active = parser.add_argument_group("Active Analysis")
    active.add_argument("--verify-http", action="store_true",
                        default=config.get("verify_http", False),
                        help="HTTP-probe origin IPs with Host header to confirm origin")
    active.add_argument("--check-favicon", action="store_true",
                        default=config.get("check_favicon", False),
                        help="Download favicon and compute Shodan MurmurHash3 dork")
    active.add_argument("--axfr", action="store_true",
                        default=config.get("axfr", False),
                        help="Attempt DNS zone transfers (AXFR) on NS servers")
    active.add_argument("--wildcard-check", action="store_true",
                        default=config.get("wildcard_check", True),
                        help="Detect and filter wildcard DNS (default: on)")
    active.add_argument("--no-wildcard-check", dest="wildcard_check",
                        action="store_false",
                        help="Disable wildcard detection")
    active.add_argument("--grab-ssl", action="store_true",
                        default=config.get("grab_ssl", False),
                        help="Connect directly to origin IPs and pull TLS certificate SANs")

    enrich = parser.add_argument_group("Enrichment")
    enrich.add_argument("--asn-lookup", action="store_true",
                        default=config.get("asn_lookup", False),
                        help="Enrich origin IPs with ASN / GeoIP via ip-api.com")
    enrich.add_argument("--nameservers", metavar="NS", nargs="+",
                        default=config.get("nameservers"),
                        help="Custom DNS resolvers (e.g. --nameservers 8.8.8.8 1.1.1.1)")

    return parser.parse_args()


def main() -> None:
    config = load_config()
    args   = parse_args(config)

    scanner = Kish964(
        domain        = args.domain,
        wordlists     = args.wordlists,
        threads       = args.threads,
        output        = args.output,
        output_format = OutputFormat(args.format),
        verbose       = args.verbose,
        quiet         = args.quiet,
        historical    = args.historical,
        check_favicon = args.check_favicon,
        verify_http   = args.verify_http,
        axfr          = args.axfr,
        wildcard_check= args.wildcard_check,
        asn_lookup    = args.asn_lookup,
        grab_ssl      = args.grab_ssl,
        shodan_key    = args.shodan_key,
        censys_id     = args.censys_id,
        censys_secret = args.censys_secret,
        nameservers   = args.nameservers,
    )
    scanner.run()


if __name__ == "__main__":
    main()