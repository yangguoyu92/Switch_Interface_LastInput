#!/usr/bin/env python3
"""
Audit switch interfaces via Cisco Catalyst Center and report stale last-input ports.

This script uses Catalyst Center's interface inventory data, specifically
`lastIncomingPacketTime`, to find interfaces that have not received traffic for
longer than a threshold.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: requests\n"
        "Install it with: pip install -r requirements.txt"
    ) from exc


@dataclass
class DeviceInfo:
    id: str
    hostname: str
    management_ip: str
    family: str
    type: str


@dataclass
class InterfaceRow:
    switch: str
    management_ip: str
    interface: str
    status: str
    admin_status: str
    port_mode: str
    vlan_id: str
    last_incoming_packet_time: int | None
    idle_days: float | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find stale switch interfaces using Cisco Catalyst Center APIs."
    )
    parser.add_argument("--base-url", required=True, help="Catalyst Center URL, e.g. https://dnac.example.com")
    parser.add_argument(
        "--username",
        default=os.getenv("CATC_USERNAME") or os.getenv("CISCO_USERNAME"),
        help="Catalyst Center username. Can also come from CATC_USERNAME or CISCO_USERNAME.",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("CATC_PASSWORD") or os.getenv("CISCO_PASSWORD"),
        help="Catalyst Center password. Can also come from CATC_PASSWORD or CISCO_PASSWORD.",
    )
    parser.add_argument(
        "--months",
        type=int,
        default=3,
        help="Threshold in months, using 30 days per month. Default: 3",
    )
    parser.add_argument(
        "--output",
        default="catalyst_center_last_input_report.csv",
        help="Output CSV path. Default: catalyst_center_last_input_report.csv",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="API page size for interfaces. Max documented value is 500. Default: 500",
    )
    parser.add_argument(
        "--site-filter",
        help="Optional substring filter applied to device hostname for a smaller report.",
    )
    parser.add_argument(
        "--include-never",
        action="store_true",
        help="Include interfaces with no lastIncomingPacketTime value.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds. Default: 30",
    )
    parser.add_argument(
        "--requests-per-minute",
        type=int,
        default=30,
        help="Cap API request rate. Default: 30 requests per minute",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
        help="Maximum retries for 429 and transient 5xx responses. Default: 5",
    )
    return parser.parse_args()


def normalize_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    for suffix in ("/dna/home", "/dna", "/home"):
        if normalized.endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break
    return normalized


class CatalystCenterClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool,
        timeout: int,
        requests_per_minute: int,
        max_retries: int,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.requests_per_minute = max(1, requests_per_minute)
        self.max_retries = max(0, max_retries)
        self.min_interval = 60.0 / self.requests_per_minute
        self.last_request_at = 0.0
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})

    def _sleep_for_rate_limit(self) -> None:
        elapsed = time.monotonic() - self.last_request_at
        delay = self.min_interval - elapsed
        if delay > 0:
            time.sleep(delay)

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}{path}"

        for attempt in range(self.max_retries + 1):
            self._sleep_for_rate_limit()
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            self.last_request_at = time.monotonic()

            if response.status_code not in {429, 500, 502, 503, 504}:
                response.raise_for_status()
                return response

            if attempt == self.max_retries:
                response.raise_for_status()

            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep_seconds = float(retry_after)
            else:
                sleep_seconds = min(60.0, (2 ** attempt) + random.uniform(0, 1))
            time.sleep(sleep_seconds)

        raise RuntimeError("Unreachable retry flow")

    def authenticate(self) -> None:
        response = self._request(
            "POST",
            "/dna/system/api/v1/auth/token",
            auth=HTTPBasicAuth(self.username, self.password),
        )
        token = response.json()["Token"]
        self.session.headers.update({"X-Auth-Token": token})

    def get_devices(self) -> dict[str, DeviceInfo]:
        response = self._request("GET", "/dna/intent/api/v1/network-device")

        devices: dict[str, DeviceInfo] = {}
        for item in response.json().get("response", []):
            device_id = item.get("id")
            if not device_id:
                continue
            devices[device_id] = DeviceInfo(
                id=device_id,
                hostname=item.get("hostname", ""),
                management_ip=item.get("managementIpAddress", ""),
                family=item.get("family", ""),
                type=item.get("type", ""),
            )
        return devices

    def get_interface_count(self) -> int:
        response = self._request("GET", "/dna/intent/api/v1/interface/count")
        return int(response.json().get("response", 0))

    def get_all_interfaces(self, limit: int) -> list[dict[str, Any]]:
        total = self.get_interface_count()
        if total == 0:
            return []

        pages = math.ceil(total / limit)
        interfaces: list[dict[str, Any]] = []

        for page in range(pages):
            offset = page * limit + 1
            response = self._request(
                "GET",
                "/dna/intent/api/v1/interface",
                params={"limit": limit, "offset": offset},
            )
            interfaces.extend(response.json().get("response", []))
        return interfaces


def epoch_ms_to_idle_days(timestamp_ms: int) -> float:
    now_ms = int(time.time() * 1000)
    delta_days = (now_ms - timestamp_ms) / 1000 / 86400
    return round(delta_days, 4)


def build_report_rows(
    devices: dict[str, DeviceInfo],
    interfaces: list[dict[str, Any]],
    threshold_days: int,
    include_never: bool,
    site_filter: str | None,
) -> list[InterfaceRow]:
    rows: list[InterfaceRow] = []
    hostname_filter = site_filter.lower() if site_filter else None

    for item in interfaces:
        device_id = item.get("deviceId")
        if not device_id or device_id not in devices:
            continue

        device = devices[device_id]
        if hostname_filter and hostname_filter not in device.hostname.lower():
            continue

        last_incoming = item.get("lastIncomingPacketTime")
        idle_days = None
        if isinstance(last_incoming, (int, float)) and last_incoming > 0:
            idle_days = epoch_ms_to_idle_days(int(last_incoming))

        if idle_days is None:
            if not include_never:
                continue
        elif idle_days <= threshold_days:
            continue

        rows.append(
            InterfaceRow(
                switch=device.hostname or device.id,
                management_ip=device.management_ip,
                interface=item.get("portName") or item.get("name") or "",
                status=item.get("status", ""),
                admin_status=item.get("adminStatus", ""),
                port_mode=item.get("portMode", ""),
                vlan_id=item.get("vlanId", ""),
                last_incoming_packet_time=int(last_incoming) if isinstance(last_incoming, (int, float)) and last_incoming > 0 else None,
                idle_days=idle_days,
            )
        )

    return sorted(rows, key=lambda row: (row.switch, row.interface))


def write_csv(path: str, rows: list[InterfaceRow]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "switch",
                "management_ip",
                "interface",
                "status",
                "admin_status",
                "port_mode",
                "vlan_id",
                "last_incoming_packet_time",
                "last_incoming_packet_iso_utc",
                "idle_days",
            ]
        )

        for row in rows:
            iso_time = ""
            if row.last_incoming_packet_time is not None:
                iso_time = datetime.fromtimestamp(
                    row.last_incoming_packet_time / 1000,
                    tz=timezone.utc,
                ).isoformat()

            writer.writerow(
                [
                    row.switch,
                    row.management_ip,
                    row.interface,
                    row.status,
                    row.admin_status,
                    row.port_mode,
                    row.vlan_id,
                    row.last_incoming_packet_time or "",
                    iso_time,
                    "" if row.idle_days is None else row.idle_days,
                ]
            )


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        print("Missing username/password for Catalyst Center.", file=sys.stderr)
        return 2

    threshold_days = args.months * 30
    client = CatalystCenterClient(
        base_url=args.base_url,
        username=args.username,
        password=args.password,
        verify=not args.insecure,
        timeout=args.timeout,
        requests_per_minute=args.requests_per_minute,
        max_retries=args.max_retries,
    )

    try:
        client.authenticate()
        devices = client.get_devices()
        interfaces = client.get_all_interfaces(args.limit)
        rows = build_report_rows(
            devices=devices,
            interfaces=interfaces,
            threshold_days=threshold_days,
            include_never=args.include_never,
            site_filter=args.site_filter,
        )
    except requests.HTTPError as exc:
        print(f"HTTP error: {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    write_csv(args.output, rows)

    print(f"Threshold: older than {args.months} month(s) (~{threshold_days} days)")
    print(f"Devices in inventory: {len(devices)}")
    print(f"Interfaces retrieved: {len(interfaces)}")
    print(f"Stale interfaces found: {len(rows)}")
    print(f"CSV report written to: {args.output}")
    print(
        f"API pacing: capped at {args.requests_per_minute} request(s) per minute with up to {args.max_retries} retries"
    )
    print(
        "Note: This uses Catalyst Center's lastIncomingPacketTime field, not the literal IOS CLI 'Last input' string."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
