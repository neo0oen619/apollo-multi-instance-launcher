#!/usr/bin/env python3
"""Status monitor for Apollo instances."""

import sys
import requests
from typing import List, Tuple

PORTS = [47990, 48090, 48190, 48290, 48390]


def check_ports() -> List[Tuple[int, bool]]:
    """Check if Apollo instances are running on configured ports."""
    results = []
    for port in PORTS:
        try:
            resp = requests.get(f"http://localhost:{port}/", timeout=2)
            results.append((port, resp.status_code == 200))
        except:
            results.append((port, False))
    return results


def print_status(results: List[Tuple[int, bool]]) -> None:
    """Pretty-print status results."""
    print("Apollo Instance Status:")
    print("-" * 40)
    for port, up in results:
        status = "[UP]" if up else "[DOWN]"
        print(f"  Port {port}: {status}")
    print("-" * 40)
    up_count = sum(1 for _, up in results if up)
    print(f"Total: {up_count}/{len(results)} instances running")


if __name__ == "__main__":
    results = check_ports()
    print_status(results)
    all_up = all(up for _, up in results)
    sys.exit(0 if all_up else 1)
