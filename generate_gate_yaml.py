#!/usr/bin/env python3
"""
KausaGate YAML Generator
Reads gate_endpoints from SQLite database and generates Pay.sh provider spec YAML.
Run after every endpoint register/delete.
"""

import sqlite3
import sys
import os

# Find database file
DB_CANDIDATES = [
    '/root/sdp-mazepocket/mazepocket.db',
    '/root/sdp-mazepocket/pocket.db',
    '/root/sdp-mazepocket/maze_pocket.db',
    '/root/sdp-mazepocket/pockets.db',
]

YAML_OUTPUT = '/root/sdp-mazepocket/kausalayer-gate.yml'

def find_db():
    for path in DB_CANDIDATES:
        if os.path.exists(path):
            # Check if it has gate_endpoints table
            try:
                conn = sqlite3.connect(path)
                conn.execute("SELECT COUNT(*) FROM gate_endpoints")
                conn.close()
                return path
            except:
                continue
    return None

def generate_yaml():
    db_path = find_db()
    if not db_path:
        print(f"ERROR: No database with gate_endpoints table found")
        sys.exit(1)

    print(f"Using database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.execute(
        "SELECT id, pocket_id, pocket_address, endpoint_url, method, description, price_usdc, category "
        "FROM gate_endpoints WHERE status = 'active' ORDER BY created_at"
    )
    endpoints = cursor.fetchall()
    conn.close()

    print(f"Found {len(endpoints)} active endpoints")

    # Build YAML
    lines = []
    lines.append("name: kausalayer")
    lines.append("subdomain: kausalayer")
    lines.append("title: 'KausaLayer Privacy Gateway'")
    lines.append("description: 'Privacy-enhanced API endpoints powered by Maze Pocket stealth wallets.'")
    lines.append("category: ai_ml")
    lines.append("version: v1")
    lines.append("routing:")
    lines.append("  type: proxy")
    lines.append("  url: http://127.0.0.1:3033/gate/proxy/")
    lines.append("operator:")
    lines.append("  currencies:")
    lines.append("    usd: ['USDC']")
    lines.append("  network: mainnet")
    lines.append("  fee_payer: false")
    lines.append("  recipient: '4bNTvXEboVkByJw7EDZQtKBoQrHYhTuVsUZ9drb4WToA'")

    if not endpoints:
        lines.append("endpoints: []")
    else:
        # Build recipients map
        recipients = {}
        for ep in endpoints:
            ep_id, pocket_id, pocket_address, endpoint_url, method, description, price_usdc, category = ep
            recipient_key = f"pocket_{pocket_id.replace('-', '_')}"
            if recipient_key not in recipients:
                recipients[recipient_key] = pocket_address

        lines.append("recipients:")
        for key, address in recipients.items():
            lines.append(f"  {key}:")
            lines.append(f"    account: '{address}'")
            lines.append(f"    label: '{key}'")

        lines.append("endpoints:")
        for ep in endpoints:
            ep_id, pocket_id, pocket_address, endpoint_url, method, description, price_usdc, category = ep
            recipient_key = f"pocket_{pocket_id.replace('-', '_')}"

            lines.append(f"  - method: {method}")
            lines.append(f"    path: '{ep_id}'")
            lines.append(f"    resource: '{ep_id}'")
            lines.append(f"    description: '{description}'")
            lines.append(f"    metering:")
            lines.append(f"      dimensions:")
            lines.append(f"        - direction: usage")
            lines.append(f"          unit: requests")
            lines.append(f"          scale: 1")
            lines.append(f"          tiers:")
            lines.append(f"            - price_usd: {price_usdc}")
            lines.append(f"      splits:")
            lines.append(f"        - recipient: {recipient_key}")
            lines.append(f"          percent: 100")
            lines.append(f"          memo: 'Revenue for {ep_id}'")

    yaml_content = '\n'.join(lines) + '\n'

    with open(YAML_OUTPUT, 'w') as f:
        f.write(yaml_content)

    print(f"Generated {YAML_OUTPUT} with {len(endpoints)} endpoints")

if __name__ == '__main__':
    generate_yaml()
