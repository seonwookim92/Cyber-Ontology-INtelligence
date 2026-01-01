#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DATA_RAW="${PROJECT_ROOT}/data/raw"

mkdir -p "$DATA_RAW"

URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT="${DATA_RAW}/mitre_enterprise_attack.json"

echo "[*] Downloading MITRE ATT&CK Enterprise STIX JSON..."
curl -fsSL -L "$URL" -o "$OUT"

echo "[+] Saved: $OUT"