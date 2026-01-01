#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DATA_RAW="${PROJECT_ROOT}/data/raw"

mkdir -p "$DATA_RAW"

URL="https://urlhaus.abuse.ch/downloads/csv_online/"
OUT="${DATA_RAW}/urlhaus_online.csv"

echo "[*] Downloading URLhaus CSV (online URLs only)..."
curl -fsSL -L "$URL" -o "$OUT"

echo "[+] Saved: $OUT"