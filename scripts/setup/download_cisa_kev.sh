#!/usr/bin/env bash
set -euo pipefail

# 프로젝트 루트 경로 계산 (scripts/setup/.. -> scripts/.. -> root)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DATA_RAW="${PROJECT_ROOT}/data/raw"

mkdir -p "$DATA_RAW"

URL="https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
OUT="${DATA_RAW}/cisa_kev.csv"

echo "[*] Downloading CISA KEV CSV..."
curl -fsSL -L "$URL" -o "$OUT"

echo "[+] Saved: $OUT"