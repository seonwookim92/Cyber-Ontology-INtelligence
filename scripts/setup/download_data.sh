#!/usr/bin/env bash
set -euo pipefail

# 스크립트 위치의 절대 경로를 구해서 프로젝트 루트 기준 경로 설정
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[*] Downloading Raw Datasets..."

# 각 다운로드 스크립트 실행
bash "${SCRIPT_DIR}/download_cisa_kev.sh"
bash "${SCRIPT_DIR}/download_mitre_attack.sh"
bash "${SCRIPT_DIR}/download_urlhaus_online_csv.sh"

echo "[+] All downloads complete."