#!/usr/bin/env bash
set -euo pipefail

# 프로젝트 루트 경로 설정
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "=================================================="
echo "[*] Cyber Graph (Neo4j) Bootstrap Starting..."
echo "=================================================="

# 1. 디렉토리 구조 생성
# data/processed: Neo4j 컨테이너가 마운트해서 읽을 CSV들이 저장될 곳
echo "[1] Creating directories..."
mkdir -p "${PROJECT_ROOT}/data/raw"
mkdir -p "${PROJECT_ROOT}/data/processed"
mkdir -p "${PROJECT_ROOT}/schema"

# 2. 데이터 다운로드
echo "[2] Downloading raw datasets..."
bash "${SCRIPT_DIR}/download_data.sh"

# 3. ETL 파이프라인 실행 (Raw -> Neo4j Import CSV)
# 이 부분은 우리가 곧 작성할 Python 스크립트들을 호출합니다.
echo "[3] Running ETL Pipeline (Raw -> CSV)..."

# PYTHONPATH 설정 (src 모듈 import 가능하도록)
export PYTHONPATH="${PROJECT_ROOT}"

# (3-1) MITRE ATT&CK 처리
if [ -f "${PROJECT_ROOT}/scripts/etl/preprocess_mitre.py" ]; then
    echo " -> Processing MITRE ATT&CK..."
    python3 "${PROJECT_ROOT}/scripts/etl/preprocess_mitre.py"
else
    echo " [!] Warning: scripts/etl/preprocess_mitre.py not found. Skipping."
fi

# (3-2) CISA KEV 처리
if [ -f "${PROJECT_ROOT}/scripts/etl/preprocess_kev.py" ]; then
    echo " -> Processing CISA KEV..."
    python3 "${PROJECT_ROOT}/scripts/etl/preprocess_kev.py"
else
     echo " [!] Warning: scripts/etl/preprocess_kev.py not found. Skipping."
fi

# (3-3) URLhaus 처리
if [ -f "${PROJECT_ROOT}/scripts/etl/preprocess_urlhaus.py" ]; then
    echo " -> Processing URLhaus..."
    python3 "${PROJECT_ROOT}/scripts/etl/preprocess_urlhaus.py"
else
     echo " [!] Warning: scripts/etl/preprocess_urlhaus.py not found. Skipping."
fi

echo "=================================================="
echo "[+] Bootstrap Preparation Complete!"
echo "    Check 'data/processed/' for generated CSV files."
echo "    Next Step: Run 'docker-compose up -d' and initialize DB."
echo "=================================================="