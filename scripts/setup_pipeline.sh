#!/bin/bash

# ==============================================================================
# 🛡️ COIN: Cyber Ontology Intelligence - Setup Pipeline
#
# 이 스크립트는 전체 데이터 파이프라인을 순차적으로 실행하여 Neo4j 그래프를 구축합니다.
# 순서: [환경설정] -> [데이터 준비] -> [DB 초기화] -> [기반 지식 적재] -> [시나리오 생성/적재]
# ==============================================================================

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   🛡️  COIN Setup: Full Data Pipeline Execution   ${NC}"
echo -e "${BLUE}======================================================${NC}"

# ------------------------------------------------------------------------------
# 0. 사전 체크
# ------------------------------------------------------------------------------
if [ ! -f ".env" ]; then
    echo -e "${RED}[Error] .env file not found. Please copy .env.example to .env first.${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. 데이터 준비 (다운로드 및 파일 전처리)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 1] Preparing Raw Data (Download & Preprocess)...${NC}"

# 데이터 디렉토리 확인
mkdir -p data/raw data/processed data/generated

# (1) 데이터 다운로드
echo -e "  - Downloading CISA KEV..."
bash scripts/setup/download_cisa_kev.sh

echo -e "  - Downloading MITRE ATT&CK..."
bash scripts/setup/download_mitre_attack.sh

echo -e "  - Downloading URLHaus..."
bash scripts/setup/download_urlhaus_online_csv.sh

# (2) 데이터 전처리 (Raw -> Processed JSON)
echo -e "  - Preprocessing CISA KEV Data..."
python scripts/etl/preprocess_kev.py

echo -e "  - Preprocessing MITRE ATT&CK Data..."
python scripts/etl/preprocess_mitre.py

echo -e "  - Preprocessing URLHaus Data..."
python scripts/etl/preprocess_urlhaus.py

# ------------------------------------------------------------------------------
# 2. DB 초기화 (스키마 설정)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 2] Initializing Neo4j Database...${NC}"
# 데이터를 넣기 전에 제약조건(Unique Constraints)과 인덱스를 먼저 거는 것이 중요합니다.
python scripts/setup/init_db.py

# ------------------------------------------------------------------------------
# 3. 시나리오 생성 (AI Generative)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 3] Generating Synthetic Incidents (AI)...${NC}"
echo -e "${YELLOW}⚠️  Note: This step requires a running LLM (Ollama/OpenAI).${NC}"

# 사용자 입력: 생성할 시나리오 개수
read -p "Enter number of incidents to generate [0 to skip]: " INCIDENT_COUNT
INCIDENT_COUNT=${INCIDENT_COUNT:-0}

if [ "$INCIDENT_COUNT" -gt 0 ]; then
    echo -e "🚀 Generating $INCIDENT_COUNT incidents..."
    python scripts/setup/generate_incidents.py --count "$INCIDENT_COUNT"
else
    echo -e "⏩ Skipping generation."
fi

# ------------------------------------------------------------------------------
# 4. 데이터 최종 적재 (Ingestion)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 4] Ingesting Incidents into Knowledge Graph...${NC}"

# [수정] 기존 적재 기록 파일이 있다면 삭제하여 강제로 다시 적재하도록 함
IMPORTED_LOG="data/processed/incidents_imported.json"
if [ -f "$IMPORTED_LOG" ]; then
    echo -e "${YELLOW}Removing previous ingestion log ($IMPORTED_LOG) to force fresh load...${NC}"
    rm "$IMPORTED_LOG"
fi

if [ -f "data/generated/incidents.json" ]; then
    # 생성된 시나리오를 Neo4j에 로드
    python scripts/etl/process_incidents.py
else
    echo -e "${YELLOW}No incident file found. Skipping ingestion.${NC}"
fi

echo -e "\n${BLUE}======================================================${NC}"
echo -e "${BLUE}   ✅  Setup Pipeline Completed Successfully!   ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "Now run the application:"
echo -e "👉 streamlit run apps/ui/Home.py"