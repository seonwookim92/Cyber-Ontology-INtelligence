#!/bin/bash

# ==============================================================================
# 🛡️ COIN: Cyber Ontology Intelligence - Setup Pipeline
# ==============================================================================

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}    🛡️  COIN Setup: Full Data Pipeline Execution    ${NC}"
echo -e "${BLUE}======================================================${NC}"

# ------------------------------------------------------------------------------
# 0. 사전 체크 및 권한 조정
# ------------------------------------------------------------------------------
if [ ! -f ".env" ]; then
    echo -e "${RED}[Error] .env file not found. Please copy .env.example to .env first.${NC}"
    exit 1
fi

# Load environment variables from .env for cypher-shell authentication
set -o allexport
source .env
set +o allexport

# 💡 권한 관련 참고: Neo4j 컨테이너(Docker)를 사용할 경우, 볼륨 매핑된 폴더의 소유권이 
# Neo4j 기본 유저(ID: 7474)로 변경될 수 있습니다. 이를 현재 유저로 다시 조정합니다.
echo -e "${YELLOW}[System] Checking directory permissions...${NC}"
mkdir -p data/raw data/processed data/generated
# 현재 실행 유저의 권한으로 재조정 (필요 시 sudo 사용 권장)
# Try to set ownership to the current user to avoid Neo4j (uid 7474) owning files.
if command -v id >/dev/null 2>&1; then
    CUR_UID=$(id -u)
    CUR_GID=$(id -g)
else
    CUR_UID=1000
    CUR_GID=1000
fi
if [ "$EUID" -ne 0 ]; then
    sudo chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || echo "Warning: chown failed or sudo required."
else
    chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || true
fi
echo -e "\n[Info] Restoring host ownership for 'data/' to current user..."
if [ "$EUID" -ne 0 ]; then
     sudo chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || echo "[Warn] chown failed or sudo required."
else
     chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || true
fi
chmod -R 755 data/
echo -e "  - Ownership set to ${CUR_UID}:${CUR_GID} and permissions updated to 755 for data directories."

# ------------------------------------------------------------------------------
# 1. 데이터 준비 (다운로드 및 파일 전처리)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 1] Preparing Raw Data (Download & Preprocess)...${NC}"

# (1) 기반 데이터 다운로드
echo -e "  - Downloading CISA KEV..."
bash scripts/setup/download_cisa_kev.sh
echo -e "  - Downloading MITRE ATT&CK..."
bash scripts/setup/download_mitre_attack.sh
echo -e "  - Downloading URLHaus..."
bash scripts/setup/download_urlhaus_online_csv.sh

# (2) 데이터 전처리 (Raw -> Processed JSON)
echo -e "  - Preprocessing Data..."
python scripts/etl/preprocess_kev.py
python scripts/etl/preprocess_mitre.py
python scripts/etl/preprocess_urlhaus.py

# ------------------------------------------------------------------------------
# 2. DB 초기화 (스키마 설정)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 2] Initializing Neo4j Database...${NC}"

# Verify required processed CSVs exist before initializing DB
REQUIRED_FILES=(
    "data/processed/mitre_nodes.csv"
    "data/processed/mitre_rels.csv"
    "data/processed/cisa_kev_clean.csv"
    "data/processed/urlhaus_indicators.csv"
)
MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo -e "[Error] Required file missing: $f"
        MISSING=1
    fi
done
if [ "$MISSING" -eq 1 ]; then
    echo -e "${RED}[Fatal] One or more required CSVs are missing in data/processed.\nPlease run preprocessing scripts (scripts/etl/*.py) or download data before initializing the DB.${NC}"
    exit 1
fi

python scripts/setup/init_db.py

# ------------------------------------------------------------------------------
# 3. 시나리오 데이터 확보 (Check Existing / Download / Generate)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 3] Incident Scenario Preparation...${NC}"

GIST_URL="https://gist.github.com/seonwookim92/50c01163876100642d927ee895fbd5fc/raw/bd5482941cc35f95fe19a36bcc99caf629d4ffa8/incidents.json"
INCIDENT_FILE="data/generated/incidents.json"

# [추가] 기존 파일 존재 여부 및 시나리오 개수 확인
if [ -f "$INCIDENT_FILE" ]; then
    # JSON 배열 내의 객체 개수를 대략적으로 파악 ({ } 의 개수)
    # jq가 설치되어 있다면 더 정확하지만, 범용성을 위해 grep 사용
    COUNT=$(grep -c "{" "$INCIDENT_FILE" || echo "0")
    echo -e "${YELLOW}📍 Found existing scenario file: $INCIDENT_FILE (${COUNT} incidents)${NC}"
    echo -e "Would you like to use this existing file or replace it?"
    echo -e "  1) Use existing file (Keep)"
    echo -e "  2) Download fresh from Gist (Replace)"
    echo -e "  3) Generate new via AI (Replace)"
    read -p "Select option [1-3]: " SCENARIO_OPT
else
    echo -e "No existing scenario file found."
    echo -e "  1) Download from Gist"
    echo -e "  2) Generate via AI"
    echo -e "  3) Skip"
    read -p "Select option [1-3]: " SCENARIO_OPT
    # 선택지 번호 보정을 위해 1을 입력하면 Gist로, 2를 입력하면 AI로 가도록 아래 case에서 처리
fi

case $SCENARIO_OPT in
    1)
        if [ -f "$INCIDENT_FILE" ] && [ "$COUNT" != "" ]; then
            echo -e "✅ Using existing file with $COUNT incidents."
        else
            echo -e "📥 Downloading scenarios from Gist..."
            curl -L "$GIST_URL" -o "$INCIDENT_FILE"
            echo -e "${GREEN}Successfully downloaded.${NC}"
        fi
        ;;
    2)
        # 기존 파일이 있는데 2번을 눌렀다면 Gist 다운로드 (Replace 상황)
        if [ -f "$INCIDENT_FILE" ]; then
            echo -e "📥 Replacing with fresh data from Gist..."
            curl -L "$GIST_URL" -o "$INCIDENT_FILE"
        else
            # 파일이 없는데 2번을 눌렀다면 AI 생성
            read -p "Enter number of incidents to generate: " INCIDENT_COUNT
            python scripts/setup/generate_incidents.py --count "${INCIDENT_COUNT:-0}"
        fi
        ;;
    3)
        # 기존 파일이 있는데 3번을 눌렀다면 AI 생성
        if [ -f "$INCIDENT_FILE" ]; then
            read -p "Enter number of incidents to generate: " INCIDENT_COUNT
            python scripts/setup/generate_incidents.py --count "${INCIDENT_COUNT:-0}"
        else
            echo -e "⏩ Skipping scenario preparation."
        fi
        ;;
    *)
        echo -e "⏩ Skipping or using existing state."
        ;;
esac

# ------------------------------------------------------------------------------
# 4. 데이터 최종 적재 (Ingestion)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 4] Ingesting Incidents into Knowledge Graph...${NC}"

# 기존 적재 기록 초기화
IMPORTED_LOG="data/processed/incidents_imported.json"
if [ -f "$IMPORTED_LOG" ]; then
    rm "$IMPORTED_LOG"
fi

if [ -f "$INCIDENT_FILE" ]; then
    python scripts/etl/process_incidents.py
else
    echo -e "${YELLOW}No incident file found at $INCIDENT_FILE. Skipping ingestion.${NC}"
fi

# ----------------------------------------------------------------------------
# 4.5 Ensure fulltext index exists (nodesFullText)
# ----------------------------------------------------------------------------
echo -e "\n${GREEN}[Phase 4.5] Ensuring fulltext index 'nodesFullText' exists...${NC}"
CONTAINER_NAME="neo4j-cyber"
FT_INDEX_NAME="nodesFullText"
FT_CREATE_CMD="CREATE FULLTEXT INDEX ${FT_INDEX_NAME} IF NOT EXISTS FOR (n:BaseNode|Incident|Indicator|Malware|Vulnerability) ON EACH [n.name, n.value, n.url, n.cve_id, n.indicator, n.description];"

exists=0
for i in {1..3}; do
    docker exec -i ${CONTAINER_NAME} cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "SHOW FULLTEXT INDEXES;" | grep -i "${FT_INDEX_NAME}" >/dev/null 2>&1 && exists=1 && break
    if [ $i -eq 1 ]; then
        echo -e "  - Fulltext index '${FT_INDEX_NAME}' not found. Creating..."
        docker exec -i ${CONTAINER_NAME} cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "${FT_CREATE_CMD}"
    else
        echo -e "  - Waiting for index to appear (attempt ${i})..."
    fi
    sleep 3
done

if [ $exists -eq 0 ]; then
    echo -e "  - Verifying index creation..."
    # wait until populationPercent reaches 100 or timeout
    for j in {1..20}; do
        out=$(docker exec -i ${CONTAINER_NAME} cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "SHOW FULLTEXT INDEXES;" 2>/dev/null | grep -i "${FT_INDEX_NAME}" || true)
        if [ -n "$out" ]; then
            echo -e "  - Index '${FT_INDEX_NAME}' detected: $out"
            break
        fi
        sleep 3
    done
fi


# Ensure files are owned by current user after pipeline (Neo4j may have created files as uid 7474)
if command -v id >/dev/null 2>&1; then
    CUR_UID=$(id -u)
    CUR_GID=$(id -g)
    if [ "$EUID" -ne 0 ]; then
        sudo chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || true
    else
        chown -R "${CUR_UID}:${CUR_GID}" data/ 2>/dev/null || true
    fi
fi

echo -e "\n${BLUE}======================================================${NC}"
echo -e "${BLUE}    ✅  Setup Pipeline Completed Successfully!    ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "👉 streamlit run apps/ui/Home.py"