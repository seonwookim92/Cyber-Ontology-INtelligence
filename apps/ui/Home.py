import streamlit as st
import sys
import os
import requests
import socket
from time import sleep

# [경로 설정]
# apps/ui/Home.py 위치에서 프로젝트 루트(coin)까지의 경로
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 1. 페이지 설정
# ==============================================================================
st.set_page_config(
    page_title="COIN",
    page_icon="🛡️",
    layout="wide"
)

# ==============================================================================
# 2. 헬퍼 함수: 상태 점검
# ==============================================================================

def check_neo4j_status():
    """Neo4j 도커 컨테이너 및 DB 접속 상태 확인"""
    try:
        # graph_client를 이용해 가벼운 쿼리 실행
        # 이것이 성공하면 도커 컨테이너가 켜져 있고, 포트가 열려 있고, 인증도 성공한 것임
        result = graph_client.query("RETURN 1")
        if result and result[0]['1'] == 1:
            return True, "Running"
    except Exception as e:
        return False, str(e)
    return False, "Connection Failed"

def check_llm_status():
    """LLM 서비스 상태 확인"""
    if settings.LLM_PROVIDER == "ollama":
        try:
            # Ollama Health check or Tags check
            res = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=2)
            if res.status_code == 200:
                return True, "Running (Local)"
        except:
            return False, "Ollama Stopped"
    else:
        # OpenAI는 API Key 존재 여부로 판단 (실제 호출은 비용 문제로 생략)
        if settings.OPENAI_API_KEY:
            return True, "Active (Cloud)"
        else:
            return False, "API Key Missing"
    return False, "Unknown"

# ==============================================================================
# 3. UI 구성
# ==============================================================================

# 헤더
hl = "color: #FF4B4B; font-weight: bold;"

st.markdown(f"""
    <h1 style='font-family: sans-serif;'>
        🛡️ COIN : 
        <span style='{hl}'>C</span>yber 
        <span style='{hl}'>O</span>ntology 
        <span style='{hl}'>IN</span>telligence
    </h1>
""", unsafe_allow_html=True)
st.markdown("##### *Knowledge Graph driven Threat Analysis Platform*")
st.markdown("---")

# 시스템 상태 대시보드 (Metrics)
st.subheader("📊 System Dashboard")
col1, col2, col3, col4 = st.columns(4)

# 1. LLM Provider Info
with col1:
    st.info("**AI Model Config**")
    current_model = settings.OPENAI_MODEL if settings.LLM_PROVIDER == 'openai' else settings.OLLAMA_MODEL
    st.write(f"- **Provider:** `{settings.LLM_PROVIDER.upper()}`")
    st.write(f"- **Model:** `{current_model}`")

# 2. Neo4j (Docker) Status
with col2:
    is_up, status_msg = check_neo4j_status()
    st.metric(
        label="Neo4j Container (Graph DB)", 
        value="Online" if is_up else "Offline", 
        delta="Connected" if is_up else "Error",
        delta_color="normal" if is_up else "inverse"
    )
    if not is_up:
        st.caption(f"⚠️ {status_msg}")

# 3. LLM Service Status
with col3:
    llm_up, llm_msg = check_llm_status()
    st.metric(
        label="LLM Service Status",
        value="Ready" if llm_up else "Not Ready",
        delta=llm_msg,
        delta_color="normal" if llm_up else "inverse"
    )

# 4. Data Graph Info
with col4:
    # DB에 있는 노드 개수 살짝 보여주기
    try:
        count_res = graph_client.query("MATCH (n) RETURN count(n) as cnt")
        total_nodes = count_res[0]['cnt'] if count_res else 0
        st.metric(label="Total Knowledge Nodes", value=f"{total_nodes:,}", delta="Entities")
    except:
        st.metric(label="Total Knowledge Nodes", value="Unknown", delta="Sync Error")

st.markdown("---")

# 네비게이션 가이드
st.subheader("🧭 Analysis Modules")
st.markdown("""
왼쪽 사이드바에서 분석 모드를 선택하세요. 이 시스템은 **MITRE ATT&CK, CISA KEV, URLHaus** 및 **생성된 시나리오** 데이터를 통합 분석합니다.
""")

# [변경] 4개의 컬럼으로 확장
mode_col1, mode_col2, mode_col3, mode_col4 = st.columns(4)

with mode_col1:
    st.markdown("""
    ### 1. Deep Analysis
    **심층 분석 및 프로파일링**
    * Incident, Threat Group, Malware, CVE에 대한 상세 정보를 조회합니다.
    * LLM과 그래프 데이터를 결합한 리포트를 제공합니다.
    """)

with mode_col2:
    st.markdown("""
    ### 2. Correlation
    **위협 연관성 분석**
    * IP, Hash, URL 등 파편화된 IoC를 입력하여 분석합니다.
    * 그래프 알고리즘을 통해 숨겨진 공격 캠페인과 배후를 추적합니다.
    """)

with mode_col3:
    st.markdown("""
    ### 3. Smart Agent
    **AI 자율 에이전트**
    * 자연어로 보안 관련 질문을 던져보세요.
    * AI가 스스로 Cypher 쿼리를 작성하여 DB를 탐색하고 답변합니다.
    """)

with mode_col4:
    st.markdown("""
    ### 4. Scenario Explorer
    **시나리오 탐색기 (New!)**
    * AI가 생성한 가상 침해 사고(Incident)를 조회합니다.
    * 공격 단계(Kill Chain)별 상세 흐름과 아티팩트를 시각화합니다.
    """)

# 푸터
st.markdown("---")
st.caption("© 2026 Cyber Ontology Intelligence Project. Powered by Neo4j & LangGraph.")