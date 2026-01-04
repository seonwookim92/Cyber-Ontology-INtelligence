import streamlit as st
import sys
import os
import requests
import socket
from time import sleep

# [경로 설정]
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 1. 페이지 설정
# ==============================================================================
st.set_page_config(
    page_title="COIN Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ==============================================================================
# 2. 헬퍼 함수: 상태 점검
# ==============================================================================

def check_neo4j_status():
    """Neo4j 도커 컨테이너 및 DB 접속 상태 확인"""
    try:
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
            res = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=2)
            if res.status_code == 200:
                return True, "Running (Local)"
        except:
            return False, "Ollama Stopped"
    else:
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

# 2. Neo4j Status
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

# 3. LLM Status
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
    try:
        # 전체 노드 수 확인
        total_res = graph_client.query("MATCH (n) RETURN count(n) as cnt")
        total_nodes = total_res[0]['cnt'] if total_res else 0
        
        # Incident(시나리오) 수 확인
        inc_res = graph_client.query("MATCH (n:Incident) RETURN count(n) as cnt")
        total_incidents = inc_res[0]['cnt'] if inc_res else 0
        
        st.metric(
            label="Total Intelligence", 
            value=f"{total_incidents} Incidents", 
            delta=f"Nodes: {total_nodes:,}"
        )
    except:
        st.metric(label="Knowledge Graph", value="Unknown", delta="Sync Error")

st.markdown("---")

# ==============================================================================
# 4. 주요 분석 모듈 소개 (Files 1~4)
# ==============================================================================
st.subheader("🧭 Core Analysis Modules")
st.markdown("사이드바 메뉴를 통해 아래 4가지 핵심 분석 도구를 사용할 수 있습니다.")

# 4개의 컬럼 (1, 2, 3, 4번 파일 대응)
mode_col1, mode_col2, mode_col3, mode_col4 = st.columns(4)

with mode_col1:
    st.markdown("""
    #### 1. Deep Analysis
    **🔎 심층 분석 및 프로파일링**
    * Threat Group, Malware 상세 정보 조회
    * LLM 기반 Graph RAG 리포트 생성
    * 엔티티 중심의 심층 정보 탐색
    """)

with mode_col2:
    st.markdown("""
    #### 2. Correlation
    **🔗 위협 연관성 분석**
    * IoC (IP, Hash, URL) 간의 연결고리 추적
    * 그래프 알고리즘을 통한 배후 공격 그룹 식별
    * 숨겨진 위협 패턴 시각화
    """)

with mode_col3:
    st.markdown("""
    #### 3. Graph Analysis
    **🎬 공격 시나리오 탐색**
    * AI가 추출한 Incident 구조(Incident-Step-Entity) 시각화
    * Kill Chain 단계별 공격 흐름(Attack Flow) 추적
    * 사건 중심의 맥락 파악
    """)

with mode_col4:
    st.markdown("""
    #### 4. Ontology Extractor
    **📝 비정형 리포트 처리**
    * CTI 텍스트 리포트 업로드 및 분석
    * LLM을 활용한 자동 구조화 (Entity Extraction)
    * Neo4j 지식 그래프로 데이터 적재
    """)

# ==============================================================================
# 5. 스마트 에이전트 (강조 섹션 - File 5)
# ==============================================================================
st.markdown("---")
st.subheader("🤖 Smart Agent (AI Analyst)")

# 강조 박스 (Success, Info, or Warning color)
with st.container():
    st.success("""
    ### 💬 "Ask Anything to your Knowledge Graph"
    
    **Smart Agent**는 단순한 챗봇이 아닙니다. **Neo4j 그래프 데이터베이스와 실시간으로 연동**되는 AI 보안 분석가입니다.
    
    * **Context-Aware Search:** "이 취약점은 어떤 사건에서 발견됐어?"라고 물으면 사건의 맥락(Incident -> Step -> Entity)을 파악해 답변합니다.
    * **Natural Language Query:** 복잡한 Cypher 쿼리를 몰라도 한국어로 질문하면 자동으로 데이터를 찾아줍니다.
    * **Cross-Analysis:** 여러 사건에 걸쳐 등장하는 공격자나 도구를 자동으로 연결해줍니다.
    
    👉 **왼쪽 사이드바에서 `5_Smart_Agent`를 선택하여 대화를 시작하세요.**
    """, icon="🧠")

# 푸터
st.markdown("---")
st.caption("© 2026 Cyber Ontology Intelligence Project. Powered by Neo4j & LangGraph.")