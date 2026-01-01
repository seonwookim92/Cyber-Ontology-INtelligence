import streamlit as st
import sys
import os
import json
import time

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import agent
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser

from src.core.config import settings

# ==============================================================================
# 0. 헬퍼 함수: 후속 질문 생성기
# ==============================================================================
def generate_followup_questions(last_query, last_answer):
    """
    LLM을 이용해 사용자가 다음에 물어볼 만한 질문 3가지를 생성합니다.
    """
    try:
        # 가벼운 모델 사용 (빠른 응답을 위해)
        if settings.LLM_PROVIDER == "openai":
            llm = ChatOpenAI(model="gpt-4o-mini", api_key=settings.OPENAI_API_KEY, temperature=0.7)
        else:
            llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0.7, base_url=settings.OLLAMA_BASE_URL)

        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful assistant suggesting follow-up questions for a cyber security analyst."),
            ("human", f"""
            Based on the user's previous question and the agent's answer, suggest 3 short, relevant follow-up questions in Korean.
            Return ONLY the questions, separated by pipes (|). Do not add numbering or quotes.
            
            [User Question] {last_query}
            [Agent Answer] {last_answer}
            
            Example format: 이 악성코드의 침해지표(IOC)는 뭐야?|관련된 대응 방안은?|어떤 그룹이 배후야?
            """)
        ])
        
        chain = prompt | llm | StrOutputParser()
        result = chain.invoke({})
        return [q.strip() for q in result.split('|') if q.strip()][:3]
    except:
        return [] # 에러 나면 추천 질문 안 띄움

# ==============================================================================
# 1. 페이지 설정
# ==============================================================================
st.set_page_config(page_title="Cyber Threat Analyst", page_icon="🕵️‍♂️", layout="wide")

st.title("🕵️‍♂️ Neo4j Cyber Threat Analyst")
st.markdown("""
Neo4j Knowledge Graph를 기반으로 보안 위협을 분석하는 AI 에이전트입니다.  
**MITRE ATT&CK, CISA KEV, URLHaus** 데이터를 교차 분석하여 답변합니다.
""")

# ==============================================================================
# 2. Session State 초기화
# ==============================================================================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "langchain_history" not in st.session_state:
    st.session_state.langchain_history = []

# [변경] 입력 트리거 관리를 위한 변수
if "trigger_query" not in st.session_state:
    st.session_state.trigger_query = None

# [신규] 마지막 답변에 대한 후속 질문 리스트 저장
if "followup_suggestions" not in st.session_state:
    st.session_state.followup_suggestions = []

# ==============================================================================
# 3. 사이드바: 샘플 질문
# ==============================================================================
with st.sidebar:
    st.header("📝 Sample Questions")
    sample_questions = [
        "이 데이터베이스의 스키마 구조를 알려줘.",
        "최근 'MongoDB'와 관련된 취약점(CVE)이 있어?",
        "Mozi 봇넷과 관련된 악성 URL 5개만 찾아줘.",
        "CVE-2025-14733 취약점은 어떤 공격 기법이랑 연관돼?",
        "APT29 그룹이 사용하는 악성코드들은 뭐야?",
        "IP '1.2.3.4'나 해시값 같은 아티팩트들 간의 숨겨진 연관성을 분석해줘. (테스트용)",
    ]

    for q in sample_questions:
        if st.button(q, use_container_width=True):
            st.session_state.trigger_query = q
            st.session_state.followup_suggestions = [] # 새 질문이므로 기존 추천 초기화
            st.rerun()

# ==============================================================================
# 4. 메인 로직 함수
# ==============================================================================
def process_query(user_input):
    # 1. 사용자 메시지 UI 표시 및 저장
    st.session_state.messages.append({"role": "user", "content": user_input})
    
    # 2. 에이전트 실행
    final_response = ""
    
    # UI에 그리기 (이전 메시지들은 아래 메인 루프에서 이미 그려짐)
    with st.chat_message("user"):
        st.markdown(user_input)

    with st.chat_message("assistant"):
        response_placeholder = st.empty()
        status_placeholder = st.status("🧠 Agent is reasoning...", expanded=True)
        
        try:
            graph = agent.build_agent_graph()
            current_human_msg = HumanMessage(content=user_input)
            input_messages = st.session_state.langchain_history + [current_human_msg]
            
            step_count = 0
            
            with status_placeholder:
                for event in graph.stream({"messages": input_messages}, stream_mode="values"):
                    current_state_messages = event["messages"]
                    if not current_state_messages: continue
                    
                    last_msg = current_state_messages[-1]
                    
                    if isinstance(last_msg, AIMessage) and last_msg.tool_calls:
                        for tc in last_msg.tool_calls:
                            step_count += 1
                            st.write(f"**Step {step_count}:** 🤔 Decided to use tool `{tc['name']}`")
                            with st.expander(f"Arguments for {tc['name']}", expanded=False):
                                st.code(json.dumps(tc['args'], indent=2), language="json")

                    elif isinstance(last_msg, ToolMessage):
                        st.write(f"**Step {step_count}:** 🔍 Tool Output (`{last_msg.name}`)")
                        with st.expander("Show Result", expanded=False):
                            try:
                                content_json = json.loads(last_msg.content)
                                st.json(content_json)
                            except:
                                st.code(last_msg.content[:1000] + "...", language="text") # 너무 길면 자름

                    elif isinstance(last_msg, AIMessage) and last_msg.content:
                        if not last_msg.tool_calls:
                            final_response = last_msg.content
            
            status_placeholder.update(label="✅ Analysis Complete", state="complete", expanded=False)
            
            if final_response:
                response_placeholder.markdown(final_response)
                
                # 저장
                st.session_state.messages.append({"role": "assistant", "content": final_response})
                st.session_state.langchain_history.append(current_human_msg)
                st.session_state.langchain_history.append(AIMessage(content=final_response))
                
                # [신규] 후속 질문 생성 (비동기처럼 보이게 처리)
                suggestions = generate_followup_questions(user_input, final_response)
                st.session_state.followup_suggestions = suggestions
                st.rerun() # 추천 질문 렌더링을 위해 리런
                
            else:
                response_placeholder.error("답변을 생성하지 못했습니다.")

        except Exception as e:
            status_placeholder.update(label="❌ Error Occurred", state="error")
            st.error(f"Error: {e}")

# ==============================================================================
# 5. 화면 렌더링 루프
# ==============================================================================

# A. 이전 대화 기록 출력 
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# B. 후속 질문 선택지 출력 (마지막이 AI 답변일 때만)
if st.session_state.messages and st.session_state.messages[-1]["role"] == "assistant":
    if st.session_state.followup_suggestions:
        st.write("👉 **Suggested Questions:**")
        cols = st.columns(len(st.session_state.followup_suggestions))
        for idx, suggestion in enumerate(st.session_state.followup_suggestions):
            if cols[idx].button(suggestion, key=f"suggest_{len(st.session_state.messages)}_{idx}"):
                st.session_state.trigger_query = suggestion
                st.session_state.followup_suggestions = [] # 선택했으니 초기화
                st.rerun()

# C. 트리거 확인 (사이드바 또는 추천 질문 클릭 시)
if st.session_state.trigger_query:
    query = st.session_state.trigger_query
    st.session_state.trigger_query = None # 소비
    process_query(query)

# D. 채팅 입력창 (항상 최하단에 유지됨)
if prompt := st.chat_input("질문을 입력하세요..."):
    st.session_state.followup_suggestions = [] # 새 질문 입력 시 추천 초기화
    process_query(prompt)