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
            
            Example format: 이 공격에 사용된 다른 IP는 뭐야?|관련된 해킹 그룹은 누구야?|대응 방안은 어떻게 돼?
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
st.set_page_config(page_title="Smart Agent", page_icon="🕵️‍♂️", layout="wide")

st.title("🕵️‍♂️ Smart Agent (Chatbot)")
st.markdown("""
**Neo4j Knowledge Graph**와 연동된 AI 보안 분석가입니다.  
**Incident(사건), Malware, Threat Group, IoC** 정보를 문맥(Context) 기반으로 답변합니다.
""")

# ==============================================================================
# 2. Session State 초기화
# ==============================================================================
if "messages" not in st.session_state:
    st.session_state.messages = []

if "langchain_history" not in st.session_state:
    st.session_state.langchain_history = []

# 입력 트리거 관리를 위한 변수
if "trigger_query" not in st.session_state:
    st.session_state.trigger_query = None

# 마지막 답변에 대한 후속 질문 리스트 저장
if "followup_suggestions" not in st.session_state:
    st.session_state.followup_suggestions = []

# ==============================================================================
# 3. 사이드바: 샘플 질문 (업데이트됨)
# ==============================================================================
with st.sidebar:
    st.header("📝 Sample Questions")
    st.caption("클릭하면 자동으로 질문합니다.")
    
    # [변경] 스키마(Incident -> Step -> Entity)에 맞춘 질문들로 교체
    sample_questions = [
        "현재 데이터베이스의 스키마 구조(Incident, Entity 등)를 알려줘.",
        "CVE-2025-14847 취약점과 '한국수력원자력 원전제어망' 사이에 연결점(연관성)이 있는지 찾아줘.",
        "블록체인 또는 가상화폐와 관련된 사건을 어떤 공격자가 주로 하고 있는지 찾아줘.",
        "IP '101.35.56.7'이 포함된 침해 사고 정보를 찾아줘.",
        "최근 6개월 내에 'Turla' 위협 그룹이 관련된 사건들을 알려줘.",
        "Malware 'TrickBot'이 연관된 사건들의 IoC들을 찾아줘"
    ]

    for q in sample_questions:
        if st.button(q, use_container_width=True):
            st.session_state.trigger_query = q
            st.session_state.followup_suggestions = [] # 새 질문이므로 기존 추천 초기화
            st.rerun()
            
    st.markdown("---")
    st.info("💡 **Tip:** 리포트를 먼저 `Intelligence Processing` 메뉴에서 등록해야 답변이 가능합니다.")

# ==============================================================================
# 4. 메인 로직 함수
# ==============================================================================
# ==============================================================================
# 4. 메인 로직 함수
# ==============================================================================
def process_query(user_input):
    # 1. 사용자 메시지 UI 표시 및 저장
    st.session_state.messages.append({"role": "user", "content": user_input})
    
    # 2. 에이전트 실행
    final_response = ""
    current_steps = [] # 이번 턴의 도구 호출 기록 저장용
    
    # UI에 그리기
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
                    
                    # Tool 호출 결정 시
                    if isinstance(last_msg, AIMessage) and last_msg.tool_calls:
                        for tc in last_msg.tool_calls:
                            step_count += 1
                            msg_text = f"**Step {step_count}:** 🤔 Decided to use tool `{tc['name']}`"
                            st.write(msg_text)
                            current_steps.append({"type": "call", "count": step_count, "name": tc['name'], "args": tc['args']})
                            with st.expander(f"Arguments for {tc['name']}", expanded=False):
                                st.code(json.dumps(tc['args'], indent=2, ensure_ascii=False), language="json")

                    # Tool 실행 결과
                    elif isinstance(last_msg, ToolMessage):
                        msg_text = f"**Step {step_count}:** 🔍 Tool Output (`{last_msg.name}`)"
                        st.write(msg_text)
                        current_steps.append({"type": "result", "count": step_count, "name": last_msg.name, "content": last_msg.content})
                        with st.expander("Show Result", expanded=False):
                            raw = last_msg.content or ""
                            try:
                                content_json = json.loads(raw)
                                st.json(content_json)
                            except Exception:
                                st.code(raw, language="text")

                    # 최종 답변
                    elif isinstance(last_msg, AIMessage) and last_msg.content:
                        if not last_msg.tool_calls:
                            final_response = last_msg.content
            
            status_placeholder.update(label="✅ Analysis Complete", state="complete", expanded=False)
            
            if final_response:
                response_placeholder.markdown(final_response)
                
                # 대화 기록 저장 (steps 포함)
                st.session_state.messages.append({
                    "role": "assistant", 
                    "content": final_response,
                    "steps": current_steps
                })
                st.session_state.langchain_history.append(current_human_msg)
                st.session_state.langchain_history.append(AIMessage(content=final_response))
                
                # 후속 질문 생성
                suggestions = generate_followup_questions(user_input, final_response)
                st.session_state.followup_suggestions = suggestions
                st.rerun()
                
            else:
                response_placeholder.error("죄송합니다. 답변을 생성하지 못했습니다.")

        except Exception as e:
            status_placeholder.update(label="❌ Error Occurred", state="error")
            st.error(f"Error Details: {e}")

# ==============================================================================
# 5. 화면 렌더링 루프
# ==============================================================================

# A. 이전 대화 기록 출력 
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        # [추가] 에이전트의 사고 과정(Steps)이 있다면 확장 버튼으로 표시
        if msg["role"] == "assistant" and msg.get("steps"):
            with st.expander("🔍 분석 사고 과정 (Tool Execution Logs)", expanded=False):
                for s in msg["steps"]:
                    if s["type"] == "call":
                        st.write(f"**Step {s['count']}:** 🛠️ `{s['name']}` 도구 사용 결정")
                        st.caption("입력 파라미터:")
                        st.code(json.dumps(s['args'], indent=2, ensure_ascii=False), language="json")
                    else:
                        st.write(f"**Step {s['count']}:** 📥 `{s['name']}` 실행 결과 수신")
                        try:
                            st.json(json.loads(s['content']))
                        except:
                            st.code(s['content'], language="text")
                st.divider()
        
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
if prompt := st.chat_input("보안 관련 질문을 입력하세요 (예: 이 IP는 어떤 사건과 연관돼?)..."):
    st.session_state.followup_suggestions = [] # 새 질문 입력 시 추천 초기화
    process_query(prompt)