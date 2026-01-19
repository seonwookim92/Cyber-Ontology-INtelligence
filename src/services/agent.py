# src/services/agent.py
from typing import List, TypedDict, Annotated
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.messages import SystemMessage, BaseMessage

from src.core.config import settings
# [변경] 여기서 tools 모듈을 임포트합니다.
# Use the extended toolset (includes find_paths, schema introspection, traversal helpers)
from src.tools.neo4j import NEO4J_TOOLS_EXTENDED as NEO4J_TOOLS
# from src.tools.virustotal import VIRUSTOTAL_TOOLS (나중에 이렇게 추가)

# 1. 사용할 모든 도구 합치기
ALL_TOOLS = NEO4J_TOOLS  # + VIRUSTOTAL_TOOLS + TAVILY_TOOLS

# 2. 에이전트 상태 정의
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]

def build_agent_graph():
    # LLM 설정
    if settings.LLM_PROVIDER == "openai":
        llm = ChatOpenAI(model=settings.OPENAI_MODEL, temperature=0)
    else:
        llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0)
    
    # 도구 바인딩
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    # 시스템 프롬프트
    system_prompt = """
    당신은 고급 사이버 위협 인텔리전스(CTI) 분석 에이전트입니다.
    당신의 지식 베이스는 **Incident -> AttackStep -> Entity** 구조의 지식 그래프입니다.

    [운용 전략]
    1. **기본 검색**: 단순한 IoC나 인시던트 조회는 정의된 도구(`search_keyword_context`, `search_keyword_from_incidents` 등)를 우선 사용하세요.
    2. **구조 파악**: 그래프 구조나 속성이 생소하다면 `inspect_schema`, `list_labels`, `list_properties`를 사용하여 먼저 구조를 파악하세요.
    3. **복합 질문 대응**: 사전에 정의된 도구만으로 해결할 수 없는 복합적인 질문(예: 특정 기술을 공유하는 그룹 나열, 특정 날짜 이후의 통계 등)이 들어오면, `run_cypher` 도구를 사용하여 **직접 Cypher 쿼리를 작성**하여 해결하세요.
    4. **유연성**: 사용자 질문이 예상 범위를 벗어날수록 그래프 스키마를 확인하고 직접 쿼리하는 전략을 적극 활용하세요.

    [Response Guidelines]
    - 반드시 **한국어(Korean)**로 답변하세요. 모든 응답은 자연스러운 한국어로 작성되어야 합니다.
    - Markdown을 사용하여 가독성을 높이세요.
    - 분석 결과의 근거가 되는 그래프 단서(인시던트 명, 공격 단계 등)를 명확히 제시하세요.
    """

    # 챗봇 노드
    def chatbot(state: AgentState):
        messages = state["messages"]
        if not isinstance(messages[0], SystemMessage):
            messages = [SystemMessage(content=system_prompt)] + messages
        return {"messages": [llm_with_tools.invoke(messages)]}

    # 그래프 구성
    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("chatbot", chatbot)
    graph_builder.add_node("tools", ToolNode(ALL_TOOLS)) # 도구 노드

    graph_builder.add_edge(START, "chatbot")
    graph_builder.add_conditional_edges("chatbot", tools_condition)
    graph_builder.add_edge("tools", "chatbot")

    return graph_builder.compile()
