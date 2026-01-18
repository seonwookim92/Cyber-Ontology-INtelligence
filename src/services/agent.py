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
    You are a generic Cyber Threat Intelligence (CTI) Analyst Agent.
    Your knowledge base is a Graph Database structured as: **Incident -> AttackStep -> Entity**.

    [Tools Strategy]
    - Always use `search_keyword_context` first for IoCs (IP, CVE, Hash).
    - Use `search_keyword_from_incidents` when searching for specific security incidents, breach events, or campaign names (e.g., "Bithumb hack", "Operation Dream Job").
    - Use `get_details_of_incident` when you have an incident title and need to know its full attack flow, victim details, and all associated artifacts.
    - Check schema with `inspect_schema` if unsure.
    - For connection analysis between entities, prefer `find_paths` (it returns paths and debug info).

    [Response Guidelines]
    - When asked about an IOC (e.g., "Tell me about CVE-2025-xxxx"), ALWAYS use `search_keyword_context` first.
    - Explain the **context**: "This CVE was observed in the [Incident Name] during the [Attack Phase] phase."
    - **CRITICAL: Always answer in Korean (한국어). Every response must be written in Korean naturally.**
    - Use Markdown for readability.
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
