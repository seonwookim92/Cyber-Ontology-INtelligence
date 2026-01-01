import json
from typing import TypedDict, Annotated, List, Union
from typing_extensions import Literal

from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, BaseMessage

# [LangGraph Core Components]
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 1. 내부 헬퍼 함수 (Cypher Logic)
# ==============================================================================

def _execute_cypher_logic(query: str, params: dict = None) -> str:
    try:
        results = graph_client.query(query, params)
        if not results:
            return "No results found."
        return json.dumps(results, ensure_ascii=False, default=str)
    except Exception as e:
        return f"Cypher Execution Error: {str(e)}"

# ==============================================================================
# 2. 도구(Tools) 정의 (이전과 동일)
# ==============================================================================

@tool
def inspect_schema() -> str:
    """
    [MUST USE FIRST] Returns the list of available Node Labels and Relationship Types.
    """
    try:
        q_labels = "CALL db.labels() YIELD label RETURN collect(label) as labels"
        labels = graph_client.query(q_labels)[0]['labels']
        q_rels = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as rels"
        rels = graph_client.query(q_rels)[0]['rels']
        q_indexes = "SHOW INDEXES YIELD name, type, properties WHERE type = 'FULLTEXT' RETURN name, properties"
        indexes = graph_client.query(q_indexes)

        return f"""
        [Graph Schema Info]
        - Node Labels: {', '.join(labels)}
        - Relationship Types: {', '.join(rels)}
        - Available Indexes: {json.dumps(indexes)}
        """
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def run_cypher(query: str) -> str:
    """
    Executes a specific Cypher query. 
    Use 'MATCH', 'WHERE toLower(n.prop) CONTAINS', and 'LIMIT'.
    """
    return _execute_cypher_logic(query)

@tool
def search_keyword(keyword: str) -> str:
    """
    [Fuzzy Search] Searches for a keyword across MITRE entities and Indicators.
    """
    q_fulltext = f"""
    CALL db.index.fulltext.queryNodes("mitre_text_index", "{keyword}") YIELD node, score
    RETURN labels(node)[0] as Type, node.name as Name, node.description as Desc, score LIMIT 5
    """
    q_indicator = f"""
    MATCH (i:Indicator)
    WHERE toLower(i.url) CONTAINS toLower("{keyword}") OR toLower(i.tags) CONTAINS toLower("{keyword}")
    RETURN 'Indicator' as Type, i.url as Name, i.tags as Desc, 1.0 as score LIMIT 5
    """
    res1 = _execute_cypher_logic(q_fulltext)
    res2 = _execute_cypher_logic(q_indicator)
    return f"MITRE Results:\n{res1}\n\nIndicator Results:\n{res2}"

@tool
def explore_entity_relations(identifier: str) -> str:
    """
    [Cross-Analysis] Retrieves all incoming and outgoing relationships for a specific entity ID/Name.
    """
    query = f"""
    MATCH (n)-[r]-(related)
    WHERE n.cve_id = "{identifier}" OR n.mitre_id = "{identifier}" OR n.name = "{identifier}" OR n.url = "{identifier}" OR n.id = "{identifier}"
    RETURN type(r) as Rel, labels(related)[0] as Type, related.name as Name, related.cve_id as CVE, related.url as URL LIMIT 50
    """
    return _execute_cypher_logic(query)

@tool
def detect_threat_correlation(artifacts: str) -> str:
    """
    [Deep Reasoning] Performs multi-layer correlation analysis for a comma-separated list of artifacts.
    """
    values = [v.strip() for v in artifacts.split(',') if v.strip()]
    if not values: return "Error: No artifacts."
    
    query = f"""
    WITH {json.dumps(values)} AS inputs
    MATCH (n) WHERE n.name IN inputs OR n.cve_id IN inputs OR n.product IN inputs OR n.url IN inputs
    MATCH (n)-[r]-(hub)-[r2]-(other)
    WHERE hub <> n AND other <> n
    WITH hub, count(distinct n) as connected_count, collect(distinct n.name) as connected_sources
    WHERE connected_count > 1
    RETURN labels(hub)[0] as HubType, hub.name as HubName, connected_count, connected_sources
    ORDER BY connected_count DESC LIMIT 5
    """
    return _execute_cypher_logic(query)

# ==============================================================================
# 3. 그래프 정의 (StateGraph 방식)
# ==============================================================================

# 3-1. 상태(State) 정의: 메시지 목록을 저장
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]

def build_agent_graph():
    # 1. LLM 설정
    if settings.LLM_PROVIDER == "openai":
        llm = ChatOpenAI(model=settings.OPENAI_MODEL, api_key=settings.OPENAI_API_KEY, temperature=0)
    else:
        llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0, base_url=settings.OLLAMA_BASE_URL)

    # 2. 도구 바인딩
    tools = [inspect_schema, run_cypher, search_keyword, explore_entity_relations, detect_threat_correlation]
    llm_with_tools = llm.bind_tools(tools)

    # 3. 시스템 메시지 설정
    system_message = SystemMessage(content=f"""
    You are a proactive Cyber Security Analyst Agent powered by a Neo4j Knowledge Graph.

    [Tools]
    1. **inspect_schema**: Check schema first.
    2. **search_keyword**: Use for fuzzy search.
    3. **explore_entity_relations**: Find connections for an entity.
    4. **detect_threat_correlation**: Find common links between multiple artifacts.
    5. **run_cypher**: Run specific queries.

    [Rules]
    - Use 'MATCH' to find patterns.
    - Use 'toLower()' for case-insensitive matching.
    - Answer in Korean (한국어).
    """)

    # 4. 노드 함수 정의 (Chatbot)
    def chatbot(state: AgentState):
        # 시스템 메시지가 없으면 맨 앞에 추가 (기존 대화 유지)
        messages = state["messages"]
        if not isinstance(messages[0], SystemMessage):
            messages = [system_message] + messages
        
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    # 5. 그래프 빌드 (Explicit StateGraph) 
    graph_builder = StateGraph(AgentState)

    # 노드 추가
    graph_builder.add_node("chatbot", chatbot)
    graph_builder.add_node("tools", ToolNode(tools))

    # 엣지 연결 (Start -> Chatbot -> Tools? -> Chatbot -> End)
    graph_builder.add_edge(START, "chatbot")
    
    # 조건부 엣지: LLM이 도구를 호출했으면 'tools'로, 아니면 'END'로
    graph_builder.add_conditional_edges(
        "chatbot",
        tools_condition,
    )
    # 도구 실행 후 다시 챗봇으로 돌아와서 결과를 해석하게 함
    graph_builder.add_edge("tools", "chatbot")

    # 컴파일
    graph = graph_builder.compile()
    
    return graph