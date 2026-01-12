import sys
import os
import json
import requests

# ------------------------------------------------------------------------------
# [설정] 프로젝트 루트 경로 확보
# ------------------------------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import settings
from src.core.fuseki import sparql_select

# Imports
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

# ------------------------------------------------------------------------------
# [Helper] 순수 로직 함수 (데코레이터 없음 -> 내부 호출 가능)
# ------------------------------------------------------------------------------

def _execute_sparql_logic(query: str) -> str:
    """
    SPARQL 쿼리를 실제로 실행하는 내부 헬퍼 함수입니다.
    Tool들이 공통으로 이 로직을 사용합니다.
    """
    clean_query = query.strip().strip('"').strip("'")
    try:
        full_query = f"{settings.SPARQL_PREFIXES}\n{clean_query}"
        
        response = requests.get(
            settings.SPARQL_QUERY_URL,
            params={"query": full_query, "format": "application/sparql-results+json"},
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        bindings = data.get("results", {}).get("bindings", [])
        
        if not bindings: return "No results found."

        simplified = []
        for row in bindings:
            item = {}
            for k, v in row.items():
                val = v.get("value", "")
                if "http://example.org/cyber#" in val: val = val.split("#")[-1]
                item[k] = val
            simplified.append(item)
            
        return json.dumps(simplified, ensure_ascii=False)

    except requests.exceptions.HTTPError as e:
        return f"SPARQL Syntax Error: {e.response.text}"
    except Exception as e:
        return f"System Error: {str(e)}"

# ------------------------------------------------------------------------------
# [1] 도구(Tools) 정의
# ------------------------------------------------------------------------------

@tool
def inspect_schema() -> str:
    """
    Use this tool FIRST to understand the database schema (Classes and Properties).
    Returns the list of available classes and properties in the ontology.
    """
    try:
        q_classes = f"SELECT DISTINCT ?type WHERE {{ GRAPH <{settings.CYBER_DATA_GRAPH}> {{ ?s a ?type }} }} ORDER BY ?type"
        rows_cls = sparql_select(q_classes)
        classes = [r.get('type_short', r.get('type')) for r in rows_cls]

        q_props = f"SELECT DISTINCT ?p WHERE {{ GRAPH <{settings.CYBER_DATA_GRAPH}> {{ ?s ?p ?o }} }} ORDER BY ?p"
        rows_prop = sparql_select(q_props)
        props = [r.get('p_short', r.get('p')) for r in rows_prop]

        return f"""
        [Ontology Schema Info]
        - Target Graph: {settings.CYBER_DATA_GRAPH}
        - Classes: {', '.join(classes)}
        - Properties: {', '.join(props)}
        - Use prefix ':' for <http://example.org/cyber#>
        """
    except Exception as e:
        return f"Error inspecting schema: {str(e)}"

@tool
def run_sparql(query: str) -> str:
    """
    Executes a SPARQL SELECT query. 
    Input must be a valid SPARQL query string using 'GRAPH <http://example.org/cyber/data>'.
    Prefixes are automatically handled.
    """
    # 내부 로직 함수 호출
    return _execute_sparql_logic(query)

@tool
def search_everywhere(keyword: str) -> str:
    """
    [POWERFUL] Search for a keyword (string) across ALL classes and properties in the database.
    Use this tool when specific queries return no results.
    This tool performs a fuzzy search (contains).
    """
    query = f"""
    SELECT ?entity ?type ?property ?value WHERE {{
        GRAPH <{settings.CYBER_DATA_GRAPH}> {{
            ?entity ?property ?value .
            OPTIONAL {{ ?entity a ?type }}
            FILTER(isLiteral(?value) && CONTAINS(LCASE(STR(?value)), LCASE("{keyword}")))
        }}
    }} LIMIT 20
    """
    # 내부 로직 함수 호출 (이제 에러가 나지 않습니다)
    return _execute_sparql_logic(query)

# ------------------------------------------------------------------------------
# [2] 에이전트 생성
# ------------------------------------------------------------------------------

def build_graph():
    print(f"🤖 LLM Provider: {settings.LLM_PROVIDER.upper()}")
    
    if settings.LLM_PROVIDER == "openai":
        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            api_key=settings.OPENAI_API_KEY,
            temperature=0
        )
    else:
        llm = ChatOllama(
            model=settings.OLLAMA_MODEL,
            temperature=0,
            base_url=settings.OLLAMA_BASE_URL
        )

    tools = [inspect_schema, run_sparql, search_everywhere]
    graph = create_react_agent(llm, tools)
    return graph

# ------------------------------------------------------------------------------
# [3] 메인 실행 루프
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n==================================================")
    print(" 🕵️‍♂️ Smart Agent (Reasoning Fixed)")
    print("==================================================")
    
    SYSTEM_PROMPT = f"""
    You are a proactive Cyber Security Analyst Agent.
    
    [Environment]
    - Database: Apache Jena Fuseki
    - Target Graph: <{settings.CYBER_DATA_GRAPH}>

    [Process & Rules]
    1. **Understand Schema First:** If you don't know the exact class names, use 'inspect_schema'.
    2. **Try Specific, Then Broad:** - Start with a specific SPARQL query.
       - **CRITICAL:** If no results, DO NOT give up. Immediately use 'search_everywhere' to look globally.
    3. **Self-Correction:** If a query fails, analyze the error and retry.
    4. **Direct Answer:** Run the query yourself and report findings.
    5. **Language:** Answer in Korean (한국어).
    """
    
    try:
        graph = build_graph()
        chat_history = []

        while True:
            user_input = input("\n질문 입력 (종료: q) > ").strip()
            if user_input.lower() in ["q", "quit", "exit"]: break
            if not user_input: continue
            
            print("\n--------------------------------------------------")
            print(" 🧠 Reasoning Trace (생각의 흐름)")
            print("--------------------------------------------------")
            
            messages = [SystemMessage(content=SYSTEM_PROMPT)] + chat_history + [HumanMessage(content=user_input)]
            final_answer = ""
            
            try:
                for event in graph.stream({"messages": messages}, stream_mode="values"):
                    current_messages = event["messages"]
                    if not current_messages: continue
                    last_msg = current_messages[-1]
                    
                    if isinstance(last_msg, AIMessage):
                        if last_msg.tool_calls:
                            for tc in last_msg.tool_calls:
                                print(f"\n  🤔 [Thought] 도구 사용 결정")
                                print(f"  🔨 [Action] {tc['name']} (Input: {tc['args']})")
                        elif last_msg.content:
                            final_answer = last_msg.content

                    elif isinstance(last_msg, ToolMessage):
                        print(f"  🔍 [Observation] 결과 수신 완료 ({len(last_msg.content)} chars)")
                        # 결과 미리보기 (150자 제한)
                        preview = last_msg.content.replace('\n', ' ')
                        if len(preview) > 150: preview = preview[:150] + "..."
                        print(f"     >> {preview}")

                print("\n--------------------------------------------------")
                print(f"🤖 [Final Answer]\n{final_answer}")
                print("--------------------------------------------------")
                
                chat_history.append(HumanMessage(content=user_input))
                chat_history.append(AIMessage(content=final_answer))

            except Exception as e:
                print(f"❌ 오류 발생: {e}")

    except Exception as e:
        print(f"❌ 초기화 오류: {e}")