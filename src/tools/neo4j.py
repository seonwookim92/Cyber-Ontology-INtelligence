# src/tools/neo4j.py
import json
from langchain_core.tools import tool
from src.core.graph_client import graph_client

# --------------------------------------------------------------------------
# 내부 헬퍼 함수
# --------------------------------------------------------------------------
def _execute_cypher(query: str, params: dict = None) -> str:
    try:
        results = graph_client.query(query, params)
        if not results: return "No results found."
        return json.dumps(results, ensure_ascii=False, default=str)[:4000]
    except Exception as e:
        return f"Cypher Error: {e}"

# --------------------------------------------------------------------------
# Tools 정의
# --------------------------------------------------------------------------
@tool
def inspect_schema() -> str:
    """Returns the current graph schema (Incident -> AttackStep -> Entity)."""
    return """
    [Graph Schema]
    Nodes: (:Incident), (:AttackStep), (:Entity {name, type})
    Rels: (:Incident)-[:HAS_ATTACK_FLOW]->(:AttackStep)-[:INVOLVES_ENTITY]->(:Entity)
    """

@tool
def search_keyword_context(keyword: str) -> str:
    """
    Search for a keyword (IP, CVE, Hash) and return its Incident Context.
    """
    # [수정된 쿼리 적용 완료]
    query = """
    MATCH (e:Entity)
    WHERE toLower(e.name) CONTAINS toLower($kw) 
       OR toLower(e.original_value) CONTAINS toLower($kw)
       OR toLower(e.type) CONTAINS toLower($kw)
    MATCH path = (i:Incident)-[:HAS_ATTACK_FLOW]->(s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    OPTIONAL MATCH (s)-[:INVOLVES_ENTITY]->(peer:Entity) WHERE peer <> e
    RETURN i.title, i.summary, s.phase, s.description, e.name, e.type, collect(distinct peer.name) as Related
    LIMIT 5
    """
    return _execute_cypher(query, {"kw": keyword})

@tool
def explore_incident_correlations(entity_name: str) -> str:
    """Check if an entity appears across multiple Incidents."""
    query = """
    MATCH (e:Entity {name: $val})<-[:INVOLVES_ENTITY]-(s:AttackStep)<-[:HAS_ATTACK_FLOW]-(i:Incident)
    RETURN i.title, i.timestamp, s.phase
    ORDER BY i.timestamp DESC LIMIT 10
    """
    return _execute_cypher(query, {"val": entity_name})

@tool
def run_cypher(query: str) -> str:
    """Execute READ-ONLY Cypher query."""
    forbidden = ["CREATE", "DELETE", "DETACH", "SET", "MERGE"]
    if any(cmd in query.upper() for cmd in forbidden): return "Error: Read-only only."
    return _execute_cypher(query)

# ★ 핵심: 이 파일에서 제공하는 도구 리스트를 export 합니다.
NEO4J_TOOLS = [inspect_schema, search_keyword_context, explore_incident_correlations, run_cypher]