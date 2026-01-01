import json
import sys
import os
from typing import Any

# 프로젝트 루트 경로 추가
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(CURRENT_DIR))) # src 위 coin 폴더까지 올라감
sys.path.append(PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP
from src.core.graph_client import graph_client
from src.core.config import settings

# MCP 서버 인스턴스 생성
mcp = FastMCP("Cyber Ontology Graph")

# ==============================================================================
# Tools (기능 노출)
# ==============================================================================

@mcp.tool()
def get_graph_schema() -> str:
    """
    Get the current graph schema definition.
    Essential for understanding how Incidents, Attack Steps, and Entities are connected.
    """
    return """
    [Graph Schema Definition]
    
    1. **Core Nodes**:
       - `(:Incident)`: Represents a security report or event (e.g., 'React2Shell Attack').
         - Properties: title, summary, timestamp
       - `(:AttackStep)`: Represents a specific phase in the attack lifecycle (e.g., 'Initial Access').
         - Properties: phase, description, step_num
       - `(:Entity)`: Represents an IoC or artifact (e.g., IP, Hash, CVE).
         - Properties: value, type (IP, Hash, Vulnerability, etc.), normalized_value
         
    2. **Relationships**:
       - `(:Incident)-[:HAS_ATTACK_FLOW]->(:AttackStep)`
       - `(:AttackStep)-[:INVOLVES_ENTITY]->(:Entity)`
    
    3. **Legacy/MITRE Nodes** (If exist):
       - `(:ThreatGroup)`, `(:Malware)`, `(:AttackTechnique)`
    """

@mcp.tool()
def search_keyword_context(keyword: str) -> str:
    """
    Search for a keyword (CVE, IP, Malware Name) and return its FULL CONTEXT.
    This tool finds which Incident it belongs to and at what Attack Step it was observed.
    
    Use this when user asks: "Tell me about CVE-2025-55182" or "What happened with IP x.x.x.x?"
    """
    # Cypher 쿼리: Entity -> Step -> Incident 역추적
    query = """
    // 1. 키워드 매칭 (이름, 값, 원본값)
    MATCH (e:Entity)
    WHERE toLower(e.value) CONTAINS toLower($kw) 
       OR toLower(e.normalized_value) CONTAINS toLower($kw)
       OR toLower(e.type) CONTAINS toLower($kw)
    
    // 2. 맥락(Context) 추적
    MATCH path = (i:Incident)-[:HAS_ATTACK_FLOW]->(s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    
    // 3. (옵션) 같은 단계의 다른 연관 엔티티도 함께 조회
    OPTIONAL MATCH (s)-[:INVOLVES_ENTITY]->(peer:Entity)
    WHERE peer <> e
    
    RETURN 
        i.title as Incident,
        i.summary as Summary,
        s.phase as Phase,
        s.description as StepDescription,
        e.value as FoundEntity,
        e.type as EntityType,
        collect(distinct peer.value) as RelatedContextArtifacts
    LIMIT 5
    """
    
    try:
        results = graph_client.query(query, {"kw": keyword})
        
        if not results:
            return f"No direct context found for '{keyword}'. It might not be in the graph yet."
            
        # LLM이 이해하기 쉬운 텍스트로 변환
        summary_lines = []
        for r in results:
            summary = (
                f"=== Found in Incident: '{r['Incident']}' ===\n"
                f"- Incident Summary: {r['Summary']}\n"
                f"- Attack Phase: {r['Phase']}\n"
                f"- Context: {r['StepDescription']}\n"
                f"- Entity Details: {r['FoundEntity']} ({r['EntityType']})\n"
                f"- Co-occurring Artifacts in this step: {', '.join(r['RelatedContextArtifacts'][:5])}\n"
            )
            summary_lines.append(summary)
            
        return "\n".join(summary_lines)
        
    except Exception as e:
        return f"Search Error: {str(e)}"

@mcp.tool()
def run_cypher_query(query: str) -> str:
    """
    Execute a direct Cypher query. Use this ONLY if 'search_keyword_context' fails 
    or if you need complex aggregations.
    
    Rules:
    - READ ONLY (MATCH, RETURN only).
    - Always use LIMIT.
    - Labels to use: Incident, AttackStep, Entity.
    """
    forbidden = ["CREATE", "DELETE", "DETACH", "SET", "MERGE", "DROP", "REMOVE"]
    if any(cmd in query.upper() for cmd in forbidden):
        return "Error: Only read-only queries are allowed."

    try:
        results = graph_client.query(query)
        if not results:
            return "No results found."
        return json.dumps(results, ensure_ascii=False, default=str)[:4000]
    except Exception as e:
        return f"Cypher Execution Error: {str(e)}"

@mcp.tool()
def analyze_incident_correlations(entity_value: str) -> str:
    """
    Find if an entity (e.g., an IP or Hash) appears across MULTIPLE Incidents.
    Useful for detecting campaigns or recurring threats.
    """
    query = """
    MATCH (e:Entity {value: $val})<-[:INVOLVES_ENTITY]-(s:AttackStep)<-[:HAS_ATTACK_FLOW]-(i:Incident)
    RETURN i.title as Incident, i.timestamp as Time, s.phase as Phase
    ORDER BY i.timestamp DESC
    """
    try:
        results = graph_client.query(query, {"val": entity_value})
        if not results:
            return "This entity appears in only one incident (or none)."
        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    mcp.run()