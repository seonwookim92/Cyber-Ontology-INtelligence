import json
import sys
import os
from typing import Any

# 프로젝트 루트 경로 추가 (src 모듈 import용)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
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
def get_schema() -> str:
    """
    Get the graph schema (Node Labels, Relationship Types, and Indexes).
    Use this to understand the database structure.
    """
    try:
        q_labels = "CALL db.labels() YIELD label RETURN collect(label) as labels"
        labels = graph_client.query(q_labels)[0]['labels']
        
        q_rels = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as rels"
        rels = graph_client.query(q_rels)[0]['rels']
        
        return f"""
        [Graph Schema]
        - Labels: {', '.join(labels)}
        - Relationships: {', '.join(rels)}
        - Core Entities: Vulnerability(cve_id), Malware(name), ThreatGroup(name), AttackTechnique(mitre_id), Indicator(url)
        """
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def run_cypher_query(query: str) -> str:
    """
    Execute a read-only Cypher query against Neo4j.
    - Use MATCH, WHERE, RETURN.
    - Use toLower() for case-insensitive comparison.
    - Example: MATCH (n:Malware) WHERE toLower(n.name) CONTAINS 'mozi' RETURN n LIMIT 5
    """
    # 안전장치: 데이터 조작 방지
    forbidden = ["CREATE", "DELETE", "DETACH", "SET", "MERGE", "DROP"]
    if any(cmd in query.upper() for cmd in forbidden):
        return "Error: Only read-only queries (MATCH, RETURN) are allowed via MCP."

    try:
        results = graph_client.query(query)
        if not results:
            return "No results found."
        # 결과가 너무 길면 잘라서 반환
        return json.dumps(results, ensure_ascii=False, default=str)[:4000]
    except Exception as e:
        return f"Cypher Error: {str(e)}"

@mcp.tool()
def search_threat_intelligence(keyword: str) -> str:
    """
    Fuzzy search for a keyword across MITRE (Groups, Malware, Techniques) and Indicators.
    Useful when you don't know the exact name or ID.
    """
    try:
        # 1. MITRE Full-text Search
        q_mitre = f"""
        CALL db.index.fulltext.queryNodes("mitre_text_index", "{keyword}") YIELD node, score
        RETURN labels(node)[0] as Type, node.name as Name, node.description as Desc, score
        LIMIT 5
        """
        res_mitre = graph_client.query(q_mitre)

        # 2. Indicator Search
        q_ioc = f"""
        MATCH (i:Indicator)
        WHERE toLower(i.url) CONTAINS toLower("{keyword}") OR toLower(i.tags) CONTAINS toLower("{keyword}")
        RETURN 'Indicator' as Type, i.url as Name, i.tags as Desc, 1.0 as score
        LIMIT 5
        """
        res_ioc = graph_client.query(q_ioc)

        return json.dumps({
            "mitre_knowledge": res_mitre,
            "indicators": res_ioc
        }, ensure_ascii=False)
    except Exception as e:
        return f"Search Error: {str(e)}"

@mcp.tool()
def analyze_correlation(artifacts: str) -> str:
    """
    Analyze hidden connections between multiple artifacts (IPs, Names, IDs).
    Input: Comma-separated string (e.g., "Mozi, CVE-2023-1234, T1059")
    Returns: Common hub nodes connecting these artifacts.
    """
    values = [v.strip() for v in artifacts.split(',') if v.strip()]
    if not values:
        return "Error: No artifacts provided."

    query = f"""
    WITH {json.dumps(values)} AS inputs
    MATCH (n) WHERE n.name IN inputs OR n.cve_id IN inputs OR n.product IN inputs OR n.url IN inputs
    MATCH (n)-[r]-(hub)-[r2]-(other)
    WHERE hub <> n AND other <> n
    WITH hub, count(distinct n) as connected_count, collect(distinct n.name) as connected_sources
    WHERE connected_count > 1
    RETURN labels(hub)[0] as HubType, hub.name as HubName, connected_count, connected_sources
    ORDER BY connected_count DESC
    LIMIT 5
    """
    try:
        results = graph_client.query(query)
        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        return f"Correlation Error: {str(e)}"

if __name__ == "__main__":
    # MCP 서버 실행 (Stdio 방식)
    mcp.run()