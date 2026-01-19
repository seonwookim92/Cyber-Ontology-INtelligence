import json
from src.core.graph_client import graph_client

def truncate_label(text, length=15):
    if not text: return "Unknown"
    return text if len(text) <= length else text[:length] + "..."

def get_incidents(limit=30):
    """사고 목록 조회"""
    q = "MATCH (i:Incident) RETURN elementId(i) as id, i.title as title ORDER BY i.timestamp DESC LIMIT $limit"
    return graph_client.query(q, {"limit": limit})

def get_search_suggestions(query):
    """엔티티 자동완성을 위한 검색 기능"""
    if not query or len(query) < 2: return []
    q = """
    MATCH (n)
    WHERE (n:Incident OR n:Identity OR n:Malware OR n:Vulnerability OR n:Indicator OR n:ThreatGroup)
      AND (toLower(coalesce(n.name, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(n.title, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(n.cve_id, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(n.url, "")) CONTAINS toLower($kw))
    RETURN coalesce(n.name, n.title, n.cve_id, n.url) as label, labels(n)[0] as type, elementId(n) as id
    LIMIT 10
    """
    res = graph_client.query(q, {"kw": query})
    return [f"[{r['type']}] {r['label']} (ID:{r['id']})" for r in res]

def fetch_node_details(node_id):
    """DB에서 노드의 상세 속성을 가져옴 (elementId 기반)"""
    # prefix가 붙어있는 구버전 ID 대응 (하위 호환)
    real_id = node_id
    for prefix in ["VIC_", "ACT_", "MAL_", "CVE_", "IOC_"]:
        if node_id.startswith(prefix):
            val = node_id.replace(prefix, "")
            q = """
            MATCH (n) 
            WHERE n.id = $val OR n.name = $val OR n.cve_id = $val OR n.url = $val
            RETURN n LIMIT 1
            """
            res = graph_client.query(q, {"val": val})
            if res: return res[0]['n']
            break

    # 1. elementId로 직접 조회 (권장)
    q = "MATCH (n) WHERE elementId(n) = $id RETURN n"
    res = graph_client.query(q, {"id": real_id})
    if res: return res[0]['n']
    
    # 2. 혹시 일반 id property인 경우
    q = "MATCH (n) WHERE n.id = $id RETURN n"
    res = graph_client.query(q, {"id": real_id})
    return res[0]['n'] if res else None

def get_incident_subgraph(inc_id):
    """특정 사건의 전체 데이터(Header, Steps, Artifacts) 조회"""
    # 1. Header Info
    q_head = """
    MATCH (i) WHERE elementId(i) = $id
    OPTIONAL MATCH (i)-[:TARGETS]->(v:Identity)
    OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(g:ThreatGroup)
    RETURN elementId(i) as id, i.title as title, i.summary as summary, 
           v.name as victim, elementId(v) as victim_id,
           g.name as actor, elementId(g) as actor_id
    """
    head = graph_client.query(q_head, {"id": inc_id})
    if not head: return None

    # 2. Path & Artifacts
    q_path = """
    MATCH (i) WHERE elementId(i) = $id
    MATCH (i)-[:STARTS_WITH|NEXT*]->(s:AttackStep)
    OPTIONAL MATCH (s)-[r]->(art)
    WHERE type(r) IN ['USES_MALWARE', 'EXPLOITS', 'HAS_INDICATOR']
    RETURN elementId(s) as step_id, s.order as order, s.phase as phase, s.description as desc, s.outcome as outcome,
           type(r) as rel, 
           labels(art) as labels,
           properties(art) as props,
           elementId(art) as art_id
    ORDER BY s.order
    """
    path = graph_client.query(q_path, {"id": inc_id})
    
    return {
        "header": head[0],
        "path": path
    }

def find_connection_paths(start_val, end_val, max_hops):
    """두 노드 간의 모든 경로 탐색 (기존 방식 - 3_Graph_Analysis.py에서 호출 중)"""
    def _clean_val(v): return v.split("] ", 1)[1] if "] " in v else v
    s_val = _clean_val(start_val)
    e_val = _clean_val(end_val)

    q = """
    MATCH (start), (target)
    WHERE (toLower(coalesce(start.name, "")) = toLower($s) OR toLower(coalesce(start.title, "")) = toLower($s) OR start.cve_id = $s OR start.url = $s)
      AND (toLower(coalesce(target.name, "")) = toLower($e) OR toLower(coalesce(target.title, "")) = toLower($e) OR target.cve_id = $e OR target.url = $e)
    
    CALL apoc.path.expandConfig(start, {
        endNodes: [target],
        maxLevel: 10,
        relationshipFilter: null,
        labelFilter: null,
        limit: 10
    }) YIELD path
    
    RETURN [n IN nodes(path) | {props: properties(n), labels: labels(n)}] as path_nodes, 
           [r IN relationships(path) | type(r)] as path_rels
    """
    return graph_client.query(q, {"s": s_val, "e": e_val})

def find_path_with_context(start_val, end_val, context_hops):
    """
    1. 두 노드 간의 shortestPath를 찾습니다 (무조건 포함).
    2. 경로 상의 노드들로부터 context_hops 만큼 주변 노드를 확장하여 반환합니다.
    """
    # Autocomplete 등에서 [Type] Label (ID:xxx) 형식으로 들어오는 경우 ID만 추출
    def _extract_id(v):
        if "(ID:" in v and v.endswith(")"):
            return v.split("(ID:", 1)[1].rstrip(")")
        return v

    s_id = _extract_id(start_val)
    e_id = _extract_id(end_val)

    # 1. Start/Target 노드 재정의 (ID가 넘어온 경우 elementId 사용, 아니면 속성 검색)
    q = """
    MATCH (start), (target)
    WHERE (elementId(start) = $s OR toLower(coalesce(start.name, "")) = toLower($s) OR toLower(coalesce(start.title, "")) = toLower($s) OR start.cve_id = $s OR start.url = $s)
      AND (elementId(target) = $e OR toLower(coalesce(target.name, "")) = toLower($e) OR toLower(coalesce(target.title, "")) = toLower($e) OR target.cve_id = $e OR target.url = $e)
    
    // 1. 최단 경로 탐색
    MATCH p = shortestPath((start)-[*..15]-(target))
    WITH start, target, p, nodes(p) as pathNodes
    
    // 2. 경로 상의 노드들 주변 확장 (AttackStep 제외)
    OPTIONAL MATCH (n)-[r]-(neighbor)
    WHERE n IN pathNodes AND NOT n:AttackStep AND $hops > 0
    
    RETURN [n IN nodes(p) | {props: properties(n), labels: labels(n), id: elementId(n)}] as core_nodes, 
           [rel IN relationships(p) | {
               type: type(rel), 
               s_id: elementId(startNode(rel)),
               e_id: elementId(endNode(rel))
           }] as core_rels,
           collect(distinct {
               n_props: properties(neighbor), 
               n_labels: labels(neighbor),
               n_id: elementId(neighbor),
               r_type: type(r),
               source_id: elementId(n)
           })[0..100] as neighbors
    """
    return graph_client.query(q, {"s": s_id, "e": e_id, "hops": context_hops})

def explore_neighbors_query(node_id, current_inc_id=None):
    """
    특정 노드의 주변 연결 엔티티 탐색 (elementId 기반 무결성 확보)
    SyntaxError 해결을 위해 UNION 구조로 리팩토링
    """
    q = """
    MATCH (n) WHERE elementId(n) = $id
    
    // 1. Malware 관련 (다른 사건, 공격 그룹)
    OPTIONAL MATCH (n:Malware)<-[:USES_MALWARE]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(mi:Incident)
    WHERE $current_id IS NULL OR elementId(mi) <> $current_id
    WITH n, collect(distinct {id: elementId(mi), label: mi.title, type: 'Incident', rel: 'USED_IN'}) as c1
    
    OPTIONAL MATCH (n:Malware)<-[:USES]-(mg:ThreatGroup)
    WITH n, c1, collect(distinct {id: elementId(mg), label: mg.name, type: 'Actor', rel: 'USED_BY'}) as c2
    
    // 2. Vulnerability 관련 (다른 사건)
    OPTIONAL MATCH (n:Vulnerability)<-[:EXPLOITS]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(vi:Incident)
    WHERE $current_id IS NULL OR elementId(vi) <> $current_id
    WITH n, c1, c2, collect(distinct {id: elementId(vi), label: vi.title, type: 'Incident', rel: 'EXPLOITED_IN'}) as c3
    
    // 3. Indicator 관련 (다른 사건)
    OPTIONAL MATCH (n:Indicator)<-[:HAS_INDICATOR]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(ii:Incident)
    WHERE $current_id IS NULL OR elementId(ii) <> $current_id
    WITH n, c1, c2, c3, collect(distinct {id: elementId(ii), label: ii.title, type: 'Incident', rel: 'SEEN_IN'}) as c4
    
    // 4. Actor 관련 (다른 사건, 사용 악성코드)
    OPTIONAL MATCH (n:ThreatGroup)<-[:ATTRIBUTED_TO]-(ai:Incident)
    WHERE $current_id IS NULL OR elementId(ai) <> $current_id
    WITH n, c1, c2, c3, c4, collect(distinct {id: elementId(ai), label: ai.title, type: 'Incident', rel: 'ATTRIBUTED_TO'}) as c5
    
    OPTIONAL MATCH (n:ThreatGroup)-[:USES]->(am:Malware)
    WITH c1, c2, c3, c4, c5, collect(distinct {id: elementId(am), label: am.name, type: 'Malware', rel: 'USES'}) as c6
    
    WITH c1 + c2 + c3 + c4 + c5 + c6 as final_list
    UNWIND final_list as r
    RETURN r.id as res_id, r.label as res_label, r.type as type, r.rel as rel
    """
    res = graph_client.query(q, {"id": node_id, "current_id": current_inc_id})
    return [r for r in res if r['res_id']]
