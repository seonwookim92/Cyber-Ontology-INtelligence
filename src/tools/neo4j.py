# src/tools/neo4j.py
import json
from langchain_core.tools import tool
from src.core.graph_client import graph_client
import re

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


# -----------------
# Helpers
# -----------------
def _normalize(s: str) -> str:
    if s is None: return ""
    # Lowercase and remove surrounding whitespace
    s2 = s.strip().lower()
    # Remove non-alphanumeric for fuzzy matching (keep hex/hash chars)
    s2 = re.sub(r"[^a-z0-9]", "", s2)
    return s2


def _apoc_available() -> bool:
    try:
        # Neo4j 5.x+ uses SHOW PROCEDURES
        res = graph_client.query("SHOW PROCEDURES YIELD name WHERE name CONTAINS 'apoc' RETURN count(*) as cnt")
        if res and isinstance(res, list) and len(res) > 0:
            cnt = list(res[0].values())[0]
            return int(cnt) > 0
    except Exception:
        # Fallback for older versions if needed, or if SHOW PROCEDURES fails
        try:
            res = graph_client.query("CALL dbms.procedures() YIELD name WHERE name CONTAINS 'apoc' RETURN count(*) as cnt")
            if res and isinstance(res, list) and len(res) > 0:
                cnt = list(res[0].values())[0]
                return int(cnt) > 0
        except:
            return False
    return False

# --------------------------------------------------------------------------
# Tools 정의
# --------------------------------------------------------------------------
@tool
def inspect_schema() -> str:
    """
    Returns a brief overview of the graph schema including labels and relationship types.
    Use this to understand what kind of nodes and connections exist before writing custom queries or when you need to explore unknown parts of the graph.
    """
    try:
        labels = graph_client.query("CALL db.labels()")
        rels = graph_client.query("CALL db.relationshipTypes()")
        
        # Extract names from records
        label_list = [list(l.values())[0] for l in labels] if labels else []
        rel_list = [list(r.values())[0] for r in rels] if rels else []
        
        return f"""
[Graph Schema Overview]
Available Node Labels: {', '.join(label_list)}
Available Relationship Types: {', '.join(rel_list)}

Key Node Properties:
- Incident: title, summary, timestamp
- AttackStep: phase, description, outcome, order
- Entity (General): name, original_value, type, description
- Malware: name, description
- Vulnerability: cve_id, description
- ThreatGroup: name, description

Core Ontology Connections:
- (Incident)-[:HAS_ATTACK_FLOW]->(AttackStep)-[:INVOLVES_ENTITY]->(Entity)
- (Incident)-[:TARGETS]->(Identity)
- (AttackStep)-[:USES_MALWARE]->(Malware)
- (AttackStep)-[:EXPLOITS]->(Vulnerability)
- (AttackStep)-[:HAS_INDICATOR]->(Indicator)
- (ThreatGroup)-[:ATTRIBUTED_TO]-(Incident)
- (ThreatGroup)-[:ALIASED_AS]->(AliasNode)
        """
    except Exception as e:
        return f"Failed to inspect schema: {e}"

@tool
def search_keyword_context(keyword: str) -> str:
    """
    Search for a keyword (IP, CVE, Hash, Name, etc.) across all nodes and return its Incident/Knowledge context.
    Treats aliased nodes (ALIASED_AS) as the same object.
    Use this as the primary starting point for any specific entity search.
    """
    # 1) Exact match across common identifying properties
    q_exact = """
    MATCH (start)
    WHERE start.name = $kw OR start.original_value = $kw OR start.cve_id = $kw 
       OR start.title = $kw OR start.id = $kw OR start.value = $kw OR start.url = $kw
    
    // 별칭 관계 확장 (동일 객체 취급)
    OPTIONAL MATCH (start)-[:ALIASED_AS*0..1]-(canonical)
    WITH distinct canonical as n
    
    // 연결된 context 및 별칭 처리
    OPTIONAL MATCH (n)-[:ALIASED_AS*1..1]-(alias)
    OPTIONAL MATCH (n)-[:HAS_ATTACK_FLOW|STARTS_WITH|NEXT*0..2]-(step:AttackStep)
    OPTIONAL MATCH (step)-[:HAS_ATTACK_FLOW|STARTS_WITH|NEXT*0..1]-(i:Incident)
    
    RETURN labels(n) as labels, 
           coalesce(n.name, n.title, n.cve_id, n.original_value, n.value, n.url) as name,
           collect(distinct alias.name) as aliases,
           collect(distinct i.title) as related_incidents
    LIMIT 20
    """
    res = graph_client.query(q_exact, {"kw": keyword})
    if res:
        return json.dumps({"match_type": "exact", "results": res}, ensure_ascii=False, default=str)[:4000]

    # 2) Contains (case-insensitive) fallback
    q_contains = """
    MATCH (start)
    WHERE toLower(coalesce(start.name, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(start.title, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(start.cve_id, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(start.original_value, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(start.value, "")) CONTAINS toLower($kw)
       OR toLower(coalesce(start.url, "")) CONTAINS toLower($kw)
    
    // 별칭 확장
    OPTIONAL MATCH (start)-[:ALIASED_AS*0..1]-(canonical)
    WITH distinct canonical as n
    
    RETURN labels(n) as labels, 
           coalesce(n.name, n.title, n.cve_id, n.original_value, n.value, n.url) as name,
           n as props
    LIMIT 50
    """
    res = graph_client.query(q_contains, {"kw": keyword})
    if res:
        return json.dumps({"match_type": "contains", "results": res}, ensure_ascii=False, default=str)[:4000]

    return "No results found."

@tool
def search_keyword_from_incidents(keyword: str) -> str:
    """
    Search for a keyword across Incidents, Victims, and related Entities (ThreatGroups, Malware, CVE, Indicators).
    Treats aliased nodes (ALIASED_AS) as the same object.
    Returns a list of matching Incidents.
    """
    q = """
    // 1. 키워드에 매칭되는 시작 노드 찾기
    MATCH (start)
    WHERE toLower(coalesce(start.name, "")) CONTAINS toLower($kw) OR 
          toLower(coalesce(start.title, "")) CONTAINS toLower($kw) OR 
          toLower(coalesce(start.summary, "")) CONTAINS toLower($kw) OR 
          toLower(coalesce(start.cve_id, "")) CONTAINS toLower($kw) OR 
          toLower(coalesce(start.url, "")) CONTAINS toLower($kw) OR
          toLower(coalesce(start.value, "")) CONTAINS toLower($kw) OR
          toLower(coalesce(start.original_value, "")) CONTAINS toLower($kw)
    
    // 2. 별칭 관계 확장 (동일 객체 취급)
    OPTIONAL MATCH (start)-[:ALIASED_AS*0..1]-(canonical)
    WITH distinct canonical as n
    
    // 3. 해당 노드와 연결된 Incident 추적
    MATCH (i:Incident)
    WHERE (i = n)
       OR (i)-[:TARGETS|ATTRIBUTED_TO|ALIASED_AS*0..1]-(n)
       OR (i)-[:STARTS_WITH|NEXT|HAS_ATTACK_FLOW*1..10]-(:AttackStep)-[:USES_MALWARE|EXPLOITS|HAS_INDICATOR|INVOLVES_ENTITY|ALIASED_AS*0..1]-(n)
    
    OPTIONAL MATCH (i)-[:TARGETS]->(v:Identity)
    
    RETURN DISTINCT i.title as title, 
           i.summary as summary, 
           i.timestamp as date,
           v.name as victim
    ORDER BY i.timestamp DESC
    LIMIT 15
    """
    res = graph_client.query(q, {"kw": keyword})
    if res:
        return json.dumps(res, ensure_ascii=False, default=str)[:4000]
    return "No incidents found matching that keyword."

@tool
def get_details_of_incident(title_keyword: str) -> str:
    """
    Get full details of an incident including its complete attack flow and linked entities.
    Searches using loose matching on the incident title.
    """
    q = """
    MATCH (i:Incident)
    WHERE toLower(i.title) CONTAINS toLower($kw)
    OPTIONAL MATCH (i)-[:TARGETS]->(v:Identity)
    
    // 공격 단계(AttackStep)들을 순서대로 가져옴
    OPTIONAL MATCH path = (i)-[:STARTS_WITH]->(s1:AttackStep)-[:NEXT*0..10]->(sn:AttackStep)
    WITH i, v, nodes(path) as steps
    UNWIND steps as s
    
    OPTIONAL MATCH (s)-[:USES_MALWARE]->(m:Malware)
    OPTIONAL MATCH (s)-[:EXPLOITS]->(vuln:Vulnerability)
    OPTIONAL MATCH (s)-[:HAS_INDICATOR]->(ind:Indicator)
    
    WITH i, v, s, 
         collect(distinct m.name) as malwares,
         collect(distinct vuln.cve_id) as vulns,
         collect(distinct ind.url) as iocs
    ORDER BY s.order ASC
    
    RETURN i.title as title, 
           i.summary as summary, 
           v.name as victim, 
           v.system as victim_system,
           collect({
             step: s.order,
             phase: s.phase,
             description: s.description,
             outcome: s.outcome,
             artifacts: malwares + vulns + iocs
           }) as attack_flow
    LIMIT 1
    """
    res = graph_client.query(q, {"kw": title_keyword})
    if res:
        return json.dumps(res[0], ensure_ascii=False, default=str)[:6000]
    return "Incident details not found."

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
def find_entity_exact(value: str) -> str:
    """Find entity by exact `name` or `original_value` equality (case-sensitive by default).
    Useful for hashes or identifiers where exact match is desired."""
    q = """
    MATCH (e:Entity)
    WHERE e.name = $v OR e.original_value = $v
    OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
    RETURN e.name as name, e.original_value as original_value, e.type as type, collect(distinct i.title) as incidents LIMIT 20
    """
    return _execute_cypher(q, {"v": value})


@tool
def find_entity_fuzzy(keyword: str, limit: int = 50) -> str:
    """Fuzzy search across `Entity` name/original_value using normalized comparison.
    This removes punctuation and lowercases both sides for broader matches."""
    # Normalize in Python and search via CONTAINS on lowercased strings
    norm = _normalize(keyword)
    q = """
    MATCH (e:Entity)
    WHERE toLower(replace(replace(replace(e.name, '[.]', ''), '-', ''), ' ', '')) CONTAINS $kw
       OR toLower(replace(replace(replace(e.original_value, '[.]', ''), '-', ''), ' ', '')) CONTAINS $kw
    OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
    RETURN i.title as incident, s.phase as phase, e.name as entity_name, e.original_value as original_value LIMIT $limit
    """
    return _execute_cypher(q, {"kw": norm, "limit": limit})


@tool
def entity_history(entity_name: str) -> str:
    """Return context (Incidents and AttackSteps) where the entity appears."""
    q = """
    MATCH (e:Entity)
    WHERE e.name = $v OR e.original_value = $v OR toLower(e.name) = toLower($v) OR toLower(e.original_value) = toLower($v)
    OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
    RETURN e.name as entity, e.original_value as original, collect(distinct {incident: i.title, phase: s.phase, step_desc: s.description}) as occurrences LIMIT 1
    """
    return _execute_cypher(q, {"v": entity_name})


@tool
def ensure_entity_indexes() -> str:
    """Create helpful indexes for `Entity.name` and `Entity.original_value` to improve search.
    Returns success/failure message."""
    try:
        # Use CREATE INDEX IF NOT EXISTS (supported in recent Neo4j versions)
        graph_client.query("CREATE INDEX entity_name_index IF NOT EXISTS FOR (e:Entity) ON (e.name)")
        graph_client.query("CREATE INDEX entity_original_index IF NOT EXISTS FOR (e:Entity) ON (e.original_value)")
        # Fulltext index suggestion (requires projection / APOC in some versions) omitted here
        return "Indexes ensured for Entity.name and Entity.original_value."
    except Exception as e:
        return f"Index creation failed: {e}"

@tool
def run_cypher(query: str) -> str:
    """Execute READ-ONLY Cypher query."""
    forbidden = ["CREATE", "DELETE", "DETACH", "SET", "MERGE"]
    if any(cmd in query.upper() for cmd in forbidden): return "Error: Read-only only."
    return _execute_cypher(query)

# ★ 핵심: 이 파일에서 제공하는 도구 리스트를 export 합니다.
NEO4J_TOOLS = [inspect_schema, search_keyword_context, explore_incident_correlations, run_cypher]

# Extended tooling: add schema introspection and exploratory traversal
NEO4J_TOOLS_EXTENDED = NEO4J_TOOLS + []


@tool
def list_labels() -> str:
    """Return all labels in the database."""
    q = "CALL db.labels()"
    return _execute_cypher(q)


@tool
def list_properties(label: str = None) -> str:
    """Return top properties (keys) for a label or for all nodes if label omitted."""
    if label:
        # safe label quoting
        q = f"MATCH (n:`{label}`) UNWIND keys(n) AS k RETURN k, count(*) AS cnt ORDER BY cnt DESC LIMIT 200"
    else:
        q = "MATCH (n) UNWIND keys(n) AS k RETURN k, count(*) AS cnt ORDER BY cnt DESC LIMIT 200"
    return _execute_cypher(q)


@tool
def sample_nodes_by_label(label: str, limit: int = 5) -> str:
    """Return sample nodes for a given label (shows properties)."""
    q = f"MATCH (n:`{label}`) RETURN n LIMIT $limit"
    return _execute_cypher(q, {"limit": limit})


@tool
def expand_neighborhood(seed: str, hops: int = 2, limit: int = 200) -> str:
    """Expand neighborhood from a seed entity (matches name/original_value) up to `hops`.
    Returns collected nodes and short summary of labels encountered.
    """
    q = """
    MATCH (s:Entity)
    WHERE s.name = $seed OR s.original_value = $seed OR toLower(s.name) = toLower($seed) OR toLower(s.original_value) = toLower($seed)
    OPTIONAL MATCH p=(s)-[*..$hops]-(n)
    WITH collect(distinct n) AS nodes, s
    UNWIND nodes AS nd
    RETURN DISTINCT labels(nd) AS labels, nd LIMIT $limit
    """
    return _execute_cypher(q, {"seed": seed, "hops": hops, "limit": limit})


# Add extended tools to export list so agent can use them
NEO4J_TOOLS_EXTENDED += [list_labels, list_properties, sample_nodes_by_label, expand_neighborhood, find_entity_exact, find_entity_fuzzy, entity_history, ensure_entity_indexes, search_keyword_from_incidents, get_details_of_incident]


@tool
def find_paths(start: str, end: str = None, max_len: int = 4, max_paths: int = 20, rel_filter: str = None, label_filter: str = None, strategy: str = "ranked", debug: bool = True) -> str:
    """Find paths from `start` to `end` (or neighborhood if end omitted).
    - Uses APOC if available for broader exploration; falls back to Cypher shortest/all path queries.
    - Safety caps: max_len<=6, max_paths<=200.
    - Returns JSON with path records; if debug=True returns used Cypher and params.
    """
    try:
        max_len = min(int(max_len), 6)
        max_paths = min(int(max_paths), 200)
    except Exception:
        max_len = 4
        max_paths = 20

    # [개선] 텅 빈 문자열이 들어오면 None으로 치환하여 APOC이 '모든 관계/라벨'로 인식하게 함
    r_filter = rel_filter if rel_filter and rel_filter.strip() else None
    l_filter = label_filter if label_filter and label_filter.strip() else None

    params = {
        "start": start, 
        "end": end, 
        "max_len": max_len, 
        "max_paths": max_paths, 
        "rel_filter": r_filter, 
        "label_filter": l_filter
    }

    use_apoc = _apoc_available()

    # Resolve start node(s) across any label by matching common identifying props
    resolve_q = """
    MATCH (n)
    WHERE any(k IN keys(n) WHERE toString(n[k]) = $val OR toLower(toString(n[k])) = toLower($val))
    RETURN elementId(n) AS nid, labels(n) AS labels, n LIMIT 50
    """
    start_nodes = graph_client.query(resolve_q, {"val": start})
    if not start_nodes:
        # No start node found
        out = {"match_type": "error", "paths_returned": 0, "results": [], "message": "Start node not found"}
        if debug:
            out["debug_resolve_start_q"] = resolve_q
            out["params"] = params
        return json.dumps(out, ensure_ascii=False, default=str)[:4000]

    end_nodes = None
    if end:
        end_nodes = graph_client.query(resolve_q, {"val": end})
        if not end_nodes:
            # end node not found; return info about start and suggest searching by label/props
            out = {"match_type": "error", "paths_returned": 0, "results": [], "message": "End node not found"}
            if debug:
                out["debug_resolve_end_q"] = resolve_q
                out["params"] = params
                out["start_nodes_sample"] = start_nodes[:5]
            return json.dumps(out, ensure_ascii=False, default=str)[:4000]

    # Prepare actual path query using node ids if resolved
    # Create lists of ids for params
    start_ids = [r.get("nid") for r in start_nodes]
    end_ids = [r.get("nid") for r in end_nodes] if end_nodes else None

    # If end specified, try to find paths between any start id and any end id
    if end_ids:
        if use_apoc:
            cypher = """
            UNWIND $start_ids AS sid
            UNWIND $end_ids AS tid
            MATCH (s) WHERE elementId(s)=sid
            MATCH (t) WHERE elementId(t)=tid
            CALL apoc.path.expandConfig(s, {endNodes:[t], maxLevel:$max_len, limit:$max_paths, relationshipFilter:$rel_filter, labelFilter:$label_filter}) YIELD path
            RETURN [n IN nodes(path) | {id:elementId(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(path) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids, "end_ids": end_ids}
        else:
            cypher = """
            UNWIND $start_ids AS sid
            UNWIND $end_ids AS tid
            MATCH (s) WHERE elementId(s)=sid
            MATCH (t) WHERE elementId(t)=tid
            MATCH p=(s)-[*..$max_len]-(t)
            RETURN [n IN nodes(p) | {id:elementId(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(p) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids, "end_ids": end_ids}
    else:
        # neighborhood exploration: first try APOC expand to get paths, else fallback to 1-hop neighbors
        if use_apoc:
            cypher = """
            UNWIND $start_ids AS sid
            MATCH (s) WHERE elementId(s)=sid
            CALL apoc.path.expandConfig(s, {maxLevel:$max_len, limit:$max_paths, relationshipFilter:$rel_filter, labelFilter:$label_filter}) YIELD path
            RETURN [n IN nodes(path) | {id:elementId(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(path) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids}
        else:
            # Fallback: return 1..max_len hops by progressively collecting neighbors; at minimum return 1-hop info
            cypher = """
            UNWIND $start_ids AS sid
            MATCH (s) WHERE elementId(s)=sid
            MATCH (s)-[r]-(n)
            RETURN {start_id:elementId(s), rel:type(r), neighbor: {id:elementId(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}} AS entry LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids}

    # Execute path query
    try:
        results = graph_client.query(cypher, p_params)
    except Exception as e:
        # If APOC map usage caused failure on non-APOC environments, simplify props extraction
        try:
            cypher_simple = cypher.replace("apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])", "n")
            results = graph_client.query(cypher_simple, p_params)
            cypher = cypher_simple
        except Exception as e2:
            out = {"match_type": "error", "paths_returned": 0, "results": [], "message": f"Path query failed: {e2}"}
            if debug:
                out["cypher"] = cypher
                out["params"] = p_params
            return json.dumps(out, ensure_ascii=False, default=str)[:4000]

    # Post-process results: normalize structure and score paths
    processed = []
    for item in results:
        # Support two shapes: {nodes: [...], rels: [...] } or entries from fallback
        if isinstance(item, dict) and 'nodes' in item:
            nodes = item.get('nodes') or []
            rels = item.get('rels') or []
        elif isinstance(item, dict) and 'entry' in item:
            # fallback single neighbor entries
            entry = item.get('entry')
            nodes = [entry.get('neighbor')] if entry else []
            rels = [entry.get('rel')] if entry else []
        else:
            # unknown shape: include raw
            nodes = []
            rels = []

        # compute simple score: base on path length and incident presence
        length = len(nodes) if nodes else (len(rels) if rels else 0)
        score = 0.0
        if length > 0:
            score = 1.0 / float(length)

        # incident bonus: if any node has label containing 'Incident' or 'Intelligence'
        incident_count = 0
        labels_seen = []
        node_summaries = []
        for n in nodes:
            lbls = n.get('labels') if isinstance(n, dict) else []
            labels_seen.extend(lbls if lbls else [])
            # Extract readable name/title property if present
            props = n.get('props') if isinstance(n, dict) else {}
            display = None
            for key in ('title','name','original_value','cve_id'):
                if props and key in props:
                    display = props.get(key)
                    break
            node_summaries.append({"labels": lbls, "display": display, "props": props})
            if any('incident' in (l.lower() if l else '') or 'intelligence' in (l.lower() if l else '') for l in (lbls or [])):
                incident_count += 1

        # boost score for incident presence
        score += incident_count * 0.5

        processed.append({
            "nodes": node_summaries,
            "rels": rels,
            "length": length,
            "incident_count": incident_count,
            "score": round(score, 3)
        })

    # sort by score desc, then by length asc
    processed_sorted = sorted(processed, key=lambda x: (-x.get('score', 0), x.get('length', 999)))

    out = {"match_type": strategy if end else "neighborhood", "paths_returned": len(processed_sorted), "results": processed_sorted}
    if debug:
        out["cypher"] = cypher
        out["params"] = p_params
    return json.dumps(out, ensure_ascii=False, default=str)[:8000]


NEO4J_TOOLS_EXTENDED.append(find_paths)