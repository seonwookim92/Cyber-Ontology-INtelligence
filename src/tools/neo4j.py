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
        res = graph_client.query("CALL dbms.procedures() YIELD name WHERE name CONTAINS 'apoc' RETURN count(*) as cnt")
        if res and isinstance(res, list) and len(res) > 0:
            cnt = list(res[0].values())[0]
            return int(cnt) > 0
    except Exception:
        return False
    return False

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
    # Strategy: 1) exact equality on name/original_value (fast, reliable for hashes)
    #           2) contains (case-insensitive)
    #           3) broader scan across other properties if still not found

    # 1) Exact match
    q_exact = """
    MATCH (e:Entity)
    WHERE e.name = $kw OR e.original_value = $kw
    OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
    OPTIONAL MATCH (s)-[:INVOLVES_ENTITY]->(peer:Entity) WHERE peer <> e
    RETURN i.title as incident, i.summary as summary, s.phase as phase, s.description as step_desc, e.name as entity_name, e.type as entity_type, collect(distinct peer.name) as related
    LIMIT 20
    """
    res = graph_client.query(q_exact, {"kw": keyword})
    if res:
        return json.dumps({"match_type": "exact", "results": res}, ensure_ascii=False, default=str)[:4000]

    # 2) Contains (case-insensitive)
    q_contains = """
    MATCH (e:Entity)
    WHERE toLower(e.name) CONTAINS toLower($kw) OR toLower(e.original_value) CONTAINS toLower($kw) OR toLower(e.type) CONTAINS toLower($kw)
    MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
    MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
    OPTIONAL MATCH (s)-[:INVOLVES_ENTITY]->(peer:Entity) WHERE peer <> e
    RETURN i.title as incident, s.phase as phase, e.name as entity_name, e.type as entity_type, collect(distinct peer.name) as related
    LIMIT 50
    """
    res = graph_client.query(q_contains, {"kw": keyword})
    if res:
        return json.dumps({"match_type": "contains", "results": res}, ensure_ascii=False, default=str)[:4000]

    # 3) Broader scan: search entity-like properties across nodes
    q_broad = """
    MATCH (n)
    WHERE any(k IN keys(n) WHERE toLower(toString(n[k])) CONTAINS toLower($kw))
    RETURN labels(n) as labels, n as node_props LIMIT 50
    """
    res = graph_client.query(q_broad, {"kw": keyword})
    if res:
        return json.dumps({"match_type": "broader", "results": res}, ensure_ascii=False, default=str)[:4000]

    return "No results found."

@tool
def search_keyword_from_incidents(keyword: str) -> str:
    """
    Search for a keyword across Incidents, Victims, and related Entities (Malware, CVE, Indicators).
    Returns a list of matching Incidents.
    """
    q = """
    // 1. 키워드에 매칭되는 시작 노드 찾기 (Incident, Identity, Malware, Vuln, Indicator)
    MATCH (n)
    WHERE (n:Incident OR n:Identity OR n:Malware OR n:Vulnerability OR n:Indicator)
      AND (
        toLower(coalesce(n.name, "")) CONTAINS toLower($kw) OR 
        toLower(coalesce(n.title, "")) CONTAINS toLower($kw) OR 
        toLower(coalesce(n.summary, "")) CONTAINS toLower($kw) OR 
        toLower(coalesce(n.cve_id, "")) CONTAINS toLower($kw) OR 
        toLower(coalesce(n.url, "")) CONTAINS toLower($kw) OR
        toLower(coalesce(n.original_value, "")) CONTAINS toLower($kw)
      )
    
    // 2. 해당 노드와 연결된 Incident 추적
    MATCH (i:Incident)
    WHERE (i = n)
       OR (i)-[:TARGETS]->(n)
       OR (i)-[:STARTS_WITH|NEXT*1..10]->(:AttackStep)-[:USES_MALWARE|EXPLOITS|HAS_INDICATOR]->(n)
    
    OPTIONAL MATCH (i)-[:TARGETS]->(v:Identity)
    
    RETURN DISTINCT i.title as title, 
           i.summary as summary, 
           i.timestamp as date,
           v.name as victim,
           v.industry as industry
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
        # safety caps
        max_len = min(int(max_len), 6)
        max_paths = min(int(max_paths), 200)
    except Exception:
        max_len = 4
        max_paths = 20

    params = {"start": start, "end": end, "max_len": max_len, "max_paths": max_paths, "rel_filter": rel_filter or "", "label_filter": label_filter or ""}

    use_apoc = _apoc_available()

    # Resolve start node(s) across any label by matching common identifying props
    resolve_q = """
    MATCH (n)
    WHERE any(k IN keys(n) WHERE toString(n[k]) = $val OR toLower(toString(n[k])) = toLower($val))
    RETURN id(n) AS nid, labels(n) AS labels, n LIMIT 50
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
            MATCH (s) WHERE id(s)=sid
            MATCH (t) WHERE id(t)=tid
            CALL apoc.path.expandConfig(s, {endNodes:[t], maxLevel:$max_len, limit:$max_paths, relationshipFilter:$rel_filter, labelFilter:$label_filter}) YIELD path
            RETURN [n IN nodes(path) | {id:id(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(path) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids, "end_ids": end_ids}
        else:
            cypher = """
            UNWIND $start_ids AS sid
            UNWIND $end_ids AS tid
            MATCH (s) WHERE id(s)=sid
            MATCH (t) WHERE id(t)=tid
            MATCH p=(s)-[*..$max_len]-(t)
            RETURN [n IN nodes(p) | {id:id(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(p) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids, "end_ids": end_ids}
    else:
        # neighborhood exploration: first try APOC expand to get paths, else fallback to 1-hop neighbors
        if use_apoc:
            cypher = """
            UNWIND $start_ids AS sid
            MATCH (s) WHERE id(s)=sid
            CALL apoc.path.expandConfig(s, {maxLevel:$max_len, limit:$max_paths, relationshipFilter:$rel_filter, labelFilter:$label_filter}) YIELD path
            RETURN [n IN nodes(path) | {id:id(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}] AS nodes, [r IN relationships(path) | type(r)] AS rels LIMIT $max_paths
            """
            p_params = {**params, "start_ids": start_ids}
        else:
            # Fallback: return 1..max_len hops by progressively collecting neighbors; at minimum return 1-hop info
            cypher = """
            UNWIND $start_ids AS sid
            MATCH (s) WHERE id(s)=sid
            MATCH (s)-[r]-(n)
            RETURN {start_id:id(s), rel:type(r), neighbor: {id:id(n), labels:labels(n), props:apoc.map.fromPairs([k IN keys(n) | [k, n[k]]])}} AS entry LIMIT $max_paths
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