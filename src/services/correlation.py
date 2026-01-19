import json
from typing import List, Dict, Tuple, Any

from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage

from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 0. LLM Helper
# ==============================================================================

def _get_llm():
    if settings.LLM_PROVIDER == "openai":
        return ChatOpenAI(model=settings.OPENAI_MODEL, api_key=settings.OPENAI_API_KEY, temperature=0)
    else:
        return ChatOllama(model=settings.OLLAMA_MODEL, temperature=0, base_url=settings.OLLAMA_BASE_URL)

def _generate_analysis(system_prompt: str, user_prompt: str) -> str:
    try:
        llm = _get_llm()
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return f"AI Analysis Failed: {str(e)}"


# ==============================================================================
# Smart hinting (kept lightweight)
# ==============================================================================

def get_smart_hints(target_type: str, context_artifacts: List[Dict[str, str]], limit: int = 20) -> List[str]:
    hints = []
    if context_artifacts:
        prev_mal = next((x['value'] for x in context_artifacts if x['type'] == 'Malware'), None)
        prev_ind = next((x['value'] for x in context_artifacts if x['type'] == 'Indicator'), None)
        if target_type == "Indicator" and prev_mal:
            q = f"MATCH (m:Malware)<-[:INDICATES]-(i:Indicator) WHERE toLower(m.name) = toLower(\"{prev_mal}\") RETURN DISTINCT i.url as val LIMIT {limit}"
            rows = graph_client.query(q)
            hints.extend([f"[Rel] {r['val']}" for r in rows])
    if len(hints) < limit:
        needed = limit - len(hints)
        q = ""
        if target_type == "Indicator":
            q = f"MATCH (n:Indicator) RETURN n.url as val ORDER BY rand() LIMIT {needed}"
        elif target_type == "Malware":
            q = f"MATCH (n:Malware) RETURN n.name as val ORDER BY n.name LIMIT {needed}"
        elif target_type == "Threat Group":
            q = f"MATCH (n:ThreatGroup) RETURN n.name as val ORDER BY n.name LIMIT {needed}"
        if q:
            rows = graph_client.query(q)
            hints.extend([r['val'] for r in rows])
    return sorted(list(set(hints)), key=lambda x: x.startswith("[Rel]"), reverse=True)[:limit]


# ==============================================================================
# Correlation / Ontology-first search
# ==============================================================================

def run_correlation_analysis(
    artifacts: List[Dict[str, str]],
    depth: int = 1,
    looseness: int = 30,
    include_incidents: bool = True
) -> Tuple[List[Dict[str, Any]], str]:
    """Ontology-first correlation:
    - schema-less matching across many properties
    - prefer any available fulltext index; fallback to contains
    - seed-driven expansion via APOC when available
    - simple combined scoring and LLM explanation
    """
    # normalize looseness
    looseness = max(0, min(100, int(looseness)))

    # properties to search across
    PROP_FIELDS = ["name", "url", "cve_id", "value", "indicator", "title", "description", "hash", "ip", "domain"]

    def _coalesce_fields(alias: str) -> str:
        # Use properties(...) map access to avoid server warnings when a property key
        # does not exist globally (UnknownPropertyKeyWarning).
        parts = [f"coalesce(properties({alias})['{p}'], '')" for p in PROP_FIELDS]
        return " + ' ' + ".join(parts)

    # detect an available fulltext index name
    def _get_fulltext_index_name() -> str:
        try:
            idxs = graph_client.query("SHOW FULLTEXT INDEXES")
        except Exception:
            return None
        if not idxs:
            return None
        preferred = None
        for i in idxs:
            name = i.get('name') if isinstance(i, dict) else None
            labels = i.get('labelsOrTypes') or []
            if labels and any(l.lower() in ['basenode', 'incident'] for l in [str(x).lower() for x in labels]):
                return name
            if not preferred:
                preferred = name
        return preferred

    fulltext_index_name = _get_fulltext_index_name()
    fulltext_available = bool(fulltext_index_name)

    sub_queries: List[str] = []

    def _escape_lucene_query(query: str) -> str:
        # Escape special characters that Lucene's QueryParser might interpret
        # See: https://lucene.apache.org/core/8_11_1/queryparser/org/apache/lucene/queryparser/classic/package-summary.html#Escaping_Special_Characters
        # All non-alphanumeric characters are escaped with a backslash.
        special_chars = r'+-&|!(){}[]^"~*?:<>/'
        for char in special_chars:
            query = query.replace(char, f'\\{char}')
        return query

    # Build subqueries per artifact
    for art in artifacts:
        val = art.get('value') or ''
        safe_val = str(val).replace("'", "\\'")

        exact_cond = f"toLower({_coalesce_fields('candidate')}) = toLower('{safe_val}')"
        contains_cond = f"toLower({_coalesce_fields('candidate')}) CONTAINS toLower('{safe_val}')"

        # exact match (Priority 1)
        sub_queries.append(f"""
            MATCH (candidate)
            WHERE toLower({_coalesce_fields('candidate')}) = toLower('{safe_val}')
            RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title) AS label, 
                   labels(candidate)[0] AS type, 0 AS dist,
                   [{{name: coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title), labels: labels(candidate)}}] AS path_nodes
            LIMIT 100
        """)

        # contains match (Priority 2) - Critical for URLs/Path fragments
        sub_queries.append(f"""
            MATCH (candidate)
            WHERE toLower({_coalesce_fields('candidate')}) CONTAINS toLower('{safe_val}')
            RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title) AS label, 
                   labels(candidate)[0] AS type, 1 AS dist,
                   [{{name: coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title), labels: labels(candidate)}}] AS path_nodes
            LIMIT 100
        """)

        # fulltext or contains fallback
        if looseness >= 20 and fulltext_available:
            idx = fulltext_index_name
            escaped_val = _escape_lucene_query(safe_val)
            ft_q = f"CALL db.index.fulltext.queryNodes('{idx}', '{escaped_val}~') YIELD node, score RETURN coalesce(node.name,node.cve_id,node.url,node.value) AS label, (CASE WHEN 'ThreatGroup' IN labels(node) THEN 'ThreatGroup' ELSE head(labels(node)) END) AS type, 1 AS dist, [{{name: coalesce(node.name,node.cve_id,node.url,node.value), labels: labels(node)}}] AS path_nodes, score AS raw_score LIMIT 200"
            sub_queries.append(ft_q)

        # seed-driven expansion
        seed_match = f"toLower({_coalesce_fields('seed')}) CONTAINS toLower('{safe_val}')"
        label_allow = "+(ThreatGroup|Campaign|Actor|Incident|Malware|Indicator|Vulnerability|AttackTechnique|Tool|Identity|AttackStep)"
        if not include_incidents:
            label_allow = label_allow.replace('|Incident', '').replace('|AttackStep', '')

        # Focused relationship filter
        rel_filter = 'USES|INDICATES|RELATED_TO|CONNECTED|RELATED|ASSOCIATED_WITH|USES_MALWARE|EXPLOITS|HAS_INDICATOR|ATTRIBUTED_TO|TARGETS|STARTS_WITH|NEXT|ALIASED_AS'

        sub_queries.append(f"""
            MATCH (seed)
            WHERE {seed_match}
            CALL apoc.path.expandConfig(seed, {{
                relationshipFilter: '{rel_filter}', 
                labelFilter: '{label_allow}', 
                minLevel: 1,
                maxLevel: {max(3, depth + 1)}, 
                bfs: true,
                limit: 200
            }}) YIELD path
            WITH last(nodes(path)) AS candidate, path, length(path) AS dist
            WHERE candidate:ThreatGroup OR candidate:Incident
            RETURN coalesce(candidate.name, candidate.title, candidate.cve_id, candidate.url, candidate.value) AS label, 
                   (CASE WHEN 'ThreatGroup' IN labels(candidate) THEN 'ThreatGroup' 
                         WHEN 'Incident' IN labels(candidate) THEN 'Incident'
                         ELSE head(labels(candidate)) END) AS type, 
                   dist AS dist,
                   [n IN nodes(path) | {{name: coalesce(n.name, n.title, n.cve_id, n.url, n.value), labels: labels(n)}}] AS path_nodes
            LIMIT 100
        """)

    if not sub_queries:
        return [], "분석 가능한 아티팩트가 없거나, 선택된 심도(Depth)에서는 탐색 경로가 정의되지 않았습니다."

    # Execute queries and collect rows
    raw_rows: List[Dict[str, Any]] = []
    for q in sub_queries:
        try:
            res = graph_client.query(q)
            if res:
                for r in res:
                    raw_rows.append(r)
        except Exception:
            pass

    # Map non-ThreatGroup candidates to ThreatGroup(s)
    tg_matches: List[Dict[str, Any]] = []
    tg_cache: Dict[str, List[str]] = {}

    def _find_threatgroups_for_label(val: str, itype: str = None) -> List[str]:
        k = val or ''
        cache_key = f"{k}_{itype}"
        if cache_key in tg_cache: return tg_cache[cache_key]
        
        if itype == 'Incident':
            q_inc = "MATCH (i:Incident) WHERE toLower(i.title) = toLower($val) OR toLower(i.name) = toLower($val) MATCH (i)-[:ATTRIBUTED_TO|ALIASED_AS*0..1]-(tg:ThreatGroup) RETURN tg.name as tgname"
            res = graph_client.query(q_inc, {"val": k})
            tgs = [r['tgname'] for r in res if r.get('tgname')]
            tg_cache[cache_key] = tgs
            return tgs
        
        q_resolve = """
            MATCH (n)
            WHERE toLower(n.name) = toLower($val) OR toLower(n.value) = toLower($val) 
               OR toLower(n.url) = toLower($val) OR toLower(n.cve_id) = toLower($val) 
               OR toLower(n.title) = toLower($val)
            WITH n LIMIT 5
            OPTIONAL MATCH (n)-[:ATTRIBUTED_TO|INDICATES|RELATED_TO|USES|ALIASED_AS*1..2]-(tg1:ThreatGroup)
            OPTIONAL MATCH (n)-[:STARTS_WITH|NEXT|HAS_INDICATOR|USES_MALWARE|EXPLOITS|ALIASED_AS*1..3]-(i:Incident)
            OPTIONAL MATCH (i)-[:ATTRIBUTED_TO|ALIASED_AS*0..1]-(tg2:ThreatGroup)
            WITH collect(distinct tg1.name) + collect(distinct tg2.name) AS tgs
            UNWIND tgs AS tgname
            RETURN DISTINCT tgname LIMIT 15
        """
        res = graph_client.query(q_resolve, params={'val': k})
        tgs = [r['tgname'] for r in res if r.get('tgname')] if res else []
        tg_cache[cache_key] = tgs
        return tgs

    # User input artifacts set for easy lookup
    input_values = {a['value'].lower(): a['value'] for a in artifacts}

    # Aggregate by ThreatGroup
    aggregated_tgs: Dict[str, Dict[str, Any]] = {}

    for r in raw_rows:
        label_val = r.get('label')
        r_type = (r.get('type') or '').strip()
        dist = r.get('dist', 10) or 10
        # path_nodes: [{'name': '...', 'labels': [...]}, ...]
        path_nodes = r.get('path_nodes') or []
        
        resolved_tgs = []
        if r_type == 'ThreatGroup':
            resolved_tgs = [label_val]
        else:
            resolved_tgs = _find_threatgroups_for_label(label_val, r_type)

        for tg_name in resolved_tgs:
            if not tg_name: continue
            if tg_name not in aggregated_tgs:
                aggregated_tgs[tg_name] = {
                    'label': tg_name,
                    'min_dist': 999,
                    'paths': [],
                    'input_hits': set(),  # Which of our input artifacts hit this TG
                    'intermediate_nodes': set() # Shared knowledge nodes
                }
            
            agg = aggregated_tgs[tg_name]
            agg['min_dist'] = min(agg['min_dist'], dist)
            
            # Extract evidence from path
            current_path_names = []
            for node in path_nodes:
                name = node.get('name')
                labels = node.get('labels') or []
                safe_name = name if name else ""
                current_path_names.append(safe_name)
                
                # [개선] 노드 이름과 입력값 간의 부분 일치 탐지 (IP, URL 조각 등 대응)
                sn_lower = safe_name.lower()
                for val_lower, original_val in input_values.items():
                    if val_lower and sn_lower and (val_lower in sn_lower or sn_lower in val_lower):
                        agg['input_hits'].add(original_val)
                
                # If this node is a mid-level clue (Malware, Tech, Vuln, etc.)
                clue_labels = {'Malware', 'Vulnerability', 'AttackTechnique', 'Indicator', 'Tool'}
                if clue_labels.intersection(set(labels)):
                    # 입력값 자체가 아니고 TG 자체도 아닌 경우에만 중간 노드로 기록
                    is_input = any(val_lower in sn_lower or sn_lower in val_lower for val_lower in input_values)
                    if not is_input and safe_name != tg_name:
                        agg['intermediate_nodes'].add(safe_name)
            
            agg['paths'].append(current_path_names)

    # Final scoring and formatting
    formatted_results: List[Dict[str, Any]] = []
    evidence_summary_for_ai: List[str] = []

    for label, agg in aggregated_tgs.items():
        # 1. Proximity Score (얼마나 직접적으로 연결되었나)
        proximity_score = 1.0 / (1 + agg['min_dist'])
        
        # 2. Breadth Score (몇 개의 입력 단서가 이 그룹을 지목하나 - 가장 중요)
        hit_count = len(agg['input_hits'])
        breadth_score = hit_count / len(artifacts)
        
        # 3. Overlap Score (입력값 외에 공유하는 정보(Malware, CVE 등)가 얼마나 많은가)
        # 단순히 개수가 아니라 전체 DB 규모 대비 비중이 중요하겠지만, 여기서는 양적 지표로 활용
        overlap_score = min(1.0, len(agg['intermediate_nodes']) / 10.0) 
        
        # 4. 가중치 결합 (Breadth 가중치 강화)
        # 단서가 많이 겹칠수록 점수의 차이를 크게 벌림
        final_score = (proximity_score * 0.2) + (breadth_score * 0.6) + (overlap_score * 0.2)
        
        # 인시던트 데이터 기반인 경우 신뢰도 보정
        has_incident_link = any('Incident' in str(p) for p in agg['paths'])
        if has_incident_link:
            final_score *= 1.15
        
        # 최종 점수 스케일링
        percent = min(round(final_score * 100, 1), 100.0)
        
        # 매칭된 단서 목록 (UI 표시용)
        matched_clues = sorted(list(agg['input_hits']))
        evidence_clues = sorted(list(agg['intermediate_nodes']))[:5] # 너무 많으면 자름

        formatted_results.append({
            "type": "ThreatGroup",
            "label": label,
            "score": round(final_score, 3),
            "percent": percent,
            "matches": ' | '.join(matched_clues) if matched_clues else "Indirect Connection",
            "evidence": ', '.join(evidence_clues),
            "uri": label
        })
        
        evidence_summary_for_ai.append({
            "ThreatGroup": label,
            "MatchConfidence": f"{percent}%",
            "DirectInputHits": matched_clues,
            "SharedKnowledgeNodes": list(agg['intermediate_nodes']),
            "SamplePaths": agg['paths'][:3]
        })

    if not formatted_results:
        return [], "조건에 맞는 위협 그룹을 찾지 못했습니다."

    # 높은 점수 순으로 정렬
    formatted_results = sorted(formatted_results, key=lambda x: x['score'], reverse=True)[:15]

    system_msg = """You are a senior Cyber Threat Intelligence Analyst. Your task is to synthesize raw findings into a concise intelligence report.
Your answer MUST be in Korean."""
    
    user_msg = f"""
[Task]
제공된 단서(Artifacts)와 지식 그래프 분석 결과를 토대로 위협 인텔리전스 보고서를 작성하세요.
단순히 목록을 나열하지 말고, 왜 특정 그룹이 배후로 강력하게 의심되는지 논리적으로 설명해야 합니다.

[Context]
- 입력된 단서: {json.dumps(list(input_values.values()), ensure_ascii=False)}
- 분석 설정: Depth={depth}, Looseness={looseness}, Include Incidents={include_incidents}

[Knowledge Graph Findings]
아래는 그래프 DB에서 찾은 가용한 모든 연결 고리입니다.
{json.dumps(evidence_summary_for_ai, ensure_ascii=False, indent=2)}

[Report Requirements]
1. **결론 우선**: 가장 가능성이 높은 위협 그룹과 판단 근거 요약을 첫 부분에 작성하세요.
2. **근거 중심 추론**: 입력한 각각의 단서가 어떻게 해당 위협 그룹과 연결되는지(예: IP -> Malware A -> Group X) 그래프 경로를 기반으로 설명하세요.
3. **공유 지식 강조**: 여러 단서가 공통으로 거쳐가는 'Shared Knowledge Nodes'(악성코드, CVE 등)가 있다면 적극적으로 언급하여 연결의 견고함을 증명하세요.
4. **신뢰성 평가**: 분석 결과에 대한 신뢰도(높음, 중간, 낮음)를 명시하고 이유를 설명하세요.
5. **한국어 작성**: 모든 보고 내용은 한국어로 작성해야 합니다.

보고서를 시작하세요.
"""
    
    analysis = _generate_analysis(system_msg, user_msg)
    return formatted_results, analysis
