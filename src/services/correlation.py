import json
from typing import List, Dict, Tuple, Any

import json
from typing import List, Dict, Tuple, Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser

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
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", user_prompt)
        ])
        chain = prompt | llm | StrOutputParser()
        return chain.invoke({})
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
                   ['ExactMatch:' + coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title)] AS matches
            LIMIT 100
        """)

        # contains match (Priority 2) - Critical for URLs/Path fragments
        sub_queries.append(f"""
            MATCH (candidate)
            WHERE toLower({_coalesce_fields('candidate')}) CONTAINS toLower('{safe_val}')
            RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title) AS label, 
                   labels(candidate)[0] AS type, 1 AS dist,
                   ['PartialMatch:' + coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value, candidate.title)] AS matches
            LIMIT 100
        """)

        # fulltext or contains fallback
        if looseness >= 20 and fulltext_available:
            idx = fulltext_index_name
            escaped_val = _escape_lucene_query(safe_val)
            ft_q = f"CALL db.index.fulltext.queryNodes('{idx}', '{escaped_val}~') YIELD node, score RETURN coalesce(node.name,node.cve_id,node.url,node.value) AS label, (CASE WHEN 'ThreatGroup' IN labels(node) THEN 'ThreatGroup' ELSE head(labels(node)) END) AS type, 1 AS dist, [coalesce(node.name,node.cve_id,node.url,node.value)] AS matches, score AS raw_score LIMIT 200"
            sub_queries.append(ft_q)
        else:
            sub_queries.append(f"""
                MATCH (candidate)
                WHERE {contains_cond}
                RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value) AS label, labels(candidate)[0] AS type, 5 AS dist,
                       ['ContainsFallback:' + coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value)] AS matches
                LIMIT 500
            """)

        # seed-driven expansion (ontology expansion)
        seed_match = f"toLower({_coalesce_fields('seed')}) CONTAINS toLower('{safe_val}') OR toLower({_coalesce_fields('seed')}) = toLower('{safe_val}')"
        label_allow = "+(ThreatGroup|Campaign|Actor|Incident|Malware|Indicator|Vulnerability|AttackTechnique|Tool|Identity)"
        if not include_incidents:
            label_allow = label_allow.replace('|Incident', '')

        # seed-driven expansion (deep correlation)
        seed_match = f"toLower({_coalesce_fields('seed')}) CONTAINS toLower('{safe_val}')"
        label_allow = "+(ThreatGroup|Campaign|Actor|Incident|Malware|Indicator|Vulnerability|AttackTechnique|Tool|Identity|AttackStep)"
        if not include_incidents:
            label_allow = label_allow.replace('|Incident', '').replace('|AttackStep', '')

        # Focused relationship filter based on diagnostic successful paths
        rel_filter = 'USES|INDICATES|RELATED_TO|CONNECTED|RELATED|ASSOCIATED_WITH|USES_MALWARE|EXPLOITS|HAS_INDICATOR|ATTRIBUTED_TO|TARGETS|STARTS_WITH|NEXT'

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
                   [n IN nodes(path) | coalesce(n.name, n.title, n.cve_id, n.url, n.value)] AS matches
            LIMIT 100
        """)

        if looseness >= 60:
            sub_queries.append(f"""
                MATCH (candidate)
                WHERE {contains_cond}
                RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value) AS label, (CASE WHEN 'ThreatGroup' IN labels(candidate) THEN 'ThreatGroup' ELSE head(labels(candidate)) END) AS type, 6 AS dist,
                       ['AggressiveContains:' + coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value)] AS matches
                LIMIT 1000
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
        except Exception as e:
            raw_rows.append({'label': None, 'type': 'QueryError', 'dist': 9999, 'matches': [f'QueryError: {str(e)}']})

    # Map non-ThreatGroup candidates to ThreatGroup(s) and collect all possible TG matches
    tg_matches: List[Dict[str, Any]] = []
    tg_cache: Dict[str, List[str]] = {}

    def _find_threatgroups_for_label(val: str, itype: str = None) -> List[str]:
        """Memory-efficient resolution of ThreatGroups."""
        k = val or ''
        cache_key = f"{k}_{itype}"
        if cache_key in tg_cache:
            return tg_cache[cache_key]
        
        # If it's already an Incident, we just need its attribution
        if itype == 'Incident':
            q_inc = "MATCH (i:Incident) WHERE i.title = $val OR i.name = $val MATCH (i)-[:ATTRIBUTED_TO]-(tg:ThreatGroup) RETURN tg.name as tgname"
            res = graph_client.query(q_inc, {"val": k})
            tgs = [r['tgname'] for r in res if r.get('tgname')]
            tg_cache[cache_key] = tgs
            return tgs
        
        # Diagnostic-informed deep search through static TI and Incident paths
        q_resolve = """
            MATCH (n)
            WHERE n.name = $val OR n.value = $val OR n.url = $val OR n.cve_id = $val OR n.title = $val
               OR toLower(coalesce(n.name, '')) CONTAINS toLower($val)
               OR toLower(coalesce(n.url, '')) CONTAINS toLower($val)
            
            WITH n LIMIT 5
            OPTIONAL MATCH (n)-[:ATTRIBUTED_TO|INDICATES|RELATED_TO|USES*1..2]-(tg1:ThreatGroup)
            
            OPTIONAL MATCH (n)-[:STARTS_WITH|NEXT|HAS_INDICATOR|USES_MALWARE|EXPLOITS*1..3]-(i:Incident)
            OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]-(tg2:ThreatGroup)
            
            WITH collect(distinct tg1.name) + collect(distinct tg2.name) AS tgs
            UNWIND tgs AS tgname
            RETURN DISTINCT tgname LIMIT 15
        """
        res = graph_client.query(q_resolve, params={'val': k})
        tgs = [r.get('tgname') for r in res if r.get('tgname')] if res else []
        tg_cache[cache_key] = tgs
        return tgs

    for r in raw_rows:
        r_type = (r.get('type') or '').strip()
        label_val = r.get('label')
        dist = r.get('dist', 10) or 10
        matches = r.get('matches') or []
        raw_score = r.get('raw_score', 0) or 0

        if r_type == 'ThreatGroup':
            tg_matches.append(r)
        else:
            tgs = _find_threatgroups_for_label(label_val, r_type)
            for tg_name in tgs:
                tg_matches.append({
                    'label': tg_name,
                    'type': 'ThreatGroup',
                    'dist': dist + (1 if r_type == 'Incident' else 2),
                    'matches': (matches if isinstance(matches, list) else [matches]) + [f'LinkedVia:{label_val}'],
                    'raw_score': raw_score
                })

    # Aggregate by ThreatGroup to show multiple pieces of evidence
    aggregated_tgs: Dict[str, Dict[str, Any]] = {}
    for r in tg_matches:
        label = r['label']
        if not label: continue
        
        if label not in aggregated_tgs:
            aggregated_tgs[label] = {
                'label': label,
                'type': 'ThreatGroup',
                'min_dist': r['dist'],
                'all_matches': set(),
                'total_raw_score': 0,
                'match_count': 0
            }
        
        agg = aggregated_tgs[label]
        agg['min_dist'] = min(agg['min_dist'], r['dist'])
        agg['total_raw_score'] += r.get('raw_score', 0) or 0
        agg['match_count'] += 1
        
        # Add matches to a set to avoid duplicates and gather all evidence
        m_list = r.get('matches') or []
        for m in (m_list if isinstance(m_list, list) else [m_list]):
            agg['all_matches'].add(str(m))

    # User input values for filtering evidence path
    user_input_values = {str(a['value']).lower() for a in artifacts}

    # Scoring and formatting
    formatted_results: List[Dict[str, Any]] = []
    evidence_summary_for_ai: List[str] = []

    for label, agg in aggregated_tgs.items():
        dist = agg['min_dist']
        all_matches = sorted(list(agg['all_matches']))
        
        # Filter: Only keep matches that are in our original user input list
        matched_clues = []
        for m in all_matches:
            # Check if this match string (or part of it for prefixed ones) is in our input set
            m_clean = m.lower()
            if ":" in m_clean: # Handle prefixes like 'ExactMatch:', 'LinkedVia:'
                parts = m_clean.split(":", 1)
                if len(parts) > 1 and parts[1] in user_input_values:
                    # Find the original case-sensitive value if possible, or just use the part
                    matched_clues.append(m.split(":", 1)[1])
            elif m_clean in user_input_values:
                matched_clues.append(m)
        
        # Deduplicate and sort matched clues
        matched_clues = sorted(list(set(matched_clues)))
        
        proximity_score = 1.0 / (1 + float(dist))
        # Weight score by number of unique USER artifacts that hit this TG
        breadth_score = min(1.0, len(matched_clues) / max(1, len(artifacts)))
        
        provenance_weight = 1.0
        if any('Incident' in str(m) or 'incident' in str(m) for m in all_matches):
            provenance_weight = 1.2

        # Combined score: Proximity tells us how close it is, breadth tells us how many artifacts hit it
        combined = (proximity_score * 0.4 + breadth_score * 0.5 + min(0.1, agg['total_raw_score']/100)) * provenance_weight
        percent = min(round(combined * 100, 1), 100.0)

        formatted_results.append({
            "type": "ThreatGroup",
            "label": label,
            "score": round(combined, 3),
            "percent": percent,
            "matches": ' | '.join(matched_clues) if matched_clues else "Indirect Link",
            "uri": label
        })
        evidence_summary_for_ai.append(f"ThreatGroup: {label} -> MatchedClues: {matched_clues}, FullPathEvidence: {all_matches}")

    if not formatted_results:
        return [], "조건에 맞는 위협 그룹을 찾지 못했습니다."

    formatted_results = sorted(formatted_results, key=lambda x: x['score'], reverse=True)[:20]

    system_msg = """You are a senior Cyber Threat Intelligence Analyst. Your task is to synthesize raw findings into a concise intelligence report.
Your answer MUST be in Korean."""
    user_msg = f"""
[Task]
Based on the provided context and findings, create a threat intelligence report.
Your primary goal is to identify the most likely Threat Group responsible and build a logical case for your conclusion.

[Context]
- User-provided Artifacts: {json.dumps([a['value'] for a in artifacts])}
- Analysis Parameters: Depth={depth}, Looseness={looseness}, Include Incidents={include_incidents}

[Findings]
The following is a raw list of potential connections found in the knowledge graph. 'ThreatGroup' is the suspect, 'MatchedClues' are the user artifacts that triggered the match, and 'FullPathEvidence' shows the graph paths.
```json
{json.dumps(evidence_summary_for_ai, indent=1)}
```

[Report Requirements]
1.  **Main Conclusion First**: Start by stating the most probable Threat Group.
2.  **Evidence-based Reasoning**: Justify your conclusion by referencing the specific connections from the '[Findings]'. Explain *how* the user's artifacts link to the suspected group through the evidence paths (e.g., "The provided IP address is a known C2 server for Malware X, which is a tool exclusively used by Lazarus Group.").
3.  **Synthesize, Don't Just List**: Do not simply list the findings. Weave them into a coherent narrative that explains the relationship between the artifacts and the threat actor.
4.  **Confidence Level**: State your confidence level (e.g., High, Medium, Low) and briefly explain what would be needed to increase it.
5.  **DO NOT Include**: Do not provide mitigation advice, recommendations, or generic descriptions of the threat group. Focus *only* on the evidence-based attribution.
6.  **Language Requirement**: **All responses must be in Korean (한국어).** 

Begin your report now.
"""

    analysis = _generate_analysis(system_msg, user_msg)
    return formatted_results, analysis
