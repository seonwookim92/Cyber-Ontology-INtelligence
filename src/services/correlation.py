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

        # exact match
        sub_queries.append(f"""
            MATCH (candidate)
            WHERE {exact_cond}
            RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value) AS label, labels(candidate)[0] AS type, 0 AS dist,
                   ['ExactMatch:' + coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value)] AS matches
            LIMIT 200
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

        sub_queries.append(f"""
            MATCH (seed)
            WHERE {seed_match}
            CALL apoc.path.expandConfig(seed, {{relationshipFilter: 'USES>|INDICATES>|RELATED_TO>|CONNECTED>|RELATED>|ASSOCIATED_WITH>', labelFilter: '{label_allow}', maxLevel: {depth}, limit: 200}}) YIELD path
            WITH last(nodes(path)) AS candidate, path, length(path) AS dist
            WHERE candidate IS NOT NULL
            RETURN coalesce(candidate.name, candidate.cve_id, candidate.url, candidate.value) AS label, (CASE WHEN 'ThreatGroup' IN labels(candidate) THEN 'ThreatGroup' ELSE head(labels(candidate)) END) AS type, dist AS dist,
                   [n IN nodes(path) | coalesce(n.name, n.cve_id, n.url, n.value)] AS matches
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
    rows: List[Dict[str, Any]] = []
    for q in sub_queries:
        try:
            res = graph_client.query(q)
            if res:
                for r in res:
                    rows.append(r)
        except Exception as e:
            rows.append({'label': None, 'type': 'QueryError', 'dist': 9999, 'matches': [f'QueryError: {str(e)}']})

    # Map non-ThreatGroup candidates to ThreatGroup(s) where possible
    tg_cache: Dict[str, List[str]] = {}

    def _find_threatgroups_for_label(val: str) -> List[str]:
        k = val or ''
        if k in tg_cache:
            return tg_cache[k]
        # exact match first
        q_exact = """
            MATCH (n)
            WHERE toLower(coalesce(n.name,'') + ' ' + coalesce(n.value,'')) = toLower($val)
            OPTIONAL MATCH (n)-[:INDICATES]->(m:Malware)<-[:USES]-(tg:ThreatGroup)
            OPTIONAL MATCH (n)-[:ATTRIBUTED_TO]-(tg2:ThreatGroup)
            OPTIONAL MATCH (tg3:ThreatGroup)-[:USES]->(n)
            WITH collect(distinct tg.name) + collect(distinct tg2.name) + collect(distinct tg3.name) AS tgs
            UNWIND tgs AS tgname
            RETURN DISTINCT tgname LIMIT 10
        """
        res = graph_client.query(q_exact, params={'val': k})
        tgs = [r.get('tgname') or list(r.values())[0] for r in res] if res else []
        if not tgs:
            # try contains fallback
            q_cont = """
                MATCH (n)
                WHERE toLower(coalesce(n.name,'') + ' ' + coalesce(n.value,'')) CONTAINS toLower($val)
                OPTIONAL MATCH (n)-[:INDICATES]->(m:Malware)<-[:USES]-(tg:ThreatGroup)
                OPTIONAL MATCH (n)-[:ATTRIBUTED_TO]-(tg2:ThreatGroup)
                OPTIONAL MATCH (tg3:ThreatGroup)-[:USES]->(n)
                WITH collect(distinct tg.name) + collect(distinct tg2.name) + collect(distinct tg3.name) AS tgs
                UNWIND tgs AS tgname
                RETURN DISTINCT tgname LIMIT 10
            """
            res = graph_client.query(q_cont, params={'val': k})
            tgs = [r.get('tgname') or list(r.values())[0] for r in res] if res else []
        tg_cache[k] = tgs
        return tgs

    # Scoring
    formatted_results: List[Dict[str, Any]] = []
    evidence_list: List[str] = []

    for r in rows:
        raw_score = r.get('raw_score', 0) or 0
        dist = r.get('dist', 10) or 10
        matches = r.get('matches') or []

        # If this candidate is not a ThreatGroup, try to map to ThreatGroup(s)
        r_type = (r.get('type') or '').strip()
        if r_type != 'ThreatGroup':
            label_val = r.get('label')
            tgs = _find_threatgroups_for_label(label_val)
            if tgs:
                # create synthetic rows for each mapped ThreatGroup
                for tg_name in tgs:
                    synth = {
                        'label': tg_name,
                        'type': 'ThreatGroup',
                        'dist': dist + 1,
                        'matches': (matches if isinstance(matches, list) else [matches]) + [f'LinkedVia:{label_val}'],
                        'raw_score': raw_score
                    }
                    rows.append(synth)
                continue
            # if no mapped TGs, skip this non-TG candidate
            continue

        proximity_score = 1.0 / (1 + float(dist))
        text_score = min(1.0, raw_score / max(1, len(artifacts)))
        provenance_weight = 1.0
        if any('Incident' in str(m) or 'incident' in str(m) for m in matches):
            provenance_weight = 1.2

        combined = (proximity_score * 0.6 + text_score * 0.3) * provenance_weight
        percent = min(round(combined * 100, 1), 100.0)

        formatted_results.append({
            "type": r.get('type') or 'Unknown',
            "label": r.get('label'),
            "score": round(combined, 3),
            "percent": percent,
            "matches": ' | '.join([str(x) for x in (matches if isinstance(matches, list) else [matches])]),
            "uri": r.get('label')
        })

        evidence_list.append(f"Suspect: {r.get('label')} (RawMatches: {raw_score}) -> Reasons: {matches}")

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
The following is a raw list of potential connections found in the knowledge graph. 'Suspect' is a potential threat group, and 'Reasons' are the connection paths or evidence found.
```json
{json.dumps(evidence_list, indent=1)}
```

[Report Requirements]
1.  **Main Conclusion First**: Start by stating the most probable Threat Group.
2.  **Evidence-based Reasoning**: Justify your conclusion by referencing the specific connections from the '[Findings]'. Explain *how* the user's artifacts link to the suspected group through the evidence paths (e.g., "The provided IP address is a known C2 server for Malware X, which is a tool exclusively used by Lazarus Group.").
3.  **Synthesize, Don't Just List**: Do not simply list the findings. Weave them into a coherent narrative that explains the relationship between the artifacts and the threat actor.
4.  **Confidence Level**: State your confidence level (e.g., High, Medium, Low) and briefly explain what would be needed to increase it.
5.  **DO NOT Include**: Do not provide mitigation advice, recommendations, or generic descriptions of the threat group. Focus *only* on the evidence-based attribution.

Begin your report now.
"""

    analysis = _generate_analysis(system_msg, user_msg)
    return formatted_results, analysis
