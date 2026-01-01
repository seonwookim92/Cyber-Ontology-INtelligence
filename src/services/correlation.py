import json
from typing import List, Dict, Tuple, Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser

from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 0. LLM Helper (Analysis.py와 동일한 로직)
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
# 1. 스마트 힌트 서비스 (Smart Hinting)
# ==============================================================================

def get_smart_hints(target_type: str, context_artifacts: List[Dict[str, str]], limit: int = 20) -> List[str]:
    hints = []
    
    # 1. 문맥 기반 추천 (Context-aware)
    if context_artifacts:
        prev_mal = next((x['value'] for x in context_artifacts if x['type'] == 'Malware'), None)
        prev_ind = next((x['value'] for x in context_artifacts if x['type'] == 'Indicator'), None)

        if target_type == "Indicator" and prev_mal:
            q = f"""MATCH (m:Malware)<-[:INDICATES]-(i:Indicator) WHERE toLower(m.name) = toLower("{prev_mal}") RETURN DISTINCT i.url as val LIMIT {limit}"""
            rows = graph_client.query(q)
            hints.extend([f"[Rel] {r['val']}" for r in rows])
        
        elif target_type == "Malware" and prev_ind:
            q = f"""MATCH (i:Indicator)-[:INDICATES]->(m:Malware) WHERE toLower(i.url) CONTAINS toLower("{prev_ind}") RETURN DISTINCT m.name as val LIMIT {limit}"""
            rows = graph_client.query(q)
            hints.extend([f"[Rel] {r['val']}" for r in rows])

    # 2. 일반 추천 (Fallback)
    if len(hints) < limit:
        needed = limit - len(hints)
        q = ""
        
        if target_type == "Indicator":
            q = f"MATCH (n:Indicator) RETURN n.url as val ORDER BY rand() LIMIT {needed}"
        elif target_type == "Malware":
            q = f"MATCH (n:Malware) RETURN n.name as val ORDER BY n.name LIMIT {needed}"
        elif target_type == "Vulnerability":
            q = f"MATCH (n:Vulnerability) RETURN n.cve_id as val ORDER BY n.date_added DESC LIMIT {needed}"
        
        # Threat Group 쿼리
        elif target_type == "Threat Group":
            q = f"MATCH (n:ThreatGroup) RETURN n.name as val ORDER BY n.name LIMIT {needed}"

        if q:
            rows = graph_client.query(q)
            hints.extend([r['val'] for r in rows])

    return sorted(list(set(hints)), key=lambda x: x.startswith("[Rel]"), reverse=True)[:limit]


def run_correlation_analysis(artifacts: List[Dict[str, str]], depth: int = 1) -> Tuple[List[Dict[str, Any]], str]:
    sub_queries = []
    
    for art in artifacts:
        val = art['value']
        atype = art['type']
        safe_val = val.replace('"', '\\"').replace("'", "\\'")
        
        # [1단계] 표면적 연결
        if atype == "Malware":
            sub_queries.append(f"""
                MATCH (entity:ThreatGroup)-[:USES]->(m:Malware)
                WHERE toLower(m.name) CONTAINS toLower("{safe_val}")
                RETURN entity.name as label, 'ThreatGroup' as type, 
                       'Direct Match: Uses Malware (' + m.name + ')' as reason
            """)
        # [추가] Threat Group이 직접 입력된 경우 (자기 자신 찾기)
        elif atype == "Threat Group":
            sub_queries.append(f"""
                MATCH (entity:ThreatGroup)
                WHERE toLower(entity.name) CONTAINS toLower("{safe_val}")
                RETURN entity.name as label, 'ThreatGroup' as type,
                       'Direct Match: Group Name Identified' as reason
            """)
            
        # [2단계] 추론적 연결
        if depth >= 2:
            if atype == "Indicator":
                sub_queries.append(f"""
                    MATCH (i:Indicator)-[:INDICATES]->(m:Malware)<-[:USES]-(entity:ThreatGroup)
                    WHERE toLower(i.url) CONTAINS toLower("{safe_val}") OR toLower(i.tags) CONTAINS toLower("{safe_val}")
                    RETURN entity.name as label, 'ThreatGroup' as type,
                           'Via Malware (' + m.name + ') linked to IOC' as reason
                """)
            elif atype == "Vulnerability":
                sub_queries.append(f"""
                    MATCH (v:Vulnerability)-[:RELATED_TO]->(t:AttackTechnique)<-[:USES]-(entity:ThreatGroup)
                    WHERE toLower(v.cve_id) CONTAINS toLower("{safe_val}") OR toLower(v.product) CONTAINS toLower("{safe_val}")
                    RETURN entity.name as label, 'ThreatGroup' as type,
                           'Targeting similar Tech (' + t.mitre_id + ') related to ' + v.cve_id as reason
                """)
                
        # [3단계] 심층 연결
        if depth >= 3:
             if atype == "Malware":
                 sub_queries.append(f"""
                    MATCH (m:Malware)-[:USES]->(t:AttackTechnique)<-[:USES]-(entity:ThreatGroup)
                    WHERE toLower(m.name) CONTAINS toLower("{safe_val}")
                    RETURN entity.name as label, 'ThreatGroup' as type,
                           'Shared TTP (' + t.mitre_id + ') with Malware ' + m.name as reason
                 """)

    if not sub_queries:
        return [], "분석 가능한 아티팩트가 없거나, 선택된 심도(Depth)에서는 탐색 경로가 정의되지 않았습니다."

    full_query_parts = " UNION ALL ".join(sub_queries)
    
    final_query = f"""
    CALL {{
        {full_query_parts}
    }}
    WITH label, type, collect(distinct reason) as matches
    RETURN label, type, size(matches) as score, matches
    ORDER BY score DESC LIMIT 10
    """
    
    try:
        results = graph_client.query(final_query)
    except Exception as e:
        return [], f"Query Error: {str(e)}"
    
    formatted_results = []
    evidence_list = []
    
    for r in results:
        score = r['score']
        matches = r['matches']
        percent = min((score / len(artifacts)) * 100, 100)
        
        formatted_results.append({
            "type": r['type'],
            "label": r['label'],
            "score": score,
            "percent": round(percent, 1),
            "matches": " | ".join(matches),
            "uri": r['label']
        })
        evidence_list.append(f"Suspect: {r['label']} (Matches: {score}) -> Reasons: {matches}")

    if not formatted_results:
        return [], "조건에 맞는 위협 그룹을 찾지 못했습니다."

    system_msg = "You are a Cyber Threat Intelligence Analyst. Always answer in Korean."
    user_msg = f"""
    [Context] Depth: {depth}, User Artifacts: {[a['value'] for a in artifacts]}
    [Findings] {json.dumps(evidence_list, indent=1)}
    
    Analyze the correlation results. Identify the most suspicious Threat Group and explain why.
    """
    
    analysis = _generate_analysis(system_msg, user_msg)
    return formatted_results, analysis