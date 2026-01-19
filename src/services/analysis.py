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
# 1. 목록 조회 서비스 (Selection Helpers)
# ==============================================================================
def get_entity_list(entity_type: str, limit: int = 100, search_query: str = None) -> List[Dict[str, str]]:
    """
    선택창(SelectBox)에 띄울 엔티티 목록을 가져옵니다. (연관도 순 정렬)
    """
    params = {"limit": limit, "query": search_query.lower() if search_query else ""}
    
    # 기본 필터링 및 점수 계산 로직
    if search_query:
        # 검색어가 있을 경우 SQL의 LIKE/CONTAINS와 유사하게 필터링
        sq = search_query.lower()
        
        # Incident의 경우 태그 클릭 시 [2024-01-01] Title... 형태이므로 전처리 필요
        if entity_type == "Incident" and sq.startswith("[") and "]" in sq:
            try:
                sq = sq.split("]", 1)[1].split("(", 1)[0].strip()
            except:
                pass
        
        params["query"] = sq # 필터링에 사용할 정제된 검색어
        
        if entity_type == "Incident":
            q = """
            MATCH (n:Incident)
            WHERE toLower(n.title) CONTAINS $query OR toLower(n.summary) CONTAINS $query
            OPTIONAL MATCH (n)-[:TARGETS]->(v:Identity)
            WITH n, v,
                 CASE 
                   WHEN toLower(n.title) = $query THEN 100
                   WHEN toLower(n.title) CONTAINS $query THEN 50
                   ELSE 20
                 END as score
            RETURN n.id as uri, 
                   '[' + substring(n.timestamp, 0, 10) + '] ' + n.title + ' (' + coalesce(v.name, 'Unknown') + ')' as label
            ORDER BY score DESC, n.timestamp DESC LIMIT $limit
            """
        elif entity_type == "Threat Group":
            q = """
            MATCH (n:ThreatGroup)
            WHERE toLower(n.name) CONTAINS $query OR toLower(n.description) CONTAINS $query
            WITH n,
                 CASE 
                   WHEN toLower(n.name) = $query THEN 100
                   WHEN toLower(n.name) STARTS WITH $query THEN 50
                   ELSE 20
                 END as score
            RETURN n.mitre_id as uri, n.name as label
            ORDER BY score DESC, n.name ASC LIMIT $limit
            """
        elif entity_type == "Malware":
            q = """
            MATCH (n:Malware)
            WHERE toLower(n.name) CONTAINS $query
            WITH n,
                 CASE 
                   WHEN toLower(n.name) = $query THEN 100
                   WHEN toLower(n.name) STARTS WITH $query THEN 50
                   ELSE 20
                 END as score
            RETURN n.name as uri, n.name as label
            ORDER BY score DESC, n.name ASC LIMIT $limit
            """
        elif entity_type == "Vulnerability":
            q = """
            MATCH (n:Vulnerability)
            WHERE toLower(n.cve_id) CONTAINS $query OR toLower(n.description) CONTAINS $query
            WITH n,
                 CASE 
                   WHEN toLower(n.cve_id) = $query THEN 100
                   WHEN toLower(n.cve_id) STARTS WITH $query THEN 50
                   ELSE 20
                 END as score
            RETURN n.cve_id as uri, n.cve_id + ' (' + coalesce(n.product, 'Unknown') + ')' as label
            ORDER BY score DESC, n.date_added DESC LIMIT $limit
            """
    else:
        # 검색어 없는 경우 기존 최신/이름순 정렬
        if entity_type == "Incident":
            q = "MATCH (n:Incident) OPTIONAL MATCH (n)-[:TARGETS]->(v:Identity) RETURN n.id as uri, '[' + substring(n.timestamp, 0, 10) + '] ' + n.title + ' (' + coalesce(v.name, 'Unknown') + ')' as label ORDER BY n.timestamp DESC LIMIT $limit"
        elif entity_type == "Threat Group":
            q = "MATCH (n:ThreatGroup) WHERE n.name IS NOT NULL RETURN n.mitre_id as uri, n.name as label ORDER BY n.name ASC LIMIT $limit"
        elif entity_type == "Malware":
            q = "MATCH (n:Malware) RETURN n.name as uri, n.name as label ORDER BY n.name ASC LIMIT $limit"
        elif entity_type == "Vulnerability":
            q = "MATCH (n:Vulnerability) RETURN n.cve_id as uri, n.cve_id + ' (' + coalesce(n.product, 'Unknown') + ')' as label ORDER BY n.date_added DESC LIMIT $limit"
        else:
            return []

    results = graph_client.query(q, params)
    
    processed = []
    for r in results:
        processed.append({
            "uri": r.get("uri"),
            "label": r.get("label"),
            "uri_short": r.get("uri")
        })
    return processed

# ==============================================================================
# 2. 분석 서비스 (Analysis Logic)
# ==============================================================================

def analyze_incident(uri: str, label: str) -> Tuple[str, List[str]]:
    """
    [New] 실제 Incident 노드와 AttackStep을 순회하며 분석합니다.
    uri: Incident ID (e.g., incident--gen-1234)
    """
    # 1. Incident 기본 정보 + 피해 기관 + 배후 그룹
    q_header = """
    MATCH (i:Incident {id: $id})
    OPTIONAL MATCH (i)-[:TARGETS]->(v:Identity)
    OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(g:ThreatGroup)
    RETURN i.title as title, i.summary as summary, i.timestamp as date,
           v.name as victim, v.system as system,
           g.name as actor
    """
    
    # 2. 공격 단계 및 아티팩트 조회
    q_steps = """
    MATCH (i:Incident {id: $id})-[:STARTS_WITH]->(s:AttackStep)
    // 연결된 모든 단계 순차 조회 (Next 관계 따라가거나 Order로 정렬)
    // 여기서는 간단하게 Incident와 직/간접 연결된 모든 Step을 Order로 정렬
    MATCH (i)-[:STARTS_WITH|NEXT*]->(step:AttackStep)
    
    OPTIONAL MATCH (step)-[:USES_MALWARE]->(m:Malware)
    OPTIONAL MATCH (step)-[:EXPLOITS]->(vuln:Vulnerability)
    OPTIONAL MATCH (step)-[:HAS_INDICATOR]->(ind:Indicator)
    
    RETURN step.order as order, step.phase as phase, step.description as desc, 
           step.outcome as outcome,
           m.name as malware, vuln.cve_id as cve, ind.url as ioc
    ORDER BY step.order ASC
    """
    
    header = graph_client.query(q_header, {"id": uri})
    steps = graph_client.query(q_steps, {"id": uri})
    
    facts = []
    
    if header:
        h = header[0]
        facts.append(f"Incident: {h.get('title')}")
        facts.append(f"Date: {h.get('date')}")
        facts.append(f"Victim: {h.get('victim')} ({h.get('system')})")
        facts.append(f"Attributed Actor: {h.get('actor', 'Unknown')}")
        facts.append(f"Summary: {h.get('summary')}")
    else:
        facts.append(f"Incident ID '{uri}' not found.")

    if steps:
        facts.append("--- Attack Flow ---")
        for s in steps:
            step_info = f"[Step {s['order']}] {s['phase']}: {s['desc']} ({s['outcome']})"
            
            artifacts = []
            if s.get('malware'): artifacts.append(f"Malware: {s['malware']}")
            if s.get('cve'): artifacts.append(f"Vuln: {s['cve']}")
            if s.get('ioc'): artifacts.append(f"IoC: {s['ioc']}")
            
            if artifacts:
                step_info += f" -> Used: {', '.join(artifacts)}"
            
            facts.append(step_info)
    else:
        facts.append("No detailed attack steps found.")

    # 3. LLM 요청
    system_msg = "You are a Cyber Incident Responder. Always answer in Korean."
    user_msg = f"""
    [Incident Context]
    {json.dumps(facts, ensure_ascii=False, indent=1)}
    
    [Request]
    Based on the incident timeline and artifacts:
    1. Provide a post-mortem analysis of the attack (How it started, How it propagated).
    2. Assess the criticality of the compromised system.
    3. Suggest immediate response actions and long-term mitigation strategies.
    4. **All responses must be in Korean (한국어).**
    """
    
    analysis = _generate_analysis(system_msg, user_msg)
    return analysis, facts

def analyze_threat_group(uri: str, label: str) -> Tuple[str, List[str]]:
    """
    Threat Group을 분석합니다. 별칭(Aliases) 정보를 포함합니다.
    """
    q = f"""
    MATCH (g:ThreatGroup)
    WHERE g.name = '{label}' OR g.mitre_id = '{uri}'
    
    OPTIONAL MATCH (g)-[:ALIASED_AS]-(a:ThreatGroup)
    OPTIONAL MATCH (g)-[:USES]->(m:Malware)
    OPTIONAL MATCH (g)-[:USES]->(t:AttackTechnique)
    
    RETURN g.description as desc, 
           collect(distinct a.name) as aliases,
           collect(distinct m.name) as malwares,
           collect(distinct t.mitre_id + ' ' + t.name) as techniques
    """
    data = graph_client.query(q)
    
    facts = [f"Threat Actor: '{label}'"]
    
    if data:
        row = data[0]
        aliases = row.get('aliases', [])
        if aliases:
            facts.append(f"Aliases: {', '.join(aliases)}")
            
        facts.append(f"Description: {row.get('desc', '')[:300]}...")
        
        malwares = row.get('malwares', [])
        for m in malwares[:10]:
            facts.append(f"Uses Malware: {m}")
            
        techs = row.get('techniques', [])
        for t in techs[:10]:
            facts.append(f"Technique: {t}")
    else:
        facts.append("No data found for this group.")

    system_msg = "You are a Threat Intelligence Analyst. Answer in Korean."
    user_msg = f"""
    [Evidence]
    {json.dumps(facts, ensure_ascii=False, indent=1)}
    
    [Request]
    Profile this Threat Group.
    1. Summarize their characteristics and main tools (including aliases).
    2. Analyze their sophistication based on techniques.
    3. Recommended defenses.
    4. **All responses must be in Korean (한국어).**
    """
    analysis = _generate_analysis(system_msg, user_msg)
    return analysis, facts

def analyze_malware(uri: str, label: str) -> Tuple[str, List[str]]:
    """Malware 분석 시 별칭 정보를 포함합니다."""
    q = f"""
    MATCH (m:Malware) WHERE m.name = '{label}'
    OPTIONAL MATCH (m)-[:ALIASED_AS]-(a:Malware)
    OPTIONAL MATCH (m)-[:USES]->(t:AttackTechnique)
    OPTIONAL MATCH (g:ThreatGroup)-[:USES]->(m)
    RETURN m.description as desc,
           collect(distinct a.name) as aliases,
           collect(distinct t.mitre_id + ' ' + t.name) as techniques,
           collect(distinct g.name) as groups
    """
    data = graph_client.query(q)
    
    facts = [f"Malware: '{label}'"]
    if data:
        row = data[0]
        aliases = row.get('aliases', [])
        if aliases:
            facts.append(f"Aliases: {', '.join(aliases)}")
            
        facts.append(f"Description: {row.get('desc', '')[:200]}...")
        for g in row.get('groups', []): facts.append(f"Used By: {g}")
        for t in row.get('techniques', []): facts.append(f"Capability: {t}")

    system_msg = "You are a Malware Analyst. Answer in Korean."
    user_msg = f"""
    [Evidence] {json.dumps(facts, ensure_ascii=False)}
    Analyze this malware's capabilities and risk.
    **All responses must be in Korean (한국어).**
    """
    return _generate_analysis(system_msg, user_msg), facts

def analyze_cve(uri: str, label: str) -> Tuple[str, List[str]]:
    # (기존 로직 유지)
    q = f"""
    MATCH (v:Vulnerability) WHERE v.cve_id = '{uri}'
    OPTIONAL MATCH (v)-[:RELATED_TO]->(t:AttackTechnique)
    RETURN v.description as desc, v.product as product,
           collect(distinct t.mitre_id + ' ' + t.name) as techniques
    """
    data = graph_client.query(q)
    
    facts = [f"Vulnerability: {label}"]
    if data:
        row = data[0]
        facts.append(f"Product: {row.get('product')}")
        facts.append(f"Description: {row.get('desc')}")
        for t in row.get('techniques', []): facts.append(f"Related Tech: {t}")

    system_msg = "You are a Vulnerability Researcher. Answer in Korean."
    user_msg = f"""
    [Evidence] {json.dumps(facts, ensure_ascii=False)}
    Analyze the impact and risk of this CVE.
    **All responses must be in Korean (한국어).**
    """
    return _generate_analysis(system_msg, user_msg), facts