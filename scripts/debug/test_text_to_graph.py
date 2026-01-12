import os
import sys
import json
import re
import warnings
from difflib import SequenceMatcher
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

warnings.filterwarnings("ignore")

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# 1. Pydantic 스키마
# ==============================================================================
class Entity(BaseModel):
    name: str = Field(description="Specific name. Remove defanging brackets (e.g. 1.1[.]1.1 -> 1.1.1.1)")
    label: Literal[
        "Incident", "Malware", "ThreatGroup", "Vulnerability", 
        "AttackTechnique", "Indicator", "SecurityEntity", "Tool"
    ] = Field(description="Detailed type.")
    reasoning: str = Field(description="Short reasoning.")
    
    # 내부 처리용
    normalized_name: Optional[str] = None
    existing_id: Optional[str] = None
    db_label: Optional[str] = None 
    match_score: float = 0.0

class Relationship(BaseModel):
    source: str
    target: str
    type: str

class GraphExtraction(BaseModel):
    entities: List[Entity]
    relationships: List[Relationship]

# ==============================================================================
# 2. Regex 기반 강제 추출기 (LLM 보완용)
# ==============================================================================
def extract_iocs_regex(text: str) -> List[Entity]:
    """
    LLM이 놓친 IOC(IP, URL, MD5 등)를 정규표현식으로 강제 추출합니다.
    """
    iocs = []
    
    # 1. IPv4 (Defanged 포함: 1.1.1[.]1)
    ip_pattern = r'\b(?:\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3})\b'
    # 2. MD5 (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    # 3. URL (hxxp, http[:] 등 포함)
    url_pattern = r'(?:hxxp|http|https)(?:\[?:\s*\]?|:)(?:/{2}|\\{2})(?:[a-zA-Z0-9\-\.]+(?:\[?\.\]?)[a-zA-Z]{2,})(?:[^\s]*)'
    # 4. Domain (aaaa[.]cyou)
    domain_pattern = r'\b(?:[a-zA-Z0-9\-]+\.)+(?:\[?\.\]?)[a-zA-Z]{2,}\b'
    # 5. CVE
    cve_pattern = r'CVE-\d{4}-\d{4,7}'

    # CVE
    for match in re.findall(cve_pattern, text, re.IGNORECASE):
        iocs.append(Entity(name=match, label="Vulnerability", reasoning="Regex Extracted CVE"))

    # IPs
    for match in re.findall(ip_pattern, text):
        # CVE나 버전 번호(2024.12.31) 오탐지 제외
        if not re.search(r'^\d{4}', match): 
            iocs.append(Entity(name=match, label="Indicator", reasoning="Regex Extracted IP"))

    # MD5
    for match in re.findall(md5_pattern, text):
        iocs.append(Entity(name=match, label="Indicator", reasoning="Regex Extracted MD5"))
        
    # URLs
    for match in re.findall(url_pattern, text, re.IGNORECASE):
        iocs.append(Entity(name=match, label="Indicator", reasoning="Regex Extracted URL"))

    # Domains (URL에 포함 안된 것들)
    for match in re.findall(domain_pattern, text, re.IGNORECASE):
        # 제외 키워드
        if any(x in match.lower() for x in ["ahnlab", "security", "korea"]): continue
        iocs.append(Entity(name=match, label="Indicator", reasoning="Regex Extracted Domain"))

    return iocs

# ==============================================================================
# 3. 유틸리티 & 정제
# ==============================================================================
def get_extractor():
    if settings.LLM_PROVIDER == "openai":
        # 긴 문맥 처리를 위해 모델 지정 중요 (GPT-4o 권장)
        llm = ChatOpenAI(model=settings.OPENAI_MODEL, temperature=0)
    else:
        llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0)
    return llm.with_structured_output(GraphExtraction)

def clean_indicator(text: str) -> str:
    """[.] 제거 및 hxxp 변환, 포트 분리 전처리"""
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = text.replace("[:]", ":").replace("http", "http").replace("hxxp", "http")
    return text

def split_composite_indicator(entity: Entity) -> List[Entity]:
    """IP:Port 분리 로직"""
    if entity.label != "Indicator": return [entity]
    
    # 정규식: IP:Port (여러개 가능)
    match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):([\d,]+)$", entity.name)
    if match:
        ip = match.group(1)
        ports = match.group(2).split(',')
        new_entities = [Entity(name=ip, label="Indicator", reasoning="Extracted IP")]
        for p in ports:
            new_entities.append(Entity(name=f"{ip}:{p.strip()}", label="Indicator", reasoning="Extracted Socket"))
        return new_entities
    return [entity]

def refine_graph_data(llm_data: GraphExtraction, regex_entities: List[Entity]) -> GraphExtraction:
    """LLM 데이터 + Regex 데이터 병합 및 중복 제거"""
    
    # 1. 병합 (LLM 우선)
    all_entities = llm_data.entities + regex_entities
    
    # 2. 중복 제거 (이름 기준)
    unique_map = {}
    for ent in all_entities:
        clean_name = clean_indicator(ent.name)
        # 이미 존재하는데 현재 것이 Regex라면 스킵 (LLM의 라벨/설명이 더 정확할 수 있음)
        if clean_name in unique_map and "Regex" in ent.reasoning:
            continue
        ent.name = clean_name
        unique_map[clean_name] = ent
    
    final_entities = []
    # 3. 분리 (Split Composite)
    for ent in unique_map.values():
        final_entities.extend(split_composite_indicator(ent))
        
    # 4. 고아 노드 연결 (Orphan Linking)
    # LLM이 Incident를 찾았다면, Regex로 찾은 고아 IOC들도 거기에 연결해준다.
    incidents = [e for e in final_entities if e.label == "Incident"]
    main_incident_name = incidents[0].name if incidents else "Detected Incident"
    
    # 관계 업데이트
    final_rels = llm_data.relationships[:] # 복사
    existing_rel_targets = {r.target for r in final_rels}
    
    for ent in final_entities:
        # 관계가 없는 Indicator/Malware는 메인 사건에 연결
        if ent.label in ["Indicator", "Malware"] and ent.name not in existing_rel_targets:
            # 사건 -> 지표 연결
            final_rels.append(Relationship(
                source=main_incident_name,
                target=ent.name,
                type="HAS_INDICATOR" if ent.label == "Indicator" else "USES_MALWARE"
            ))

    return GraphExtraction(entities=final_entities, relationships=final_rels)

# ==============================================================================
# 4. Grounding Logic
# ==============================================================================
def calculate_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def normalize_entity(entity: Entity) -> Entity:
    clean_name = entity.name
    
    if entity.label in ["Incident", "SecurityEntity"]:
        entity.normalized_name = clean_name
        entity.match_score = 1.0
        return entity

    query = f"""
    MATCH (n)
    WHERE toLower(n.name) CONTAINS toLower($name) 
       OR toLower($name) CONTAINS toLower(n.name)
    RETURN n.name as name, coalesce(n.id, elementId(n)) as id, labels(n) as labels
    LIMIT 10
    """
    
    try:
        results = graph_client.query(query, {"name": clean_name})
    except Exception:
        results = []
    
    best_match = None
    best_score = 0.0

    if results:
        for r in results:
            score = calculate_similarity(clean_name, r['name'])
            if clean_name.lower() == r['name'].lower(): score = 1.0
            
            valid_labels = [l for l in r['labels'] if l not in ['BaseNode', 'Resource', 'Entity']]
            primary_label = valid_labels[0] if valid_labels else r['labels'][0]

            if score > best_score:
                best_score = score
                best_match = {"name": r['name'], "id": r['id'], "label": primary_label}

    # [수정] 임계값 상향 (0.6 -> 0.8) : NetCat <-> Net 오탐지 방지
    if best_match and best_score >= 0.8: 
        entity.normalized_name = best_match['name']
        entity.existing_id = str(best_match['id'])
        entity.db_label = best_match['label']
        entity.match_score = best_score
    else:
        entity.normalized_name = clean_name
        entity.db_label = entity.label
        entity.match_score = best_score if best_match else 0.0
        
    return entity

# ==============================================================================
# 5. 실행
# ==============================================================================
def run_interactive_test():
    extractor = get_extractor()
    
    print("\n" + "="*60)
    print("📝 Paste your threat report text below. (Ctrl+D to submit)")
    print("="*60)
    
    try:
        lines = sys.stdin.readlines()
    except EOFError:
        pass
    text_input = "".join(lines).strip()
    if not text_input: return

    print(f"\n🚀 [Step 1] Hybrid Extraction (LLM + Regex)...")
    
    # 1. LLM Extraction
    llm_result = extractor.invoke(text_input)
    print(f"   -> LLM found: {len(llm_result.entities)} entities.")
    
    # 2. Regex Extraction
    regex_entities = extract_iocs_regex(text_input)
    print(f"   -> Regex found: {len(regex_entities)} potential IOCs.")
    
    # 3. Refinement & Merge
    result = refine_graph_data(llm_result, regex_entities)
    valid_entities = [e for e in result.entities if e.label != "SecurityEntity"]
    print(f"   -> Merged Total: {len(valid_entities)} entities.")

    print("\n🚀 [Step 2] Grounding with Neo4j...")
    
    normalized_entities = []
    
    for ent in valid_entities:
        norm_ent = normalize_entity(ent)
        normalized_entities.append(norm_ent)

    # 출력
    print("\n" + "="*80)
    print(f"{'TYPE':<15} | {'NAME':<35} | {'STATUS':<10} | {'SCORE'}")
    print("-" * 80)
    
    for ent in normalized_entities:
        status = "EXISTING" if ent.existing_id else "NEW"
        label_display = ent.db_label if ent.db_label else ent.label
        # 이름이 너무 길면 자름
        display_name = (ent.normalized_name[:32] + '..') if len(ent.normalized_name) > 32 else ent.normalized_name
        print(f"{label_display:<15} | {display_name:<35} | {status:<10} | {ent.match_score:.2f}")

    print("\n[Edges (Sample)]")
    count = 0
    for rel in result.relationships:
        if count > 20: 
            print("... (more edges hidden)")
            break
        print(f"  ({rel.source}) --[{rel.type}]--> ({rel.target})")
        count += 1

if __name__ == "__main__":
    run_interactive_test()