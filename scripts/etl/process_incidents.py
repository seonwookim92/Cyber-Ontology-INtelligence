import json
import os
import sys
from typing import Dict, Any

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from src.core.graph_client import graph_client

# 경로 설정
GENERATED_FILE = os.path.join(os.path.dirname(__file__), "../../data/generated/incidents.json")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "../../data/processed")
PROCESSED_FILE = os.path.join(PROCESSED_DIR, "incidents_imported.json")

def load_generated_data():
    if not os.path.exists(GENERATED_FILE):
        print(f"[!] Generated file not found: {GENERATED_FILE}")
        return []
    with open(GENERATED_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def ingest_incident(incident: Dict[str, Any]):
    print(f"[*] Processing Incident: {incident.get('title')}")
    
    # 1. Incident 및 Victim(Identity) 노드 생성
    #    Identity는 피해 기관을 의미함
    q_core = """
    MERGE (i:Incident {id: $id})
    SET i.title = $title,
        i.summary = $summary,
        i.timestamp = $timestamp,
        i.created_at = datetime()

    MERGE (v:Identity {name: $victim_org})
    SET v.industry = $victim_ind,
        v.system = $victim_sys,
        v.country = $victim_country

    MERGE (i)-[:TARGETS]->(v)
    """
    
    params_core = {
        "id": incident["id"],
        "title": incident["title"],
        "summary": incident.get("summary", ""),
        "timestamp": incident.get("timestamp", ""),
        "victim_org": incident["victim"]["organization"],
        "victim_sys": incident["victim"].get("system", ""),
        "victim_ind": incident["victim"].get("industry", ""),
        "victim_country": incident["victim"].get("country", "Unknown")
    }
    graph_client.query(q_core, params_core)

    # 2. Attribution (Threat Group 연결)
    #    LLM이 만든 그룹명이 DB에 정확히 없을 수도 있으므로 CONTAINS로 느슨하게 연결하거나
    #    정확도를 위해 정확히 일치하는 경우만 연결
    group_name = incident["attribution"].get("group_name")
    if group_name and group_name != "None":
        q_group = """
        MATCH (g:ThreatGroup)
        WHERE toLower(g.name) = toLower($group_name)
        MATCH (i:Incident {id: $id})
        MERGE (i)-[:ATTRIBUTED_TO]->(g)
        """
        graph_client.query(q_group, {"group_name": group_name, "id": incident["id"]})

    # 3. Attack Flow (Step별 노드 생성 및 연결)
    steps = incident.get("attack_flow", [])
    # 순서 보장을 위해 step 번호로 정렬
    steps.sort(key=lambda x: x.get("step", 0))
    
    previous_step_id = None
    
    for idx, step in enumerate(steps):
        step_id = f"{incident['id']}-step-{step['step']}"
        
        # Step 노드 생성
        q_step = """
        MATCH (i:Incident {id: $inc_id})
        MERGE (s:AttackStep {id: $step_id})
        SET s.phase = $phase,
            s.description = $desc,
            s.technique_name = $tech_name,
            s.outcome = $outcome,
            s.order = $order
        
        // Incident와 첫 번째 Step 연결
        WITH i, s
        CALL apoc.do.when(
            $is_first,
            'MERGE (i)-[:STARTS_WITH]->(s)',
            '',
            {i:i, s:s}
        ) YIELD value
        RETURN s
        """
        
        # APOC가 없으면 위 쿼리가 실패할 수 있음. APOC 없는 버전으로 분기 처리 필요하지만
        # 여기서는 간단히 Python 로직으로 처리.
        
        # (1) Step Node 생성
        q_create_step = """
        MERGE (s:AttackStep {id: $step_id})
        SET s.phase = $phase,
            s.description = $desc,
            s.technique_name = $tech_name,
            s.outcome = $outcome,
            s.order = $order
        """
        graph_client.query(q_create_step, {
            "step_id": step_id,
            "phase": step.get("phase", "Unknown"),
            "desc": step.get("description", ""),
            "tech_name": step.get("technique", ""),
            "outcome": step.get("outcome", ""),
            "order": step.get("step")
        })

        # (2) Incident -> First Step 연결
        if idx == 0:
            q_link_start = """
            MATCH (i:Incident {id: $inc_id}), (s:AttackStep {id: $step_id})
            MERGE (i)-[:STARTS_WITH]->(s)
            """
            graph_client.query(q_link_start, {"inc_id": incident["id"], "step_id": step_id})
        
        # (3) Previous Step -> Current Step 연결
        if previous_step_id:
            q_link_next = """
            MATCH (prev:AttackStep {id: $prev_id}), (curr:AttackStep {id: $curr_id})
            MERGE (prev)-[:NEXT]->(curr)
            """
            graph_client.query(q_link_next, {"prev_id": previous_step_id, "curr_id": step_id})
            
        previous_step_id = step_id

        # (4) Artifact Linking (Step -> Malware/Vuln/Indicator)
        related = step.get("related_entity")
        if related and isinstance(related, dict):
            r_type = related.get("type")
            r_val = related.get("value")
            
            if not r_val or r_val == "None": continue

            if r_type == "Malware":
                q_link_mal = """
                MATCH (s:AttackStep {id: $step_id})
                MERGE (m:Malware {name: $val})
                MERGE (s)-[:USES_MALWARE]->(m)
                """
                graph_client.query(q_link_mal, {"step_id": step_id, "val": r_val})

            elif r_type == "Vulnerability":
                # CVE-XXXX-XXXX 포맷만 추출
                cve_clean = r_val.split(' ')[0]
                q_link_vuln = """
                MATCH (s:AttackStep {id: $step_id})
                MERGE (v:Vulnerability {cve_id: $val})
                MERGE (s)-[:EXPLOITS]->(v)
                """
                graph_client.query(q_link_vuln, {"step_id": step_id, "val": cve_clean})
            
            elif r_type == "Indicator":
                # Indicator는 DB에 없을 수도 있으니 MERGE로 생성
                q_link_ind = """
                MATCH (s:AttackStep {id: $step_id})
                MERGE (i:Indicator {url: $val})
                ON CREATE SET i.type = 'URL', i.source = 'Generated Scenario'
                MERGE (s)-[:HAS_INDICATOR]->(i)
                """
                graph_client.query(q_link_ind, {"step_id": step_id, "val": r_val})

def run_etl():
    if not os.path.exists(PROCESSED_DIR):
        os.makedirs(PROCESSED_DIR)

    # 1. 데이터 로드
    raw_data = load_generated_data()
    if not raw_data:
        print("[!] No generated incidents found.")
        return

    # 2. 이미 처리된 ID 로드 (중복 처리 방지)
    processed_ids = set()
    if os.path.exists(PROCESSED_FILE):
        with open(PROCESSED_FILE, 'r', encoding='utf-8') as f:
            processed_data = json.load(f)
            processed_ids = {item['id'] for item in processed_data}

    # 3. ETL 실행
    new_processed = []
    for incident in raw_data:
        if incident['id'] in processed_ids:
            continue
            
        try:
            ingest_incident(incident)
            new_processed.append(incident)
        except Exception as e:
            print(f"[!] Failed to ingest incident {incident['id']}: {e}")

    # 4. 처리 결과 저장
    if new_processed:
        # 기존 처리 파일에 추가
        final_processed_list = []
        if os.path.exists(PROCESSED_FILE):
            with open(PROCESSED_FILE, 'r', encoding='utf-8') as f:
                final_processed_list = json.load(f)
        
        final_processed_list.extend(new_processed)
        
        with open(PROCESSED_FILE, 'w', encoding='utf-8') as f:
            json.dump(final_processed_list, f, ensure_ascii=False, indent=2)
            
        print(f"\n[+] Successfully ingested {len(new_processed)} new incidents into Neo4j.")
    else:
        print("\n[*] All incidents are already up to date in Neo4j.")

if __name__ == "__main__":
    run_etl()