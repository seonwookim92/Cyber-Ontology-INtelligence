import json
import csv
import os
import sys
from typing import List, Dict, Any

# 경로 설정 (프로젝트 루트 기준)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
INPUT_FILE = os.path.join(PROJECT_ROOT, 'data', 'raw', 'mitre_enterprise_attack.json')
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'data', 'processed')

# Neo4j로 보낼 CSV 파일 경로
NODE_CSV = os.path.join(OUTPUT_DIR, 'mitre_nodes.csv')
REL_CSV = os.path.join(OUTPUT_DIR, 'mitre_rels.csv')

def load_json_data(filepath: str) -> List[Dict[str, Any]]:
    """JSON 파일을 로드합니다."""
    if not os.path.exists(filepath):
        print(f"[Error] Input file not found: {filepath}")
        print("Run 'bash scripts/setup/download_data.sh' first.")
        sys.exit(1)
        
    print(f"[*] Loading MITRE ATT&CK data from: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('objects', [])

def get_mitre_id(obj: Dict[str, Any]) -> str:
    """external_references에서 T1059 같은 MITRE ID를 추출합니다."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') in ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']:
            return ref.get('external_id')
    return ""

def sanitize(text: str) -> str:
    """CSV 깨짐 방지를 위해 줄바꿈 등을 처리합니다."""
    if not text: return ""
    return text.replace('\n', ' ').replace('\r', '').replace('"', "'")

def process_mitre_data():
    objects = load_json_data(INPUT_FILE)
    
    nodes = []
    rels = []
    valid_stix_ids = set()
    name_to_id = {} # name.lower() -> stix_id

    # 우리가 관심을 가질 STIX 타입 -> Neo4j Label 매핑
    type_mapping = {
        'attack-pattern': 'AttackTechnique',
        'intrusion-set': 'ThreatGroup',
        'malware': 'Malware',
        'tool': 'Tool',
        'course-of-action': 'Mitigation',
        'x-mitre-tactic': 'AttackTactic'
    }

    # 1. 1차 패스: 모든 "메인" 노드 추출 및 이름 맵핑 생성
    print("[*] Phase 1: Parsing Main Nodes...")
    for obj in objects:
        stix_type = obj.get('type')
        if obj.get('revoked') or obj.get('x_mitre_deprecated'): continue
        if stix_type in type_mapping:
            stix_id = obj.get('id')
            name = obj.get('name', 'Unknown')
            name_to_id[name.lower()] = stix_id
            
            label = type_mapping[stix_type]
            description = sanitize(obj.get('description', ''))
            mitre_id = get_mitre_id(obj)
            
            if stix_type == 'x-mitre-tactic' and not mitre_id:
                mitre_id = obj.get('x_mitre_shortname', '')

            nodes.append({
                'stix_id': stix_id,
                'label': label,
                'name': name,
                'mitre_id': mitre_id,
                'description': description[:1000]
            })
            valid_stix_ids.add(stix_id)

    # 2. 2차 패스: 별칭(Aliases) 처리
    print("[*] Phase 2: Processing Aliases...")
    import hashlib
    for obj in objects:
        stix_type = obj.get('type')
        if obj.get('revoked') or obj.get('x_mitre_deprecated'): continue
        
        # ThreatGroup 또는 Malware의 별칭 필드 확인
        aliases = obj.get('aliases', []) or obj.get('x_mitre_aliases', [])
        if not aliases: continue
        
        stix_id = obj.get('id')
        name = obj.get('name', 'Unknown')
        
        for alias in aliases:
            if alias.lower() == name.lower(): continue
            
            target_id = None
            # 이미 메인 노드 중에 동일한 이름이 있는지 확인
            if alias.lower() in name_to_id:
                target_id = name_to_id[alias.lower()]
            else:
                # 없으면 가상 노드 ID 생성 및 추가
                alias_stix_id = f"alias--{hashlib.md5(alias.encode()).hexdigest()}"
                target_id = alias_stix_id
                
                if alias_stix_id not in valid_stix_ids:
                    nodes.append({
                        'stix_id': alias_stix_id,
                        'label': type_mapping.get(stix_type, 'BaseNode'),
                        'name': alias,
                        'mitre_id': "Alias",
                        'description': f"Alias for '{name}'"
                    })
                    valid_stix_ids.add(alias_stix_id)
            
            # ALIASED_AS 관계 추가
            if stix_id in valid_stix_ids and target_id in valid_stix_ids:
                rels.append({
                    'source_id': stix_id,
                    'target_id': target_id,
                    'type': 'ALIASED_AS'
                })

    # 3. 3차 패스: Relationship(기존 관계) 추출
    print("[*] Phase 3: Parsing Relationships...")
    for obj in objects:
        if obj.get('type') == 'relationship':
            source = obj.get('source_ref')
            target = obj.get('target_ref')
            rel_type = obj.get('relationship_type')
            
            if source in valid_stix_ids and target in valid_stix_ids:
                normalized_type = rel_type.upper().replace('-', '_')
                rels.append({
                    'source_id': source,
                    'target_id': target,
                    'type': normalized_type
                })

    # 3. CSV 파일 저장
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Node CSV 저장
    print(f"[*] Saving {len(nodes)} nodes to {NODE_CSV}")
    with open(NODE_CSV, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['stix_id', 'label', 'name', 'mitre_id', 'description']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(nodes)

    # Relationship CSV 저장
    print(f"[*] Saving {len(rels)} relationships to {REL_CSV}")
    with open(REL_CSV, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['source_id', 'target_id', 'type']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rels)

    print("[+] MITRE ETL Completed Successfully.")

if __name__ == "__main__":
    process_mitre_data()