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

    # 1. Node(개체) 추출
    print("[*] Parsing Nodes (Techniques, Groups, Malware, etc.)...")
    
    # 우리가 관심을 가질 STIX 타입 -> Neo4j Label 매핑
    type_mapping = {
        'attack-pattern': 'AttackTechnique',
        'intrusion-set': 'ThreatGroup',
        'malware': 'Malware',
        'tool': 'Tool',
        'course-of-action': 'Mitigation',
        'x-mitre-tactic': 'AttackTactic'
    }

    for obj in objects:
        stix_type = obj.get('type')
        
        # 폐기된(revoked) 객체나 더 이상 안 쓰는(deprecated) 객체는 제외
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue

        if stix_type in type_mapping:
            label = type_mapping[stix_type]
            stix_id = obj.get('id')
            name = obj.get('name', 'Unknown')
            description = sanitize(obj.get('description', ''))
            mitre_id = get_mitre_id(obj)
            
            # Tactic의 경우 shortname(예: persistence)을 ID로 쓰기도 함
            if stix_type == 'x-mitre-tactic' and not mitre_id:
                mitre_id = obj.get('x_mitre_shortname', '')

            # CSV 행 데이터 준비
            nodes.append({
                'stix_id': stix_id,
                'label': label,
                'name': name,
                'mitre_id': mitre_id,
                'description': description[:1000] # 너무 길면 자름
            })
            valid_stix_ids.add(stix_id)

    # 2. Relationship(관계) 추출
    print("[*] Parsing Relationships...")
    for obj in objects:
        if obj.get('type') == 'relationship':
            source = obj.get('source_ref')
            target = obj.get('target_ref')
            rel_type = obj.get('relationship_type') # uses, mitigates, subtechnique-of
            
            # 소스와 타겟이 모두 우리가 추출한 유효한 노드일 때만 저장
            if source in valid_stix_ids and target in valid_stix_ids:
                # 관계 타입 정규화 (스네이크 케이스 -> 대문자)
                # 예: subtechnique-of -> SUBTECHNIQUE_OF
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