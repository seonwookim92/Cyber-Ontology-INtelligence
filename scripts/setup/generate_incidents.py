import json
import os
import sys
import random
import time
import re
from typing import List, Dict, Any
import argparse

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from src.core.config import settings
from src.core.graph_client import graph_client

# ==============================================================================
# [설정] 경로 정의
# ==============================================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
DATA_DIR = os.path.join(BASE_DIR, "data/generated")
SEED_DIR = os.path.join(BASE_DIR, "data/seed") 

OUTPUT_FILE = os.path.join(DATA_DIR, "incidents.json")
VICTIM_FILE = os.path.join(SEED_DIR, "victims.json")

# ==============================================================================
# 0. Helpers
# ==============================================================================
def load_victim_pool() -> List[Dict[str, str]]:
    """외부 JSON 파일에서 타겟 목록을 로드합니다."""
    if not os.path.exists(VICTIM_FILE):
        print(f"[!] Warning: Victim seed file not found at {VICTIM_FILE}")
        # 파일이 없을 경우를 대비한 최소한의 폴백 데이터
        return [{"org": "테스트기관", "sys": "테스트시스템", "ind": "Public"}]
        
    try:
        with open(VICTIM_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data
    except Exception as e:
        print(f"[!] Error loading victim file: {e}")
        return []

def extract_json_from_text(text: str):
    try:
        pattern = r"\[\s*\{.*\}\s*\]"
        match = re.search(pattern, text, re.DOTALL)
        if match: return json.loads(match.group(0))
        
        pattern_obj = r"\{.*\}"
        match_obj = re.search(pattern_obj, text, re.DOTALL)
        if match_obj: return [json.loads(match_obj.group(0))]

        return json.loads(text)
    except Exception as e:
        return None

# ==============================================================================
# 1. Neo4j에서 시나리오 재료(Ingredients) 수집
# ==============================================================================
def fetch_ingredients() -> Dict[str, str]:
    # print("    [*] Fetching graph ingredients...")
    queries = {
        "groups": "MATCH (n:ThreatGroup) RETURN n.name as val LIMIT 50",
        "malwares": "MATCH (n:Malware) RETURN n.name as val LIMIT 50",
        "vulnerabilities": "MATCH (n:Vulnerability) RETURN n.cve_id + ' (' + coalesce(n.product, '') + ')' as val ORDER BY n.date_added DESC LIMIT 50",
        "techniques": "MATCH (n:AttackTechnique) RETURN n.mitre_id + ' ' + n.name as val LIMIT 50",
        "indicators": "MATCH (n:Indicator) WHERE n.url IS NOT NULL RETURN n.url as val LIMIT 50"
    }
    
    ingredients = {}
    for key, q in queries.items():
        try:
            results = graph_client.query(q)
            all_vals = [r['val'] for r in results]
            if not all_vals:
                ingredients[key] = "None"
            else:
                sample_vals = random.sample(all_vals, min(len(all_vals), 10))
                ingredients[key] = ", ".join(sample_vals)
        except Exception:
            ingredients[key] = ""
    return ingredients

# ==============================================================================
# 2. LLM 시나리오 생성기
# ==============================================================================
def generate_scenarios(count: int = 1) -> List[Dict[str, Any]]:
    # 1. 재료 준비
    ingredients = fetch_ingredients()
    
    # 2. 타겟 로드 및 랜덤 선정 (파일에서 읽어옴)
    victim_pool = load_victim_pool()
    if not victim_pool:
        print("[!] No victim pool available.")
        return []
        
    target = random.choice(victim_pool)
    
    # 변수 주입
    ingredients['count'] = str(count)
    ingredients['target_org'] = target['org']
    ingredients['target_sys'] = target['sys']
    ingredients['target_ind'] = target['ind']
    
    # LLM 설정
    if settings.LLM_PROVIDER == "openai":
        llm = ChatOpenAI(model=settings.OPENAI_MODEL, api_key=settings.OPENAI_API_KEY, temperature=0.95)
    else:
        llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0.95, base_url=settings.OLLAMA_BASE_URL)

    system_prompt = """
    You are a Cyber Threat Intelligence Generator. 
    Your job is to create realistic cybersecurity incident scenarios in JSON format.
    
    [Rules]
    1. **Strict Target**: You MUST create an incident targeting the organization provided in the user prompt.
    2. **Realism**: Use the provided 'Ingredients' (Groups, Malware, CVEs) to build a logical attack chain.
    3. **Story**: The 'attack_flow' should be a sequence of 3-5 steps explaining how the breach happened.
    4. **Language**: Use Korean (한국어) for title, summary, and descriptions.
    5. **Date**: Random date between 2024 and 2026.
    """

    user_prompt = """
    Create {count} unique incident scenario targeting the following entity:
    
    [Target Victim]
    - Organization: {target_org}
    - System: {target_sys}
    - Industry: {target_ind}
    
    [Ingredients to Use]
    - Threat Groups: {groups}
    - Malware: {malwares}
    - Vulnerabilities: {vulnerabilities}
    - Techniques: {techniques}
    - Indicators: {indicators}
    
    [Output JSON Schema]
    [
      {{
        "id": "incident--uuid",
        "title": "Incident Title (Korean)",
        "timestamp": "ISO8601 Date distributed between 2023-2025",
        "victim": {{ 
            "organization": "{target_org}", 
            "system": "{target_sys}", 
            "industry": "{target_ind}", 
            "country": "South Korea" 
        }},
        "attribution": {{ "group_name": "Pick one from ingredients", "confidence": "High/Medium/Low" }},
        "summary": "Brief summary in Korean",
        "attack_flow": [
           {{
             "step": 1,
             "phase": "Initial Access/Execution/...",
             "technique": "Pick one from ingredients",
             "description": "What happened? (Korean)",
             "outcome": "Success/Blocked",
             "related_entity": {{ "type": "Malware/Vulnerability/Indicator", "value": "Value from ingredients" }}
           }}
        ]
      }}
    ]
    
    IMPORTANT: Return ONLY the raw JSON array.
    """

    print(f"[*] Generating scenario targeting: {target['org']} ({target['sys']})...")
    print("    [*] Invoking LLM...")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", user_prompt)
    ])
    
    chain = prompt | llm | StrOutputParser()
    
    try:
        response = chain.invoke(ingredients)
        data = extract_json_from_text(response)
        if not data:
            print("[!] JSON Extraction Failed. Retrying...")
            return []
        return data

    except Exception as e:
        print(f"[!] Generation Error: {e}")
        return []

# ==============================================================================
# 3. 파일 누적 저장
# ==============================================================================
def save_incidents(new_incidents: List[Dict[str, Any]]):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    existing_data = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = []

    existing_ids = {item['id'] for item in existing_data}
    
    added_count = 0
    for incident in new_incidents:
        if 'id' not in incident or not str(incident['id']).startswith('incident--'):
            incident['id'] = f"incident--gen-{random.randint(10000,99999)}"
            
        if incident['id'] not in existing_ids:
            existing_data.append(incident)
            added_count += 1
            
            print("\n" + "="*60)
            print(f"🚨 [New Incident] {incident.get('title')}")
            print(f"   🏢 Target: {incident['victim'].get('organization')} - {incident['victim'].get('system')}")
            print(f"   ☠️ Actor:  {incident['attribution'].get('group_name')}")
            print(f"   📝 Flow:   {len(incident.get('attack_flow', []))} Steps")
            print("="*60 + "\n")

    if added_count > 0:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, ensure_ascii=False, indent=2)
        print(f"[+] Saved {added_count} incidents. Total: {len(existing_data)}")

# ==============================================================================
# Main Loop
# ==============================================================================
if __name__ == "__main__":
    # 1. 인자 파서 설정
    parser = argparse.ArgumentParser(description="Generate synthetic cyber incidents using LLM.")
    parser.add_argument("--count", type=int, default=1, help="Number of incidents to generate")
    args = parser.parse_args()
    
    LIMIT = args.count

    print(f"🚀 Incident Generator Started")
    print(f"[*] Target Count: {LIMIT}")
    # VICTIM_FILE 변수가 상단에 정의되어 있다고 가정
    if 'VICTIM_FILE' in globals():
        print(f"[*] Reading victims from: {VICTIM_FILE}")
    
    try:
        for i in range(LIMIT):
            print(f"\n[+] Generating scenario {i+1}/{LIMIT}...")
            
            # 1개씩 생성
            scenarios = generate_scenarios(1)
            
            if scenarios:
                save_incidents(scenarios)
                print(f"   ✅ Saved scenario {i+1}.")
            
            # 마지막 생성이 아니면 API 호출 제한을 고려해 잠시 대기
            if i < LIMIT - 1:
                print("💤 Waiting 2s for rate limit...")
                time.sleep(2)

    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error occurred: {e}")
        sys.exit(1)

    print("\n🎉 Generation Complete.")