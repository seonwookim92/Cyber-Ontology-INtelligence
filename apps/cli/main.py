#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interactive Cyber Ontology CLI (v9.0 - Refactored Edition)
- src.core 및 src.services 모듈을 사용하여 로직과 UI를 완벽히 분리함
"""

import sys
import os
import textwrap

# [중요] 상위 폴더(루트)를 모듈 검색 경로에 추가해야 'src'를 찾을 수 있습니다.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import clear

# 우리가 만든 모듈들 Import
from src.core.config import settings
from src.services import analysis
from src.services import correlation

# -------------------------
# UI Helpers
# -------------------------
def banner() -> str:
    return textwrap.dedent(f"""
        ============================================================
         🛡️ Cyber Ontology Intelligence CLI (v9.0)
         - Target Graph: {settings.CYBER_DATA_GRAPH}
         - LLM Provider: {settings.LLM_PROVIDER.upper()}
        ============================================================
    """).strip()

def print_section(title: str):
    print(f"\n{'-'*60}\n 🔍 {title}\n{'-'*60}")

def print_evidence(facts: list):
    """서비스에서 받은 근거(Facts) 리스트 출력"""
    print_section("Evidence Trace (Ontology Facts)")
    for idx, fact in enumerate(facts):
        print(f" {idx+1}. {fact}")
    print(f"{'-'*60}\n")

def print_ai_analysis(text: str):
    """AI 분석 결과 출력"""
    print(" 🤖 [AI Analyst Report]")
    print(f"{'-'*60}")
    print(text)
    print(f"{'-'*60}\n")

# ==============================================================================
# [MODULE 1] Deep Analysis UI
# ==============================================================================

def select_and_analyze(entity_type: str):
    # 1. 목록 가져오기 (Service 호출)
    rows = analysis.get_entity_list(entity_type, limit=20)
    
    if not rows:
        print(f"[!] 데이터가 없습니다 ({entity_type}).")
        return

    print(f"\n📋 [최근 {entity_type} 목록]")
    for idx, row in enumerate(rows):
        label = row.get('label', 'No Label')
        sid = row.get('uri_short', 'N/A')
        # 추가 정보 표시 (날짜, 카운트 등)
        extra = row.get('date') or row.get('id') or f"Count:{row.get('cnt', 0)}"
        print(f"  {idx+1}. {label} (ID: {sid} | {extra})")

    choice = prompt(f"\n분석할 번호 선택 (1-{len(rows)}) > ").strip()
    
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(rows):
            target = rows[idx]
            print(f"\n🚀 '{target.get('label')}' 분석 중...")
            
            # 2. 상세 분석 요청 (Service 호출)
            ai_text, facts = "", []
            if entity_type == "Incident":
                ai_text, facts = analysis.analyze_incident(target['uri'], target['label'])
            elif entity_type == "Malware":
                ai_text, facts = analysis.analyze_malware(target['uri'], target['label'])
            elif entity_type == "Vulnerability":
                ai_text, facts = analysis.analyze_cve(target['uri'], target['label'])
            
            # 3. 결과 출력
            print_evidence(facts)
            print_ai_analysis(ai_text)
            prompt("\n엔터를 누르면 메뉴로 돌아갑니다...")

# ==============================================================================
# [MODULE 2] Correlation Analysis UI
# ==============================================================================

def run_correlation_ui():
    artifacts = []
    # Depth 설정
    depth_str = prompt("\n[설정] 분석 깊이를 선택하세요 (1:직접, 2:추론, 3:심층) [기본:1] > ").strip()
    depth = int(depth_str) if depth_str in ['1', '2', '3'] else 1
    
    while True:
        clear()
        print(banner())
        print(f"⚙️  Current Depth: {depth} (Fuzzy Search ON)")
        print(f"\n📦 수집된 단서: {len(artifacts)}개")
        for i, a in enumerate(artifacts): 
            print(f"   {i+1}. [{a['type']}] {a['value']}")
        
        print("\n[단서 추가]")
        print("1. Indicator (IP, URL 부분)  2. Malware Name  3. CVE ID")
        print("r. 분석 실행  c. 초기화  d. 깊이 변경  q. 뒤로가기")
        
        choice = prompt("\n선택 > ").strip().lower()
        if choice == 'q': return
        if choice == 'c': artifacts = []; continue
        if choice == 'd': 
            d = prompt("변경할 깊이 (1-3) > ").strip()
            if d in ['1','2','3']: depth = int(d)
            continue
            
        if choice == 'r': 
            if artifacts: 
                print("\n🚀 연관 관계 분석 및 AI 추론 중...")
                # 1. 연관 분석 요청 (Service 호출)
                results, ai_text = correlation.run_correlation_analysis(artifacts, depth)
                
                # 2. 결과 테이블 출력
                print_section(f"Correlation Results ({len(results)} matches)")
                if not results:
                    print(" [!] 매칭된 결과가 없습니다.")
                else:
                    for idx, r in enumerate(results):
                        print(f" {idx+1}. [{r['type']}] {r['label']}")
                        print(f"    - 관련성: {r['percent']}% (Score: {r['score']})")
                        print(f"    - 근거: {r['matches']}")
                        print("")
                
                # 3. AI 분석 출력
                if results:
                    print_ai_analysis(ai_text)
                    
                prompt("\n엔터를 누르면 계속합니다...")
            return
        
        # 힌트 및 입력 로직
        t_map = {'1': 'Indicator', '2': 'Malware', '3': 'Vulnerability'}
        if choice in t_map:
            target = t_map[choice]
            # 힌트 가져오기 (Service 호출)
            hints = correlation.get_smart_hints(target, artifacts)
            
            print(f"\n💡 [Smart Hints]")
            for h in hints: 
                print(f"   - {h.replace('[Rel] ', '')}")
            
            val = prompt(f"\n[{target}] 값 입력 (부분 검색 가능) > ").strip()
            if val: 
                artifacts.append({"type": target, "value": val.replace("[Rel] ", "")})

# ==============================================================================
# Main Loop
# ==============================================================================

def main():
    while True:
        clear()
        print(banner())
        print("\n[메인 메뉴]")
        print("1. 심층 분석 (Deep Analysis) - Entity 상세 조회")
        print("2. 연관 분석 (Correlation)   - 다층 연결고리 추적")
        print("q. 종료")
        
        choice = prompt("\n선택 > ").strip().lower()
        if choice == 'q': 
            print("Bye!")
            break
            
        elif choice == '1':
            while True:
                print("\n[조회 대상] 1.Incident 2.Malware 3.CVE b.뒤로")
                sub = prompt("> ").strip().lower()
                if sub == 'b': break
                elif sub == '1': select_and_analyze("Incident")
                elif sub == '2': select_and_analyze("Malware")
                elif sub == '3': select_and_analyze("Vulnerability")
                
        elif choice == '2':
            run_correlation_ui()

if __name__ == "__main__":
    main()