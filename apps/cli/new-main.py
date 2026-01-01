#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import textwrap

# 경로 설정
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import clear

# 기존 모듈 Imports
from src.core.config import settings
from src.services import analysis
from src.services import correlation

# [NEW] 에이전트 모듈 및 LangChain 메시지 Imports
from src.services import agent
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

# -------------------------
# UI Helpers (기존 유지)
# -------------------------
def banner() -> str:
    return textwrap.dedent(f"""
        ============================================================
         🛡️ Cyber Ontology Intelligence CLI (v9.5 - Reasoning)
         - Target Graph: {settings.CYBER_DATA_GRAPH}
         - LLM Provider: {settings.LLM_PROVIDER.upper()}
        ============================================================
    """).strip()

def print_section(title: str):
    print(f"\n{'-'*60}\n 🔍 {title}\n{'-'*60}")

def print_evidence(facts: list):
    print_section("Evidence Trace (Ontology Facts)")
    for idx, fact in enumerate(facts):
        print(f" {idx+1}. {fact}")
    print(f"{'-'*60}\n")

def print_ai_analysis(text: str):
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
# [MODULE 3] AI Agent Chat UI (New!)
# ==============================================================================

def run_agent_ui():
    """
    Reasoning Agent와 대화하는 대화형 UI
    """
    print("\n🚀 스마트 에이전트 모드를 시작합니다. (초기화 중...)")
    
    try:
        # 1. 그래프 빌드
        graph = agent.build_agent_graph()
        
        # 2. 대화 기록 초기화
        chat_history = []
        
        clear()
        print(banner())
        print("\n💬 [AI Agent Chat Mode]")
        print("질문을 입력하면 에이전트가 스스로 판단(Reasoning)하고 DB를 조회합니다.")
        print("예: '최근 사건 목록 보여줘', 'IP 1.2.3.4 찾아줘'")
        print("(종료하려면 'q' 또는 'exit' 입력)\n")

        while True:
            user_input = prompt("\nUser > ").strip()
            if user_input.lower() in ["q", "quit", "exit"]:
                break
            if not user_input:
                continue

            print("\n--------------------------------------------------")
            print(" 🧠 Reasoning Trace (생각의 흐름)")
            print("--------------------------------------------------")
            
            # 메시지 구성: [SystemPrompt] + History + [UserQuery]
            messages = [SystemMessage(content=agent.AGENT_SYSTEM_PROMPT)] + chat_history + [HumanMessage(content=user_input)]
            
            final_answer = ""
            
            try:
                # 스트리밍 실행 (단계별 출력)
                for event in graph.stream({"messages": messages}, stream_mode="values"):
                    current_messages = event["messages"]
                    if not current_messages: continue
                    
                    last_msg = current_messages[-1]
                    
                    # AI의 생각 / 도구 호출
                    if isinstance(last_msg, AIMessage):
                        if last_msg.tool_calls:
                            for tc in last_msg.tool_calls:
                                print(f"\n  🤔 [Thought] 도구 사용 결정")
                                print(f"  🔨 [Action] {tc['name']} (Input: {tc['args']})")
                        elif last_msg.content:
                            final_answer = last_msg.content
                    
                    # 도구 실행 결과
                    elif isinstance(last_msg, ToolMessage):
                        print(f"  🔍 [Observation] 결과 수신 완료 ({len(last_msg.content)} chars)")
                        # 너무 길면 자르기
                        preview = last_msg.content.replace('\n', ' ')
                        if len(preview) > 100: preview = preview[:100] + "..."
                        print(f"     >> {preview}")

                # 최종 답변 출력
                print("\n--------------------------------------------------")
                print(f"🤖 [Final Answer]\n{final_answer}")
                print("--------------------------------------------------")
                
                # 히스토리 업데이트
                chat_history.append(HumanMessage(content=user_input))
                chat_history.append(AIMessage(content=final_answer))

            except Exception as e:
                print(f"❌ 대화 중 오류 발생: {e}")
                
    except Exception as e:
        print(f"❌ 에이전트 초기화 실패: {e}")
        prompt("엔터를 누르면 메뉴로 돌아갑니다...")

# ==============================================================================
# Main Loop (Updated)
# ==============================================================================

def main():
    while True:
        clear()
        print(banner())
        print("\n[메인 메뉴]")
        print("1. 심층 분석 (Deep Analysis) - Entity 상세 조회")
        print("2. 연관 분석 (Correlation)   - 다층 연결고리 추적")
        print("3. 스마트 에이전트 (AI Chat) - 자율 추론 및 질의응답 [NEW]")
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
                elif sub == '1': select_and_analyze("Incident")  # 기존 함수
                elif sub == '2': select_and_analyze("Malware")   # 기존 함수
                elif sub == '3': select_and_analyze("Vulnerability") # 기존 함수
                
        elif choice == '2':
            run_correlation_ui() # 기존 함수

        elif choice == '3':
            run_agent_ui() # [NEW]

if __name__ == "__main__":
    main()