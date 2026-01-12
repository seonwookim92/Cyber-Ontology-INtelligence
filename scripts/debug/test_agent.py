import sys
import os

# src 모듈 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.services.agent import build_agent_graph

def test_agent():
    print("Initializing Neo4j Agent...")
    try:
        agent = build_agent_graph()
    except Exception as e:
        print(f"[Fatal Error] Agent Init Failed: {e}")
        return

    # 테스트 시나리오
    questions = [
        # 1. 스키마 확인
        "이 데이터베이스의 스키마 정보를 알려줘. 어떤 노드랑 관계가 있어?",
        
        # 2. 복합 추론 (KEV + MITRE 연결 확인)
        "MongoDB와 관련된 취약점(CVE)이 있는지 찾아보고, 만약 있다면 그 취약점이 어떤 공격 기술(Technique)과 연관되어 있는지 설명해줘.",
        
        # 3. 악성코드 및 URL 조회 (URLHaus + Fuzzy Match)
        "Mozi 봇넷과 관련된 URL 정보가 있어? 그리고 Mozi는 어떤 위협 그룹이랑 연관될 가능성이 있어?"
    ]
    
    for i, q in enumerate(questions, 1):
        print(f"\n\n[{i}] >>> User: {q}")
        print("-" * 60)
        
        try:
            # LangGraph 실행
            response = agent.invoke({"messages": [("human", q)]})
            
            # 답변 출력
            last_message = response["messages"][-1]
            print(f">>> Agent: {last_message.content}")
            
        except Exception as e:
            print(f"[Error] Question Failed: {e}")

if __name__ == "__main__":
    test_agent()