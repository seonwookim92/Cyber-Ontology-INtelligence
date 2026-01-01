# debug_llm.py
# LLM 설정 및 연결 상태를 진단하는 유틸리티 스크립트
# 사용법: 터미널에서 `python src/utils/debug_llm.py` 실행


import sys
import os
import requests

# ------------------------------------------------------------------
# [경로 설정] 현재 위치(src/core/utils)에서 루트(../../..)를 찾아 Path에 추가
# ------------------------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../"))

if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.core.config import settings
    from src.core.llm import chat
except ImportError as e:
    print(f"❌ 모듈 로드 실패: {e}")
    print(f"   현재 인식된 프로젝트 루트: {project_root}")
    print("   프로젝트 구조가 올바른지 확인해주세요.")
    sys.exit(1)


def run_diagnostics():
    print(f"🔍 [LLM 진단 시작]")
    print(f"--------------------------------------------------")
    print(f"1. 설정 확인")
    print(f"   - Provider: {settings.LLM_PROVIDER}")
    
    if settings.LLM_PROVIDER == "ollama":
        print(f"   - Base URL: {settings.OLLAMA_BASE_URL}")
        print(f"   - Model:    {settings.OLLAMA_MODEL}")
        
        # 2. Ollama 서버 연결 테스트
        print(f"\n2. Ollama 서버 연결 테스트 ({settings.OLLAMA_BASE_URL})")
        try:
            r = requests.get(settings.OLLAMA_BASE_URL, timeout=5)
            if r.status_code == 200:
                print(f"   ✅ 서버 연결 성공! (Ollama is running)")
            else:
                print(f"   ❌ 서버 응답 이상: {r.status_code}")
        except Exception as e:
            print(f"   ❌ 서버 연결 실패: {e}")
            print(f"   👉 'ollama serve'가 실행 중인지 확인하세요.")
            return

        # 3. 모델 존재 여부 확인
        print(f"\n3. 모델 확인 ('{settings.OLLAMA_MODEL}')")
        try:
            r = requests.get(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags", timeout=5)
            models = [m['name'] for m in r.json().get('models', [])]
            
            # 태그 매칭 (latest 태그 처리 포함)
            if any(settings.OLLAMA_MODEL in m for m in models):
                print(f"   ✅ 모델 발견됨: {settings.OLLAMA_MODEL}")
            else:
                print(f"   ❌ 모델을 찾을 수 없음!")
                print(f"   👉 현재 설치된 모델: {models}")
                print(f"   👉 해결책: 터미널에 'ollama pull {settings.OLLAMA_MODEL}' 입력")
                return
        except Exception as e:
            print(f"   ⚠️ 모델 목록 조회 실패: {e}")

    elif settings.LLM_PROVIDER == "openai":
        print(f"   - Model: {settings.OPENAI_MODEL}")
        if not settings.OPENAI_API_KEY:
            print("   ❌ OPENAI_API_KEY가 없습니다!")
            return
        print("   ✅ API Key 설정됨")

    # 4. 실제 생성 테스트
    print(f"\n4. 실제 생성 테스트 (Hello World)")
    messages = [{"role": "user", "content": "Say 'Connection Successful' in Korean."}]
    
    try:
        print("   ⏳ 요청 전송 중...")
        response = chat(messages)
        if response:
            print(f"   ✅ 응답 수신 성공:")
            print(f"   >> {response}")
        else:
            print(f"   ❌ 응답이 비어있습니다. (src/core/llm.py 내부 오류 로그 확인 필요)")
    except Exception as e:
        print(f"   ❌ 생성 중 치명적 오류: {e}")

if __name__ == "__main__":
    run_diagnostics()