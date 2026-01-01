import requests
import json
from typing import List, Dict
from src.core.config import settings

def chat(messages: List[Dict[str, str]], timeout: int = 120) -> str:
    """
    설정된 Provider(Ollama 또는 OpenAI)에 따라 적절한 API를 호출하여 응답을 반환합니다.
    모든 비즈니스 로직은 이 함수 하나만 바라보면 됩니다.
    """
    provider = settings.LLM_PROVIDER

    if provider == "openai":
        return _chat_openai(messages, timeout)
    elif provider == "ollama":
        return _chat_ollama(messages, timeout)
    else:
        return f"[System Error] 지원하지 않는 LLM Provider입니다: {provider}"

def _chat_ollama(messages: List[Dict], timeout: int) -> str:
    """Ollama API 호출 (Local)"""
    url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat"
    payload = {
        "model": settings.OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": settings.LLM_TEMPERATURE,
            "num_ctx": settings.OLLAMA_NUM_CTX
        }
    }
    
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"[Core/LLM] Ollama Error: {e}")
        return ""

def _chat_openai(messages: List[Dict], timeout: int) -> str:
    """OpenAI API 호출 (Public)"""
    if not settings.OPENAI_API_KEY:
        return "[System Error] .env 파일에 OPENAI_API_KEY가 설정되지 않았습니다."

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": settings.OPENAI_MODEL,
        "messages": messages,
        "temperature": settings.LLM_TEMPERATURE,
        # OpenAI는 num_ctx 대신 모델 자체 한계를 따르므로 생략하거나 max_tokens 사용
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f"[Core/LLM] OpenAI Error: {e}")
        # API 키 오류나 쿼터 초과 시 상세 내용 출력
        if hasattr(e, 'response') and e.response is not None:
             print(f"Details: {e.response.text}")
        return ""