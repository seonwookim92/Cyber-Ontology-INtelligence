# src/core/config.py

import os
from dotenv import load_dotenv

# .env 파일 로드 (프로젝트 루트에 있는 .env를 찾습니다)
load_dotenv()

class Settings:
    """
    프로젝트 전체에서 공유하는 설정 관리 클래스
    모든 환경 변수는 여기서 로드하고 타입 변환을 수행합니다.
    """
    
    # 프로젝트 기본 정보
    PROJECT_NAME = os.getenv("PROJECT_NAME", "Cyber Ontology Graph")

    # =========================================================
    # 1. Neo4j Settings (Replaces Fuseki)
    # =========================================================
    # Docker 컨테이너의 Bolt 포트 (기본값: 7687)
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    
    # 인증 정보 (.env 파일에서 로드)
    NEO4J_USERNAME = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password1234!")

    # (선택) 특정 DB를 사용할 경우 설정 (Community Edition은 'neo4j'만 사용 가능)
    NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

    # =========================================================
    # 2. LLM Settings (OpenAI & Local Support) - 유지
    # =========================================================
    
    # provider: 'ollama' 또는 'openai' 선택 가능
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()

    # [Ollama 설정]
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
    # Context Window Size (이전 대화에서 요청하신 설정)
    OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

    # [OpenAI 설정]
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

    # [공통 설정]
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.0"))

    # =========================================================
    # 3. Graph Agent Settings
    # =========================================================
    # Cypher 쿼리 생성 시 스키마 정보를 얼마나 자세히 줄지 제한 (토큰 절약용)
    SCHEMA_LOOKUP_LIMIT = 50 

# 싱글톤 인스턴스 생성
settings = Settings()