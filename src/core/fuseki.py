import requests
from typing import List, Dict, Optional
from src.core.config import settings

def sparql_select(query_body: str, timeout: int = 30) -> List[Dict[str, str]]:
    """
    Fuseki에 SPARQL SELECT 쿼리를 실행하고, 결과를 사용하기 쉬운 리스트 형태로 반환합니다.
    
    Args:
        query_body (str): 'SELECT ...' 로 시작하는 쿼리 본문 (PREFIX 제외)
        timeout (int): 타임아웃 초 (기본 30초)
        
    Returns:
        List[Dict[str, str]]: 결과 행들의 리스트. 
                              각 행은 {'변수명': '값', '변수명_short': '짧은ID'} 형태의 딕셔너리.
    """
    # 1. Config에서 정의한 공통 Prefix와 쿼리 본문을 합칩니다.
    full_query = f"{settings.SPARQL_PREFIXES}\n{query_body}"
    
    try:
        # 2. Fuseki 서버로 요청 전송
        response = requests.get(
            settings.SPARQL_QUERY_URL,
            params={"query": full_query, "format": "application/sparql-results+json"},
            timeout=timeout
        )
        response.raise_for_status() # HTTP 에러(404, 500 등) 발생 시 예외 송출
        
        # 3. 결과 파싱 (Raw JSON -> List of Dicts)
        data = response.json()
        bindings = data.get("results", {}).get("bindings", [])
        
        rows = []
        for b in bindings:
            row = {}
            for k, v in b.items():
                val = v.get("value", "")
                row[k] = val
                
                # [편의 기능] URI인 경우, '#' 뒤의 ID만 잘라서 '_short' 키로 추가 제공
                # 예: row['entity'] = 'http://.../incident_01'
                #     row['entity_short'] = 'incident_01'
                if "#" in val:
                    row[f"{k}_short"] = val.split("#")[-1]
                else:
                    row[f"{k}_short"] = val
            rows.append(row)
            
        return rows

    except requests.exceptions.RequestException as e:
        print(f"[Core/Fuseki] Network Error: {e}")
        return []
    except Exception as e:
        print(f"[Core/Fuseki] Unexpected Error: {e}")
        return []

def sparql_update(update_body: str, timeout: int = 30) -> bool:
    """
    데이터 삽입/삭제를 위한 SPARQL UPDATE (INSERT/DELETE) 실행
    (추후 데이터 수정 기능이 필요할 때 사용)
    """
    full_query = f"{settings.SPARQL_PREFIXES}\n{update_body}"
    
    try:
        response = requests.post(
            settings.SPARQL_UPDATE_URL,
            data={"update": full_query},
            timeout=timeout
        )
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"[Core/Fuseki] Update Failed: {e}")
        return False