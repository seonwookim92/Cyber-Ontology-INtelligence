from neo4j import GraphDatabase
from src.core.schemas import IntelligenceReport
from src.core.config import settings

# 설정을 통해 접속 정보 로드
driver = GraphDatabase.driver(
    settings.NEO4J_URI,  # 예: "bolt://localhost:7687"
    auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD) # .env에 설정된 ID/PW
)

def save_incident_to_graph(report: IntelligenceReport):
    """
    IntelligenceReport 객체를 받아 Neo4j에 저장합니다.
    분류(Category)에 따라 Incident, MalwareReport 등의 라벨을 부여합니다.
    """
    
    # 1. 카테고리에 따른 동적 라벨 설정 (White-list 검증)
    allowed_labels = ["Incident", "MalwareReport", "ThreatReport", "VulnerabilityReport"]
    category_label = report.category if report.category in allowed_labels else "Report"
    
    # 2. 메인 구조 저장 쿼리 (Intelligence 공통 라벨 + 동적 카테고리 라벨)
    # 
    query_structure = f"""
    MERGE (i:Intelligence:{category_label} {{title: $title}})
    SET i.summary = $summary, 
        i.category = $category,
        i.timestamp = $timestamp,
        i.victim_org = $victim_org,
        i.attacker_group = $attacker_group,
        i.updated_at = datetime()
    
    WITH i
    UNWIND $steps AS step_data
    // Step 노드 생성 및 연결
    MERGE (s:AttackStep {{id: $title + "_" + toString(step_data.step)}})
    SET s.phase = step_data.phase, 
        s.description = step_data.description,
        s.step_num = step_data.step
    
    MERGE (i)-[:HAS_ATTACK_FLOW {{order: step_data.step}}]->(s)
    """

    # 3. 엔티티(IoC) 연결 쿼리
    query_entities = """
    WITH s, step_data
    UNWIND step_data.related_entities AS entity
    
    // 엔티티 생성 (정규화된 이름 우선 사용)
    MERGE (e:Entity {name: entity.normalized_value}) 
    ON CREATE SET e.original_value = entity.value, 
                  e.type = entity.type,
                  e.created_at = datetime()
    
    // 공격 단계와 엔티티 연결
    MERGE (s)-[:INVOLVES_ENTITY]->(e)
    """
    
    full_query = query_structure + query_entities
    
    # 4. 데이터 파라미터 준비
    params = report.model_dump()
    # attack_flow 필드를 쿼리의 $steps와 매핑
    params['steps'] = params.pop('attack_flow') 

    # 5. DB 실행
    try:
        with driver.session() as session:
            session.run(full_query, params)
    except Exception as e:
        print(f"[ERROR] Failed to save to Neo4j: {e}")
        raise e

def close_driver():
    driver.close()