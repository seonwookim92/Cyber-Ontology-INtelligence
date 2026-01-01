from typing import List, Optional, Literal
from pydantic import BaseModel, Field

# ==============================================================================
# 1. Entity (IoC 및 아티팩트)
# ==============================================================================
class Entity(BaseModel):
    type: Literal[
        "IP", "Domain", "URL", "Hash", "Malware", "Vulnerability", 
        "Tool", "Person", "Organization", "Cryptocurrency", "Email"
    ]
    value: str = Field(..., description="The raw value extracted")
    
    # 내부 로직용 필드 (DB 저장 및 정규화 시 사용)
    normalized_value: Optional[str] = None
    existing_id: Optional[str] = None
    is_new: bool = True

# ==============================================================================
# 2. AttackStep (공격 단계)
# ==============================================================================
class AttackStep(BaseModel):
    step: int
    phase: str
    description: str
    related_entities: List[Entity] = []

# ==============================================================================
# 3. IntelligenceReport (리포트/사건) - [이전 수정사항 반영됨]
# ==============================================================================
class IntelligenceReport(BaseModel):
    title: str
    # 문서의 성격을 규정하는 카테고리
    category: Literal[
        "Incident",           # 실제 침해 사고
        "MalwareReport",      # 악성코드 분석
        "ThreatReport",       # 위협 그룹 보고서
        "VulnerabilityReport" # 취약점 분석
    ] = Field(..., description="Classify the document type.")
    
    summary: str
    timestamp: Optional[str] = None
    victim_org: Optional[str] = None
    attacker_group: Optional[str] = None
    attack_flow: List[AttackStep]
    
    class Config:
        use_enum_values = True

# ==============================================================================
# 4. EntityResolution (누락되었던 클래스 복구!)
# ==============================================================================
class EntityResolution(BaseModel):
    """
    LLM이 엔티티 정규화(Grounding)를 수행할 때 사용하는 응답 구조
    예: "Remcos" == "RemcosRAT" 판단용
    """
    is_match: bool
    matched_id: Optional[str] = None
    normalized_name: Optional[str] = None