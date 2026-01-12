import re
from typing import List, Optional, Set
from difflib import SequenceMatcher

from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from src.core.config import settings
from src.core.schemas import IntelligenceReport, Entity, EntityResolution, AttackStep
from src.core.graph_client import graph_client

class IntelligenceProcessor:
    def __init__(self):
        if settings.LLM_PROVIDER == "openai":
            self.llm = ChatOpenAI(model=settings.OPENAI_MODEL, api_key=settings.OPENAI_API_KEY, temperature=0)
        else:
            self.llm = ChatOllama(model=settings.OLLAMA_MODEL, temperature=0, base_url=settings.OLLAMA_BASE_URL)
        # [변경] IntelligenceReport로 변경
        self.extractor = self.llm.with_structured_output(IntelligenceReport)
        self.resolver = self.llm.with_structured_output(EntityResolution)
        
        # [변경] 프롬프트에 분류(Classification) 지침 추가
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """
            You are a CTI Analyst performing 'Exhaustive Entity Extraction'.
            
            [STEP 1: CLASSIFICATION]
            Determine the `category` of the text:
            - **Incident**: A specific breach event targeting a specific organization (e.g., "Bithumb Hacked").
            - **MalwareReport**: Technical analysis of a malware family (e.g., "Analysis of EtherRAT").
            - **ThreatReport**: Tracking a threat group's campaign (e.g., "Lazarus Group's new campaign").
            - **VulnerabilityReport**: Analysis of a specific CVE (e.g., "Deep dive into Log4Shell").

            [STEP 2: EXTRACTION]
            1. **EXTRACT EVERYTHING**: Extract all domains, hashes, IPs individually.
            2. **Mappings**: Assign entities to the most relevant Attack Step.
            3. **Context**: If it's a 'MalwareReport', the steps should describe the malware's execution flow.
            
            [EXCLUSION RULES]
            - Ignore placeholders like '{{ IP Address }}'.
            - Ignore generic terms like 'Malware', 'Unknown'.
            """),
            ("human", "{text}"),
        ])
        self.chain = self.prompt | self.extractor

    def process_report(self, text: str) -> IntelligenceReport:
        # 1. LLM 구조적 추출
        report: IntelligenceReport = self.chain.invoke({"text": text})
        
        # 2. Regex 보완 (기존 로직 동일)
        regex_iocs = self._extract_iocs_regex(text)
        self._inject_missing_iocs(report, regex_iocs)
        
        # 3. 후처리 (Validation -> Cleaning -> Grounding) (기존 로직 동일)
        for step in report.attack_flow:
            valid_entities = []
            for entity in step.related_entities:
                if not self._is_valid_entity(entity): continue
                split_entities = self._clean_and_split(entity)
                for sub_ent in split_entities:
                    if not self._is_valid_entity(sub_ent): continue
                    grounded_ent = self._ground_entity(sub_ent)
                    valid_entities.append(grounded_ent)
            step.related_entities = valid_entities
            
        return report

    # --------------------------------------------------------------------------
    # [Logic] Regex Extraction (기존 패턴 + 신규 패턴)
    # --------------------------------------------------------------------------
    def _extract_iocs_regex(self, text: str) -> List[Entity]:
        iocs = []
        
        # 1. IPv4 (기존 패턴 유지)
        # 1.1.1.1 또는 1.1.1[.]1 형태 매칭
        for m in re.findall(r'\b(?:\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3}(?:\[?\.\]?|\(\.\))\d{1,3})\b', text):
            # 연도(2025)나 버전(1.2.3.4) 등 오탐 가능성 높은 것 제외
            if not re.search(r'^\d{4}', m) and self._is_valid_ip(m): 
                iocs.append(Entity(type="IP", value=m))

        # 2. URL/Domain (기존 패턴 + hxxp 지원)
        for m in re.findall(r'(?:hxxp|http|https)(?:\[?:\s*\]?|:)(?:/{2}|\\{2})(?:[a-zA-Z0-9\-\.]+(?:\[?\.\]?)[a-zA-Z]{2,})(?:[^\s]*)', text, re.IGNORECASE):
            iocs.append(Entity(type="URL", value=m))
            
        # 3. 일반 도메인 (기존 패턴 - 필터링 강화)
        for m in re.findall(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|kr|ru|cn|eu|co|biz|info)\b', text, re.IGNORECASE):
            # 주요 벤더 도메인 제외 (오탐 방지)
            if any(x in m.lower() for x in ["ahnlab", "microsoft", "google", "facebook", "twitter", "github"]): 
                continue
            iocs.append(Entity(type="Domain", value=m))

        # 4. CVE (기존 패턴)
        for m in re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE):
            iocs.append(Entity(type="Vulnerability", value=m))
            
        # 5. [신규] Hashes (MD5, SHA1, SHA256) - 중요!
        hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text)
        for h in hashes:
            # 숫자로만 구성된 경우 오탐 가능성 높음 (예: 타임스탬프) -> 제외
            if not h.isdigit(): 
                iocs.append(Entity(type="Hash", value=h))

        # 6. [신규] Cryptocurrency Wallet (Ethereum/Bitcoin 등)
        # Ethereum (0x...)
        eth_wallets = re.findall(r'\b0x[a-fA-F0-9]{40}\b', text)
        for w in eth_wallets:
            iocs.append(Entity(type="Cryptocurrency", value=w))
            
        return iocs

    # --------------------------------------------------------------------------
    # [Logic] Validation & Cleaning (노이즈 제거 핵심)
    # --------------------------------------------------------------------------
    def _is_valid_entity(self, entity: Entity) -> bool:
        """{ IP Address } 같은 플레이스홀더나 쓰레기 값 필터링"""
        val = entity.value.strip()
        
        # 1. 길이 및 빈 값 체크
        if not val or len(val) < 3:
            return False
            
        # 2. 플레이스홀더 패턴 ({...}, <...>)
        if (val.startswith("{") and val.endswith("}")) or \
           (val.startswith("<") and val.endswith(">")) or \
           "IP Address" in val or "Target" in val:
            return False
            
        # 3. 블랙리스트 키워드
        blacklist = ["unknown", "none", "n/a", "example.com", "localhost", "127.0.0.1"]
        if val.lower() in blacklist:
            return False
            
        return True

    def _is_valid_ip(self, ip_str: str) -> bool:
        """IP 형식이 맞는지 간단 검증 (숫자 포함 여부 등)"""
        # 최소한 하나의 숫자는 있어야 함
        if not any(char.isdigit() for char in ip_str):
            return False
        return True

    def _clean_string(self, text: str) -> str:
        """[.] -> . 변환 등 De-fanging 복구"""
        return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("hxxp", "http")

    def _clean_and_split(self, entity: Entity) -> List[Entity]:
        """IP:Port 분리 및 De-fanging"""
        clean_val = self._clean_string(entity.value)
        
        # IP 타입인데 포트가 붙어있는 경우 (예: 1.1.1.1:8080)
        if entity.type == "IP" and ":" in clean_val:
            # 정규식으로 IP와 Port 분리 시도
            match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):([\d,]+)$", clean_val)
            if match:
                ip_val = match.group(1)
                # 원본 객체를 복사해서 IP로 수정
                ip_ent = entity.model_copy()
                ip_ent.value = ip_val
                return [ip_ent]
                # Port 정보는 필요하다면 별도 Entity로 추가 가능하지만 여기선 생략
        
        # 값 업데이트 후 반환
        entity.value = clean_val
        return [entity]

    def _inject_missing_iocs(self, report: IntelligenceReport, regex_iocs: List[Entity]):
        """LLM이 놓친 Regex IoC를 마지막 단계에 추가"""
        # 이미 존재하는 값들 수집 (정규화된 형태로 비교)
        existing_values = set()
        for step in report.attack_flow:
            for ent in step.related_entities:
                existing_values.add(self._clean_string(ent.value))
        
        missing_entities = []
        for ri in regex_iocs:
            clean_val = self._clean_string(ri.value)
            # 중복 체크
            if clean_val not in existing_values:
                missing_entities.append(ri)
                existing_values.add(clean_val)
        
        if missing_entities:
            # 'Observed Indicators' 단계 생성하여 추가
            new_step = AttackStep(
                step=len(report.attack_flow) + 1,
                phase="Observed Indicators",
                description="Technical indicators (IoCs) extracted via automated pattern matching.",
                related_entities=missing_entities
            )
            report.attack_flow.append(new_step)

    # --------------------------------------------------------------------------
    # [Logic] Grounding (DB 비교)
    # --------------------------------------------------------------------------
    def _ground_entity(self, entity: Entity) -> Entity:
        """DB 검색 및 유사도 기반 정규화"""
        
        # 기본값 설정
        entity.normalized_value = entity.value
        entity.is_new = True
        
        # DB 검색
        try:
            query = """
            MATCH (n)
            WHERE toLower(n.name) CONTAINS toLower($val) 
            RETURN n.name as name, elementId(n) as id, labels(n) as labels
            LIMIT 3
            """
            results = graph_client.query(query, {"val": entity.value})
        except Exception:
            results = []

        if not results:
            return entity 

        # 매칭 후보 평가
        candidates = []
        for r in results:
            score = SequenceMatcher(None, entity.value.lower(), r['name'].lower()).ratio()
            candidates.append({"name": r['name'], "id": r['id'], "score": score, "labels": r['labels']})

        best = max(candidates, key=lambda x: x['score']) if candidates else None
        
        # 1. 확실한 매칭 (0.9 이상)
        if best and best['score'] > 0.9:
            entity.normalized_value = best['name']
            entity.existing_id = best['id']
            entity.is_new = False
            
        # 2. 애매한 매칭 (0.6 ~ 0.9) -> LLM에게 확인
        elif best and best['score'] > 0.6:
            # LLM Resolution 호출
            try:
                cand_str = "\n".join([f"- {c['name']} (ID: {c['id']})" for c in candidates])
                prompt = f"Is '{entity.value}' ({entity.type}) essentially the same as any of these?\n{cand_str}"
                res = self.resolver.invoke(prompt)
                
                if res and res.is_match:
                    entity.normalized_value = res.normalized_name
                    entity.existing_id = res.matched_id
                    entity.is_new = False
            except Exception:
                pass # LLM 에러 시 무시하고 새로운 노드로 취급

        return entity

# 인스턴스 생성
processor = IntelligenceProcessor()