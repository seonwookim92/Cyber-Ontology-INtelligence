import streamlit as st
import sys
import os

# src 모듈 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import analysis

st.set_page_config(page_title="Deep Analysis", page_icon="🔍", layout="wide")

st.title("🔍 Entity Deep Analysis")
st.markdown("사건(Incident), 위협 그룹(Threat Group), 악성코드, 취약점의 상세 정보를 조회하고 AI 분석을 수행합니다.")

# 1. 대상 유형 선택
col1, col2 = st.columns([1, 3])
with col1:
    entity_type = st.selectbox(
        "분석 대상 유형", 
        ["Incident", "Threat Group", "Malware", "Vulnerability"]
    )

# 2. 검색 및 선택 UI
if 'selected_item' not in st.session_state:
    st.session_state.selected_item = None

# [핵심] 태그 클릭 시 검색어를 주입하기 위한 프리-프로세싱
# 버튼 클릭 시 설정된 'pending_q'가 있다면 widget key에 우선 주입
pending_key = f"pending_q_{entity_type}"
widget_key = f"q_{entity_type}"

if pending_key in st.session_state:
    st.session_state[widget_key] = st.session_state[pending_key]
    del st.session_state[pending_key]

with col2:
    # 검색어 입력 (입력 시마다 하단 selectbox 옵션이 필터링됨)
    search_q = st.text_input(
        f"🔍 {entity_type} 검색 (Loose Search)", 
        placeholder="키워드를 입력하여 목록을 필터링하세요...", 
        key=widget_key
    )
    
    # 목록 로드 (검색어 반영)
    with st.spinner(f"{entity_type} 목록 검색 중..."):
        rows = analysis.get_entity_list(entity_type, limit=100, search_query=search_q)
        # 예시용 상위 8개 추출
        examples = analysis.get_entity_list(entity_type, limit=8)
    
    if not rows:
        st.warning(f"'{search_q}' 검색 결과가 없습니다.")
        st.session_state.selected_item = None
    else:
        options = {r['label']: r for r in rows}
        default_idx = 0
        selected_label = st.selectbox("분석할 항목 선택", list(options.keys()), index=default_idx)
        st.session_state.selected_item = options.get(selected_label)

# 2-1. 예시 태그 버튼들 (가로 배치)
if examples:
    st.markdown("##### 💡 Quick Select (Examples)")
    example_cols = st.columns(min(len(examples), 4))
    for i, ex in enumerate(examples):
        col_idx = i % 4
        if example_cols[col_idx].button(f"🏷️ {ex['label']}", key=f"btn_{entity_type}_{i}", use_container_width=True):
            # 직접 widget key를 수정하면 에러가 나므로, pending_key에 저장 후 리런
            st.session_state[pending_key] = ex['label']
            st.rerun()

target = st.session_state.selected_item

# 3. 분석 실행 버튼
if st.button("🚀 상세 분석 실행", type="primary"):
    if not target:
        st.error("분석할 대상을 먼저 검색하거나 선택해 주세요.")
    else:
        st.divider()
        
        # 분석 로직 실행 (Service 호출)
        ai_text = ""
        facts = []
        
        with st.spinner("AI Analyst가 그래프 데이터를 분석 중입니다..."):
            try:
                # [수정] 유형별 함수 분기 처리
                if entity_type == "Incident":
                    ai_text, facts = analysis.analyze_incident(target['uri'], target['label'])
                    
                elif entity_type == "Threat Group":
                    ai_text, facts = analysis.analyze_threat_group(target['uri'], target['label'])
                    
                elif entity_type == "Malware":
                    ai_text, facts = analysis.analyze_malware(target['uri'], target['label'])
                    
                elif entity_type == "Vulnerability":
                    ai_text, facts = analysis.analyze_cve(target['uri'], target['label'])
                
                # 4. 결과 출력
                c1, c2 = st.columns([1.2, 0.8])
                
                with c1:
                    st.subheader("🤖 AI Analyst Report")
                    st.info(ai_text)
                
                with c2:
                    st.subheader("🕸️ Knowledge Graph Evidence")
                    
                    # 별칭(Aliases) 강조 표시
                    aliases_info = [f for f in facts if f.startswith("Aliases:")]
                    if aliases_info:
                        st.warning(f"🔍 {aliases_info[0]}")
                    
                    st.write(f"Found {len(facts)} facts from Graph DB.")
                    with st.expander("추론 근거 (Evidence Trace) 보기", expanded=True):
                        for f in facts:
                            if f.startswith("Aliases:"): continue # 위에서 표시함
                            
                            # 텍스트가 너무 길면 보기 싫으니 적당히 포맷팅
                            if f.startswith("---") or f.startswith("[Step") or f.startswith("Threat Actor") or f.startswith("Malware"):
                                st.markdown(f"**{f}**")
                            else:
                                st.write(f"- {f}")
                            
            except Exception as e:
                st.error(f"분석 중 오류 발생: {e}")