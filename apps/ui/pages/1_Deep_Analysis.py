import streamlit as st
import sys
import os

# src 모듈 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import analysis

st.set_page_config(page_title="Deep Analysis", page_icon="🔍", layout="wide")

st.title("🔍 Entity Deep Analysis")
st.markdown("사건(Incident), 위협 그룹(Threat Group), 악성코드, 취약점의 상세 정보를 조회하고 AI 분석을 수행합니다.")

# 1. 대상 선택
col1, col2 = st.columns([1, 3])
with col1:
    # [수정] Threat Group 추가
    entity_type = st.selectbox(
        "분석 대상 유형", 
        ["Incident", "Threat Group", "Malware", "Vulnerability"]
    )

# 2. 목록 로드 (Service 호출)
with st.spinner(f"{entity_type} 목록을 불러오는 중..."):
    rows = analysis.get_entity_list(entity_type, limit=50)

if not rows:
    st.error("데이터가 없습니다.")
    if entity_type == "Incident":
        st.caption("Tip: 'generate_incidents.py'를 실행하여 사건 데이터를 생성하세요.")
else:
    # Selectbox용 라벨 만들기
    # rows의 label은 보기 좋은 텍스트, uri는 실제 ID
    options = {r['label']: r for r in rows}
    
    with col2:
        selected_label = st.selectbox("분석할 항목 선택", list(options.keys()))
        target = options[selected_label]

    # 3. 분석 실행 버튼
    if st.button("🚀 상세 분석 실행", type="primary"):
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
                    st.write(f"Found {len(facts)} facts from Graph DB.")
                    with st.expander("추론 근거 (Evidence Trace) 보기", expanded=True):
                        for f in facts:
                            # 텍스트가 너무 길면 보기 싫으니 적당히 포맷팅
                            if f.startswith("---") or f.startswith("[Step"):
                                st.markdown(f"**{f}**")
                            else:
                                st.write(f"- {f}")
                            
            except Exception as e:
                st.error(f"분석 중 오류 발생: {e}")