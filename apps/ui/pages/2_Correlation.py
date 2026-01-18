import streamlit as st
import sys
import os
import pandas as pd

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import correlation

st.set_page_config(page_title="Threat Correlation", page_icon="🔗", layout="wide")

st.title("🔗 Threat Correlation Analysis")
st.markdown("""
파편화된 위협 정보(IP, Hash, CVE, Name)들 간의 **숨겨진 연결고리**를 찾아내어, 
배후의 공격 그룹(Threat Group)이나 연관된 캠페인을 추적합니다.
""")

# ==============================================================================
# 0. UI 상태 관리 함수 (Callbacks)
# ==============================================================================
if "input_val_key" not in st.session_state:
    st.session_state.input_val_key = ""

def on_hint_change():
    """추천 값 선택 시 실행되는 콜백"""
    selected = st.session_state.get("hint_selectbox")
    if selected and selected != "(직접 입력)":
        clean_val = selected.replace("[Rel] ", "")
        st.session_state.input_val_key = clean_val

def add_artifact():
    """추가 버튼 클릭 시 실행되는 콜백 (여기서 값을 처리하고 비움)"""
    # 위젯 키를 통해 현재 상태 값 가져오기
    current_type = st.session_state.get("artifact_type_select")
    current_val = st.session_state.input_val_key
    
    if current_val and current_val.strip():
        # 중복 체크
        if any(x['value'] == current_val.strip() for x in st.session_state.artifacts):
            st.toast("⚠️ 이미 추가된 아티팩트입니다.")
        else:
            st.session_state.artifacts.append({"type": current_type, "value": current_val.strip()})
            # [핵심] 여기서 값을 비워야 에러가 안 납니다.
            st.session_state.input_val_key = ""
            st.toast("✅ 추가되었습니다.")
    else:
        st.toast("⚠️ 값을 입력하거나 선택해주세요.")

# ==============================================================================
# 1. 사이드바: 분석 설정 & 아티팩트 입력
# ==============================================================================
with st.sidebar:
    st.header("1️⃣ Input Artifacts")
    
    depth = st.slider("Analysis Depth", 1, 3, 2, 
                      help="1: 직접 연결, 2: 간접 연결(IOC/Vuln), 3: 심층 연결(TTP 공유)")
    include_incidents = st.checkbox("Include Incidents DB", value=True, help="Incident 기록을 포함하여 연관성을 찾습니다.")
    looseness = st.slider("Looseness (fuzziness)", 0, 100, 30, help="높을수록 느슨한(퍼지/부분) 매칭을 허용합니다.")
    
    st.divider()
    
    if "artifacts" not in st.session_state:
        st.session_state.artifacts = []

    st.subheader("➕ Add New Artifact")
    
    # 1. 유형 선택 (키 추가됨)
    a_type = st.selectbox(
        "Artifact Type", 
        ["Malware", "Vulnerability", "Indicator", "Threat Group"],
        key="artifact_type_select" 
    )
    
    # 2. 추천 값 조회
    try:
        hints = correlation.get_smart_hints(a_type, st.session_state.artifacts, limit=15)
    except:
        hints = []
        
    options = ["(직접 입력)"] + hints
    
    # 3. 드롭다운 (Callback 연결)
    st.selectbox(
        "Suggested Values (DB)", 
        options, 
        index=0, 
        key="hint_selectbox",
        on_change=on_hint_change, 
        help="선택하면 아래 입력창에 자동으로 채워집니다."
    )
    
    # 4. 값 입력 (세션 스테이트 키 바인딩)
    st.text_input(
        "Value", 
        key="input_val_key", 
        placeholder="e.g., Lazarus, CVE-2021-44228"
    )
    
    # 5. 추가 버튼 (Callback 연결)
    # on_click을 사용하면 버튼 로직이 렌더링 전에 처리되므로 에러가 해결됩니다.
    st.button("Add to List", type="secondary", use_container_width=True, on_click=add_artifact)
    

# ==============================================================================
# 2. 메인 화면: 분석 실행 및 결과
# ==============================================================================

if not st.session_state.artifacts:
    st.info("👈 왼쪽 사이드바에서 분석할 아티팩트(단서)를 추가해주세요.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("##### 💡 Quick Start")
        if st.button("Load Example (Lazarus Campaign)"):
            st.session_state.artifacts = [
                {"type": "Indicator", "value": "101.35.56.7"},
                {"type": "Indicator", "value": "zddtxxyxb.zip"},
                {"type": "Indicator", "value": "http://101.43.166.60:8888/02.08.2022.exe"},
                {"type": "Vulnerability", "value": "CVE-2025-21739"},
                {"type": "Indicator", "value": "101.126.11.168"},
                {"type": "Vulnerability", "value": "CVE-2025-11371"},
                {"type": "Indicator", "value": "http://1.64.40.207/Photo.scr"},
                {"type": "Indicator", "value": "eznoted2b1405e.zip"},
                {"type": "Malware", "value": "Amadey"}
            ]
            st.rerun()

else:
    # --- Added: Tag-style display of selected artifacts ---
    col_header, col_clear = st.columns([5, 1])
    with col_header:
        st.markdown("##### 📍 Active Clues (Click to remove)")
    with col_clear:
        if st.button("Clear All", type="tertiary", use_container_width=True):
            st.session_state.artifacts = []
            st.rerun()
    
    # Custom CSS for high-fidelity 3D pill tags + Horizontal Flow Fix
    st.markdown("""
        <style>
        /* 1. Force Streamlit's horizontal block (columns) to wrap */
        div[data-testid="stHorizontalBlock"] {
            flex-wrap: wrap !important;
            gap: 10px !important;
        }

        /* 2. Ensure each column only takes as much space as needed for the tag */
        div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
            width: auto !important;
            min-width: min-content !important;
            flex: 0 1 auto !important;
        }

        /* 3. High-Fidelity 3D Pill Style */
        div.stButton > button[id*="tag_"] {
            border-radius: 50px !important;
            border: none !important;
            outline: none !important;
            padding: 0 16px !important;
            height: 34px !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            color: white !important;
            white-space: nowrap !important;
            cursor: pointer !important;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), inset 0 -3px 0 rgba(0,0,0,0.2) !important;
            transition: all 0.1s ease !important;
            margin-bottom: 5px !important;
        }

        /* Physical 'Pressed' effect */
        div.stButton > button[id*="tag_"]:active {
            transform: translateY(2px) !important;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.2) !important;
        }

        /* Hover effect */
        div.stButton > button[id*="tag_"]:hover {
            filter: brightness(1.1) !important;
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 8px -1px rgba(0, 0, 0, 0.15), inset 0 -3px 0 rgba(0,0,0,0.2) !important;
        }

        /* Type-specific colors */
        button[id*="tag_Malware"] { background-color: #ef4444 !important; }
        button[id*="tag_Vulnerability"] { background-color: #f59e0b !important; }
        button[id*="tag_Indicator"] { background-color: #3b82f6 !important; }
        button[id*="tag_Threat Group"] { background-color: #8b5cf6 !important; }
        </style>
    """, unsafe_allow_html=True)

    artifact_list = st.session_state.artifacts
    
    if not artifact_list:
        st.caption("No clues added yet.")
    else:
        # Create a large number of columns and force them to wrap via CSS
        # This keeps them horizontal and left-aligned.
        cols = st.columns([1] * 20) 
        for i, art in enumerate(artifact_list):
            # Fill columns one by one; CSS handles the wrapping and left-alignment
            with cols[i % 20]:
                btn_label = f"✕ {art['type']}: {art['value']}"
                if st.button(btn_label, key=f"tag_{art['type']}_{i}"):
                    st.session_state.artifacts.pop(i)
                    st.rerun()
    st.divider()
    if st.button("🚀 Run Correlation Analysis", type="primary", use_container_width=True):
        with st.spinner(f"Analyzing connections across the graph (Depth {depth})..."):
            try:
                results, ai_analysis = correlation.run_correlation_analysis(
                    st.session_state.artifacts, 
                    depth=depth,
                    looseness=looseness,
                    include_incidents=include_incidents
                )
                
                st.success("Analysis Complete!")
                st.markdown("### 🤖 AI Intelligence Report")
                st.info(ai_analysis)
                
                st.markdown("### 🕸️ Knowledge Graph Matches")
                if results:
                    df = pd.DataFrame(results)

                    # Create a new DataFrame for display to avoid SettingWithCopyWarning
                    df_display = pd.DataFrame({
                        'Suspect Group/Entity': df['label'],
                        'Type': df['type'],
                        'Match Score': df['score'].round(2),
                        'Confidence(%)': df['percent'].round(2),
                        'Evidence Path': df['matches']
                    })
                    
                    try:
                        st.dataframe(
                            df_display.style.format({
                                'Match Score': '{:.2f}',
                                'Confidence(%)': '{:.2f}'
                            }).background_gradient(subset=['Match Score'], cmap="Reds"),
                            use_container_width=True
                        )
                    except:
                        st.dataframe(df_display, use_container_width=True)
                else:
                    st.warning("No strong correlations found with the current database.")
                    
            except Exception as e:
                st.error(f"Error during analysis: {e}")