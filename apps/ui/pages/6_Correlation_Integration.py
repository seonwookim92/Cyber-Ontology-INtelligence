import streamlit as st
import sys
import os
import pandas as pd
import tempfile
import asyncio
import logging
import io
from pathlib import Path

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import correlation
from src.services.binary_analysis import BinaryAnalysisService

st.set_page_config(page_title="Threat Correlation (Test)", page_icon="🔗", layout="wide")

# ==============================================================================
# Logging Setup (Toggleable)
# ==============================================================================
# Initialize capture buffer in session state if needed, or global
if "log_capture_string" not in st.session_state:
    st.session_state.log_capture_string = io.StringIO()

log_capture_string = st.session_state.log_capture_string

# Configure Logger
analysis_logger = logging.getLogger("src.services.binary_analysis")

# Ensure handler is attached only once
# Check if our custom handler is already attached
has_handler = False
for h in analysis_logger.handlers:
    if isinstance(h, logging.StreamHandler) and h.stream == log_capture_string:
        has_handler = True
        break

if not has_handler:
    ch = logging.StreamHandler(log_capture_string)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    analysis_logger.addHandler(ch)

st.title("🔗 Threat Correlation Analysis (Integrated)")
st.markdown("""
파편화된 위협 정보(IP, Hash, CVE, Name)들 간의 **숨겨진 연결고리**를 찾아내어, 
배후의 공격 그룹(Threat Group)이나 연관된 캠페인을 추적합니다.
**추가 기능:** 바이너리 및 악성 스크립트를 직접 업로드하여 분석된 결과를 아티팩트로 추가할 수 있습니다.
""")

# ==============================================================================
# Service Initialization
# ==============================================================================
@st.cache_resource
def get_analysis_service():
    return BinaryAnalysisService()

analysis_service = get_analysis_service()

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

def add_artifact(val=None, type_override=None):
    """추가 버튼 클릭 시 실행되는 콜백"""
    current_type = type_override if type_override else st.session_state.get("artifact_type_select")
    current_val = val if val else st.session_state.input_val_key
    
    if current_val and current_val.strip():
        if any(x['value'] == current_val.strip() for x in st.session_state.artifacts):
            st.toast(f"⚠️ 이미 추가된 아티팩트입니다: {current_val}")
        else:
            st.session_state.artifacts.append({"type": current_type, "value": current_val.strip()})
            if not val:
                st.session_state.input_val_key = ""
            st.toast(f"✅ 추가되었습니다: {current_val}")
    else:
        if not val:
            st.toast("⚠️ 값을 입력하거나 선택해주세요.")

# ==============================================================================
# 1. 사이드바: 분석 설정 & 아티팩트 입력
# ==============================================================================
with st.sidebar:
    st.header("1️⃣ Input Artifacts")
    
    # Debug Toggle
    show_debug = st.checkbox("Show Debug Logs", value=False, help="Enable detailed logging for file analysis.")
    
    # Set Logging Level based on checkbox
    if show_debug:
        analysis_logger.setLevel(logging.DEBUG)
    else:
        analysis_logger.setLevel(logging.INFO)

    depth = st.slider("Analysis Depth", 1, 3, 2, 
                      help="1: 직접 연결, 2: 간접 연결(IOC/Vuln), 3: 심층 연결(TTP 공유)")
    include_incidents = st.checkbox("Include Incidents DB", value=True, help="Incident 기록을 포함하여 연관성을 찾습니다.")
    looseness = st.slider("Looseness (fuzziness)", 0, 100, 30, help="높을수록 느슨한(퍼지/부분) 매칭을 허용합니다.")
    
    st.divider()
    
    if "artifacts" not in st.session_state:
        st.session_state.artifacts = []

    # --- New File Analysis Section ---
    with st.expander("📂 Add Binary/Script (New!)", expanded=False):
        st.markdown("파일을 업로드하여 분석 결과(IoC, Malware Family)를 아티팩트에 추가합니다.")
        
        # State management for file upload
        if "file_analysis_state" not in st.session_state:
            st.session_state.file_analysis_state = "upload" # upload, detected, analyzed
        
        uploaded_file = st.file_uploader("Upload File", type=None, key="uploader")
        
        if uploaded_file:
            # 1. Save to temp immediately to allow analysis
            # We need a persistent temp path across reruns for this file
            if "current_file_path" not in st.session_state or st.session_state.get("current_file_name") != uploaded_file.name:
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp:
                    tmp.write(uploaded_file.getvalue())
                    st.session_state.current_file_path = tmp.name
                    st.session_state.current_file_name = uploaded_file.name
                    st.session_state.file_analysis_state = "upload" # Reset state on new file

            # 2. Detect (Auto-run once)
            if st.session_state.file_analysis_state == "upload":
                with st.spinner("Detecting file type..."):
                    det_res = analysis_service.detect_file_type(st.session_state.current_file_path)
                    st.session_state.detected_type = det_res.get("type", "ETC")
                    st.session_state.detected_lang = det_res.get("language", "ETC")
                    st.session_state.file_analysis_state = "detected"
        
            # 3. User Confirmation / Correction
            if st.session_state.file_analysis_state in ["detected", "analyzed"]:
                st.markdown("---")
                st.caption("File Details")
                
                # Language/Type Selector
                c1, c2 = st.columns(2)
                with c1:
                    sel_type = st.selectbox("Type", ["Binary", "Script", "ETC"], 
                                            index=["Binary", "Script", "ETC"].index(st.session_state.detected_type) if st.session_state.detected_type in ["Binary", "Script", "ETC"] else 2)
                with c2:
                    # Smart options based on type
                    lang_opts = ["C", "C++", "C#", "Java", "PowerShell", "VBScript", "Python", "ETC"]
                    
                    # Try to find default index
                    try:
                        def_idx = lang_opts.index(st.session_state.detected_lang)
                    except ValueError:
                        def_idx = len(lang_opts) - 1
                        
                    sel_lang = st.selectbox("Language", lang_opts, index=def_idx)

                # Analyze Button
                if st.button("Confirm & Analyze", type="primary", use_container_width=True):
                    # Clear logs before new analysis
                    log_capture_string.truncate(0)
                    log_capture_string.seek(0)
                    
                    with st.status("Running Analysis...", expanded=True) as status:
                        try:
                            st.write("Initializing analysis...")
                            extracted_artifacts = []
                            temp_path = st.session_state.current_file_path
                            
                            if sel_type == "Binary":
                                st.write("Running GNN Binary Classification...")
                                bin_res = asyncio.run(analysis_service.analyze_binary(temp_path))
                                
                                mal_fam = bin_res.get("malware_family")
                                apt_grp = bin_res.get("apt_group")
                                
                                if mal_fam:
                                    st.write(f"Found Malware Family: **{mal_fam}**")
                                    extracted_artifacts.append({"type": "Malware", "value": mal_fam})
                                if apt_grp:
                                    st.write(f"Found APT Group: **{apt_grp}**")
                                    extracted_artifacts.append({"type": "Threat Group", "value": apt_grp})
                                    
                            elif sel_lang in ["PowerShell", "VBScript"]:
                                st.write(f"Deobfuscating {sel_lang} script...")
                                script_res = analysis_service.deobfuscate_script(temp_path, sel_lang)
                                iocs = script_res.get("ioc_list", {})
                                
                                urls = iocs.get("urls", [])
                                ips = iocs.get("ips", [])
                                
                                st.write(f"Extracted {len(urls)} URLs, {len(ips)} IPs")
                                
                                for url in urls:
                                    extracted_artifacts.append({"type": "Indicator", "value": url})
                                for ip in ips:
                                    extracted_artifacts.append({"type": "Indicator", "value": ip})
                            
                            st.session_state.last_analysis_results = extracted_artifacts
                            st.session_state.file_analysis_state = "analyzed"
                            status.update(label="Analysis Complete!", state="complete", expanded=False)
                            
                        except Exception as e:
                            st.error(f"Analysis failed: {e}")
                            status.update(label="Analysis Failed", state="error")

                # Show Debug Logs (Toggleable)
                if show_debug:
                    with st.expander("Debug Logs (Console Output)", expanded=True):
                        # Refresh logs
                        logs = log_capture_string.getvalue()
                        if logs:
                            st.code(logs, language="text")
                        else:
                            st.caption("No logs captured yet.")

    # Show Analysis Results from Session State
    if "last_analysis_results" in st.session_state and st.session_state.last_analysis_results:
        st.markdown("##### Analysis Results")
        with st.form("add_results_form"):
            results = st.session_state.last_analysis_results
            selected_indices = []
            
            for i, item in enumerate(results):
                # Checkbox for each item
                if st.checkbox(f"[{item['type']}] {item['value']}", value=True, key=f"chk_{i}"):
                    selected_indices.append(i)
            
            if st.form_submit_button("Add Selected to Correlation"):
                count = 0
                for i in selected_indices:
                    item = results[i]
                    if not any(x['value'] == item['value'] for x in st.session_state.artifacts):
                        st.session_state.artifacts.append(item)
                        count += 1
                
                st.toast(f"{count} items added.")
                st.session_state.last_analysis_results = None # Clear after adding
                st.rerun()

    st.divider()

    # --- Standard Input ---
    st.subheader("➕ Add New Artifact")
    
    a_type = st.selectbox(
        "Artifact Type", 
        ["Malware", "Vulnerability", "Indicator", "Threat Group"],
        key="artifact_type_select" 
    )
    
    try:
        hints = correlation.get_smart_hints(a_type, st.session_state.artifacts, limit=15)
    except:
        hints = []
        
    options = ["(직접 입력)"] + hints
    
    st.selectbox(
        "Suggested Values (DB)", 
        options, 
        index=0, 
        key="hint_selectbox",
        on_change=on_hint_change, 
        help="선택하면 아래 입력창에 자동으로 채워집니다."
    )
    
    st.text_input(
        "Value", 
        key="input_val_key", 
        placeholder="e.g., Lazarus, CVE-2021-44228"
    )
    
    
    st.button("Add to List", type="secondary", use_container_width=True, on_click=add_artifact)


# ==============================================================================
# 2. 메인 화면: 분석 실행 및 결과
# ==============================================================================

if not st.session_state.artifacts:
    st.info("👈 왼쪽 사이드바에서 분석할 아티팩트(단서)를 추가하거나 파일을 업로드하세요.")
    
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

                    df_display = pd.DataFrame({
                        'Suspect Group/Entity': df['label'],
                        'Type': df['type'],
                        'Match Score': df['score'].round(2),
                        'Confidence(%)': df['percent'].round(2),
                        'Evidence Path': df['matches']
                    })
                    
                    try:
                        st.dataframe(
                            df_display.style.background_gradient(subset=['Match Score'], cmap="Reds"),
                            width='stretch'
                        )
                    except:
                        st.dataframe(df_display, width='stretch')
                else:
                    st.warning("No strong correlations found with the current database.")
                    
            except Exception as e:
                st.error(f"Error during analysis: {e}")
