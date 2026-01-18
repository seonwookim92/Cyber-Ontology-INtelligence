"""
Streamlit Frontend for File Language Detector
Provides a web UI for uploading files and reviewing detection results.
"""

import streamlit as st
import requests
import json
from typing import Optional

# Configuration
API_BASE_URL = "http://localhost:8000"

# Available categories for dropdown
CATEGORIES = [
    "Binary (C)",
    "Binary (C++)",
    "Binary (C#)",
    "Binary (Java)",
    "Script (C)",
    "Script (C++)",
    "Script (C#)",
    "Script (Java)",
    "Script (PowerShell)",
    "Script (VBScript)",
    "ETC"
]


def parse_category(category: str) -> tuple[str, str]:
    """Parse category string into type and language."""
    if "(" in category and ")" in category:
        type_part = category.split("(")[0].strip()
        lang_part = category.split("(")[1].split(")")[0].strip()
        return type_part, lang_part
    return "ETC", "ETC"


def upload_file(file) -> Optional[dict]:
    """Upload file to API and get detection result."""
    try:
        files = {"file": (file.name, file, file.type)}
        response = requests.post(f"{API_BASE_URL}/upload", files=files)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Upload failed: {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to API server. Please make sure the server is running on port 8000.")
        st.info("Run: python server.py")
        return None
    except Exception as e:
        st.error(f"Error uploading file: {str(e)}")
        return None


def deobfuscate_file(file_id: str, language: str = None) -> Optional[dict]:
    """Request deobfuscation for a file."""
    try:
        data = {"file_id": file_id, "language": language}
        response = requests.post(f"{API_BASE_URL}/deobfuscate", json=data)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Deobfuscation failed: {response.text}")
            return None
    except Exception as e:
        st.error(f"Error during deobfuscation: {str(e)}")
        return None


def analyze_threat_actor(file_id: str) -> Optional[dict]:
    """Request threat actor analysis for a file."""
    try:
        data = {"file_id": file_id}
        response = requests.post(f"{API_BASE_URL}/analyze-threat-actor", json=data)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Threat actor analysis failed: {response.text}")
            return None
    except Exception as e:
        st.error(f"Error during threat actor analysis: {str(e)}")
        return None


def finalize_detection(file_id: str, selected_type: str, selected_language: str,
                      ioc_list: Optional[dict] = None, threat_actor: Optional[str] = None,
                      threat_actor_probability: Optional[float] = None, malware_family: Optional[str] = None,
                      malware_probability: Optional[float] = None) -> Optional[dict]:
    """Send final detection result to API."""
    try:
        data = {
            "file_id": file_id,
            "type": selected_type,
            "language": selected_language,
            "ioc_list": ioc_list,
            "threat_actor": threat_actor,
            "threat_actor_probability": threat_actor_probability,
            "malware_family": malware_family,
            "malware_probability": malware_probability
        }
        response = requests.post(f"{API_BASE_URL}/finalize", json=data)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Finalization failed: {response.text}")
            return None
    except Exception as e:
        st.error(f"Error finalizing detection: {str(e)}")
        return None


def main():
    """Main Streamlit application."""
    st.set_page_config(
        page_title="바이너리/스크립트 분석기",
        page_icon="🔍",
        layout="centered"
    )

    st.title("🔍 바이너리 분석기/스크립트 분석기")
    st.markdown("바이너리나 스크립트 파일을 업로드하여 프로그래밍 언어를 감지합니다.")

    # Initialize session state
    if "detection_result" not in st.session_state:
        st.session_state.detection_result = None
    if "file_uploaded" not in st.session_state:
        st.session_state.file_uploaded = False
    if "deobfuscation_result" not in st.session_state:
        st.session_state.deobfuscation_result = None
    if "threat_actor_result" not in st.session_state:
        st.session_state.threat_actor_result = None
    if "final_result" not in st.session_state:
        st.session_state.final_result = None
    if "selected_type" not in st.session_state:
        st.session_state.selected_type = None
    if "selected_language" not in st.session_state:
        st.session_state.selected_language = None

    # Step 5: Display Final Result (최종 결과가 있으면 이것만 표시)
    if st.session_state.final_result:
        st.header("5단계: 최종 분석 결과")

        final = st.session_state.final_result

        # Display as JSON
        st.success("✓ 전체 분석 완료!")
        st.json(final)

        # Display formatted result
        st.markdown("---")
        st.subheader("요약")

        # Basic info
        st.markdown(f"""
        - **파일명:** {final["filename"]}
        - **종류:** {final["final_type"]}
        - **언어:** {final["final_language"]}
        - **분류:** {final["final_category"]}
        """)

        # Threat Actor info
        if final.get("threat_actor"):
            st.markdown(f"""
        - **Threat Actor:** {final["threat_actor"]}
        - **확률:** {final["threat_actor_probability"] * 100:.0f}%
            """)
        else:
            st.markdown("- **Threat Actor:** 분석 안됨")

        # IoC List
        if final.get("ioc_list"):
            st.markdown("---")
            st.subheader("IoC List")

            ioc = final["ioc_list"]

            if ioc.get("urls"):
                st.markdown("**URLs:**")
                for item in ioc["urls"]:
                    st.markdown(f"- Pass {item['Pass']}: `{item['URL']}`")

            if ioc.get("ips"):
                st.markdown("**IPs:**")
                for item in ioc["ips"]:
                    st.markdown(f"- Pass {item['Pass']}: `{item['IP']}`")
        else:
            st.markdown("- **IoC List:** 추출 안됨")

        # Reset button
        if st.button("다른 파일 분석하기"):
            st.session_state.detection_result = None
            st.session_state.file_uploaded = False
            st.session_state.deobfuscation_result = None
            st.session_state.threat_actor_result = None
            st.session_state.final_result = None
            st.session_state.selected_type = None
            st.session_state.selected_language = None
            st.rerun()

    # Step 4: Threat Actor Analysis (조건부 - Binary 또는 PowerShell/VBScript)
    elif st.session_state.threat_actor_result:
        st.header("4단계: Threat Actor 분석 결과")

        threat = st.session_state.threat_actor_result

        st.success("✓ Threat Actor 분석 완료!")

        # Display result
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Threat Actor", threat["threat_actor"])
        with col2:
            st.metric("확률", f"{threat['probability'] * 100:.0f}%")

        st.info(f"**{threat['threat_actor']}**로 분류되었습니다 (신뢰도: {threat['probability'] * 100:.0f}%)")

        # Display result
        col3, col4 = st.columns(2)
        with col3:
            st.metric("Malware", threat["malware_family"])
        with col4:
            st.metric("확률", f"{threat['malware_probability'] * 100:.0f}%")

        st.info(f"**{threat['malware_family']}**로 분류되었습니다 (신뢰도: {threat['malware_probability'] * 100:.0f}%)")
        # Next button
        if st.button("다음 단계로", type="primary"):
            # Finalize
            ioc_list = st.session_state.deobfuscation_result.get("ioc_list") if st.session_state.deobfuscation_result else None

            with st.spinner("최종 결과 생성중..."):
                final_result = finalize_detection(
                    st.session_state.detection_result["file_id"],
                    st.session_state.selected_type,
                    st.session_state.selected_language,
                    ioc_list=ioc_list,
                    threat_actor=threat["threat_actor"],
                    threat_actor_probability=threat["probability"],
                    malware_family=threat["malware_family"],
                    malware_probability=threat["malware_probability"]
                )

                if final_result:
                    st.session_state.final_result = final_result
                    st.rerun()

    # Step 3: Deobfuscation (조건부 - PowerShell/VBScript만)
    elif st.session_state.deobfuscation_result:
        st.header("3단계: 난독화 해제 결과")

        deobf = st.session_state.deobfuscation_result

        st.success("✓ 난독화 해제 완료!")

        # Display codes vertically (4 code blocks)
        st.subheader("코드 비교")

        # Original Code
        st.markdown("**Original Code**")
        st.code(deobf["original_code"], 
                language="powershell" if st.session_state.selected_language == "PowerShell" else "vbscript",
                height=400,
                wrap_lines=True)

        # Deobfuscated Code
        st.markdown("**Deobfuscated Code**")
        st.code(deobf["deobfuscated_code"], 
                language="powershell" if st.session_state.selected_language == "PowerShell" else "vbscript",
                height=400,
                wrap_lines=True)

        # Aggressively Deobfuscated Code
        st.markdown("**Aggressively Deobfuscated Code**")
        st.code(deobf["aggressively_deobfuscated_code"], 
                language="powershell" if st.session_state.selected_language == "PowerShell" else "vbscript",
                height=400,
                wrap_lines=True)
        
        # LLM Refined Code
        st.markdown("**LLM Refined Code**")
        st.code(deobf["aggressively_deobfuscated_code2"], 
                language="powershell" if st.session_state.selected_language == "PowerShell" else "vbscript",
                height=400,
                wrap_lines=True)

        # Download buttons (3 buttons - excluding original)
        st.markdown("---")
        st.subheader("다운로드")

        col1, col2, col3 = st.columns(3)
        filename_base = deobf["filename"].rsplit(".", 1)[0]
        file_ext = deobf["filename"].rsplit(".", 1)[1] if "." in deobf["filename"] else "txt"

        with col1:
            st.download_button(
                label="Deobfuscated Code",
                data=deobf["deobfuscated_code"],
                file_name=f"{filename_base}_deobfuscated.{file_ext}",
                mime="text/plain"
            )

        with col2:
            st.download_button(
                label="Aggressively Deobfuscated Code",
                data=deobf["aggressively_deobfuscated_code"],
                file_name=f"{filename_base}_aggressive.{file_ext}",
                mime="text/plain"
            )

        with col3:
            st.download_button(
                label="LLM Refined Code",
                data=deobf["aggressively_deobfuscated_code2"],
                file_name=f"{filename_base}_llm_refined.{file_ext}",
                mime="text/plain"
            )

        # IoC List
        st.markdown("---")
        st.subheader("IoC List")

        ioc = deobf["ioc_list"]

        if ioc.get("urls"):
            st.markdown("**URLs:**")
            for item in ioc["urls"]:
                st.markdown(f"- Pass {item['Pass']}: `{item['URL']}`")

        if ioc.get("ips"):
            st.markdown("**IPs:**")
            for item in ioc["ips"]:
                st.markdown(f"- Pass {item['Pass']}: `{item['IP']}`")

        if ioc.get("emails"):
            st.markdown("**Emails:**")
            for item in ioc["emails"]:
                st.markdown(f"- Pass {item['Pass']}: `{item['Email']}`")

        # Next button - proceed to Final step (skip Threat Actor analysis for scripts)
        if st.button("다음 단계로", type="primary"):
            with st.spinner("최종 결과 생성중..."):
                ioc_list = st.session_state.deobfuscation_result.get("ioc_list")

                final_result = finalize_detection(
                    st.session_state.detection_result["file_id"],
                    st.session_state.selected_type,
                    st.session_state.selected_language,
                    ioc_list=ioc_list
                )

                if final_result:
                    st.session_state.final_result = final_result
                    st.rerun()

    # Step 2: Review and Modify Detection (탐지 결과가 있으면 이것만 표시)
    elif st.session_state.detection_result:
        st.header("2단계: 탐지 결과 검토")

        result = st.session_state.detection_result

        # Display detection info
        col1, col2 = st.columns(2)
        with col1:
            st.metric("파일명", result["filename"])
        with col2:
            st.metric("감지됨", result["category"])

        # Allow user to modify the detection
        st.subheader("확인 또는 수정")

        current_category = result["category"]
        default_index = CATEGORIES.index(current_category) if current_category in CATEGORIES else len(CATEGORIES) - 1

        selected_category = st.selectbox(
            "올바른 분류를 선택하세요:",
            options=CATEGORIES,
            index=default_index,
            help="이 파일과 잘 맞는 분류를 선택해주세요"
        )

        # Parse selected category
        selected_type, selected_language = parse_category(selected_category)

        # Show what will be submitted
        st.info(f"**분류:** {selected_type}  \n**언어:** {selected_language}")

        # Buttons
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("✓ 제출하기", type="primary", use_container_width=True):
                # Store selected values
                st.session_state.selected_type = selected_type
                st.session_state.selected_language = selected_language

                # Decide next step based on language
                if selected_language in ["PowerShell", "VBScript"]:
                    # PowerShell/VBScript: Go to deobfuscation (Step 3)
                    with st.spinner("난독화 해제중..."):
                        deobf_result = deobfuscate_file(result["file_id"], selected_language)

                        if deobf_result:
                            st.session_state.deobfuscation_result = deobf_result
                            st.rerun()

                elif selected_type == "Binary":
                    # Binary: Go to Threat Actor analysis (Step 4)
                    with st.spinner("Threat Actor 분석중..."):
                        threat_result = analyze_threat_actor(result["file_id"])

                        if threat_result:
                            st.session_state.threat_actor_result = threat_result
                            st.rerun()

                else:
                    # ETC: Go directly to final (Step 5)
                    with st.spinner("최종 결과 생성중..."):
                        final_result = finalize_detection(
                            result["file_id"],
                            selected_type,
                            selected_language
                        )

                        if final_result:
                            st.session_state.final_result = final_result
                            st.rerun()

        with col2:
            if st.button("다시 업로드 하러 가기", use_container_width=True):
                st.session_state.detection_result = None
                st.session_state.file_uploaded = False
                st.session_state.deobfuscation_result = None
                st.session_state.threat_actor_result = None
                st.session_state.final_result = None
                st.session_state.selected_type = None
                st.session_state.selected_language = None
                st.rerun()

    # Step 1: File Upload (초기 상태에서만 표시)
    else:
        st.header("1단계 : 파일 업로드")

        uploaded_file = st.file_uploader(
            "파일 선택",
            type=None,  # Allow all file types
            help="바이너리나 스크립트 파일을 업로드 합니다"
        )

        if uploaded_file is not None and not st.session_state.file_uploaded:
            with st.spinner("파일 분석중..."):
                result = upload_file(uploaded_file)

                if result:
                    st.session_state.detection_result = result
                    st.session_state.file_uploaded = True
                    st.success("✓ 파일 업로드 및 분석이 완료되었습니다")
                    st.rerun()

    # Sidebar with info
    with st.sidebar:
        st.header("About")
        st.markdown("""
        바이너리를 올리면 그룹 분류 및 IoC 추출까지 해드립니다~

        **지원:**
        - **바이너리**: C, C++, C#, Java (JAR)
        - **코드/스크립트**: PowerShell, VBScript

        """)

        st.markdown("---")
        st.caption("Powered by FastAPI + Streamlit + Pygments")


if __name__ == "__main__":
    main()
