import streamlit as st
import pandas as pd
import sys
import os

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

# [변경] 모듈 임포트 경로 수정 (src. 포함)
from src.services.intelligence_processor import processor
from src.core.repository.graph_repository import save_incident_to_graph
from streamlit_agraph import agraph, Node, Edge, Config

st.set_page_config(page_title="Intelligence Processing", page_icon="🧠", layout="wide")

# ==============================================================================
# [STYLE] 노드 스타일 정의
# ==============================================================================
NODE_STYLES = {
    # Intelligence Category Styles
    "Incident": {"color": "#FF2B2B", "shape": "hexagon", "size": 40},
    "MalwareReport": {"color": "#D32DFF", "shape": "dot", "size": 35},
    "ThreatReport": {"color": "#1A1A1A", "shape": "star", "size": 35},
    "VulnerabilityReport": {"color": "#FF9F1C", "shape": "triangle", "size": 35},
    
    # Common Nodes
    "AttackStep": {"color": "#FFFFFF", "shape": "text", "size": 20},
    "IP": {"color": "#00E096", "shape": "square", "size": 18},
    "Domain": {"color": "#00E096", "shape": "square", "size": 18},
    "URL": {"color": "#00E096", "shape": "square", "size": 18},
    "Hash": {"color": "#7B61FF", "shape": "box", "size": 18},
    "Tool": {"color": "#2D8CFF", "shape": "box", "size": 20},
    "Unknown": {"color": "#999999", "shape": "dot", "size": 10}
}

# ==============================================================================
# 0. 헬퍼 함수 및 초기화
# ==============================================================================

def truncate_text(text, max_length):
    """텍스트가 지정된 길이보다 길면 자르고 '...'을 붙임"""
    if not text: return ""
    return str(text)[:max_length] + "..." if len(str(text)) > max_length else str(text)

if "proc_result" not in st.session_state:
    st.session_state.proc_result = None

# 그래프 강제 리프레시를 위한 버전 관리
if "graph_version" not in st.session_state:
    st.session_state.graph_version = 0

# ==============================================================================
# 1. Header & Input
# ==============================================================================
st.title("🧠 Ontology Intelligence Processor")
st.markdown("""
비정형데이터(위협리포트, 블로그, 분석자료 등)에서 LLM을 활용해 사이버 위협 인텔리전스를 추출하고 이를 구조화하여 지식그래프에 적재합니다.
""")
col_input, col_output = st.columns([1, 1.5])

with col_input:
    st.subheader("📝 Input Report")
    report_text = st.text_area(
        "Paste threat report here...", 
        height=500,
        placeholder="Copy and paste the CTI report content here..."
    )
    
    if st.button("🔍 Analyze & Extract", use_container_width=True):
        if not report_text.strip():
            st.warning("Please enter text first.")
        else:
            with st.spinner("LLM Analyzing & Structuring..."):
                try:
                    # [변경] Processor 호출 (auto_ingest 제거)
                    result = processor.process_report(report_text)
                    st.session_state.proc_result = result
                    st.session_state.graph_version += 1
                    st.success("Analysis Done!")
                except Exception as e:
                    st.error(f"Analysis Failed: {e}")

# ==============================================================================
# 2. Visualization
# ==============================================================================
with col_output:
    if st.session_state.proc_result:
        # Pydantic 객체 가져오기
        report = st.session_state.proc_result
        
        # 통계 계산을 위해 엔티티 평탄화(Flatten)
        all_entities = []
        for step in report.attack_flow:
            all_entities.extend(step.related_entities)

        st.subheader("📊 Extraction Results")
        tab1, tab2, tab3 = st.tabs(["📋 Data Tables", "🕸️ Graph Preview", "💾 DB Ingest"])

        # --- TAB 1: 테이블 뷰 ---
        with tab1:
            st.markdown(f"**Title:** {report.title}")
            st.markdown(f"**Category:** `{report.category}`")
            st.markdown(f"**Summary:** {report.summary}")
            
            st.markdown("#### 1. Extracted Entities")
            ent_data = []
            for e in all_entities:
                ent_data.append({
                    "Original Value": e.value,
                    "Normalized": e.normalized_value or e.value,
                    "Type": e.type,
                    "Status": "✅ Existing" if not e.is_new else "✨ New",
                    "Step": next((s.phase for s in report.attack_flow if e in s.related_entities), "Unknown")
                })
            
            if ent_data:
                st.dataframe(pd.DataFrame(ent_data), use_container_width=True)
            else:
                st.info("No entities extracted.")

            st.markdown("#### 2. Attack Flow Steps")
            step_data = []
            for step in report.attack_flow:
                step_data.append({
                    "Order": step.step,
                    "Phase": step.phase,
                    "Description": step.description,
                    "Entities Count": len(step.related_entities)
                })
            st.dataframe(pd.DataFrame(step_data), use_container_width=True)

        # --- TAB 2: 그래프 뷰 ---
        with tab2:
            col_head, col_btn = st.columns([4, 1])
            with col_head:
                st.caption("Structured Subgraph Preview")
            with col_btn:
                # Reset 버튼 클릭 시 세션 버전을 올림
                if st.button("🔄 Reset View"):
                    st.session_state.graph_version += 1
                    st.rerun()

            graph_nodes = []
            graph_edges = []
            added_node_ids = set()

            # 1. Root Node (Category에 따른 스타일 적용)
            inc_id = "ROOT_NODE"
            # 카테고리에 맞는 스타일 선택 (기본값 Incident)
            root_style = NODE_STYLES.get(report.category, NODE_STYLES["Incident"])
            
            graph_nodes.append(Node(
                id=inc_id,
                label=truncate_text(report.title, 15),
                size=root_style["size"],
                shape=root_style["shape"],
                color=root_style["color"],
                title=f"Category: {report.category}\nTitle: {report.title}"
            ))

            # 2. Attack Steps & Entities 생성 로직
            for step in report.attack_flow:
                step_id = f"STEP_{step.step}"
                graph_nodes.append(Node(
                    id=step_id,
                    label=f"{step.step}. {step.phase}",
                    size=20,
                    shape="box",
                    color="#444444",
                    font={"color": "white"}
                ))
                graph_edges.append(Edge(source=inc_id, target=step_id, label="HAS_FLOW"))

                for ent in step.related_entities:
                    ent_id = ent.normalized_value if ent.normalized_value else ent.value
                    if ent_id not in added_node_ids:
                        # 엔티티 타입별 스타일 적용
                        e_style = NODE_STYLES.get(ent.type, NODE_STYLES["Unknown"])
                        graph_nodes.append(Node(
                            id=ent_id,
                            label=truncate_text(ent_id, 12),
                            size=e_style["size"],
                            shape=e_style["shape"],
                            color=e_style["color"],
                            font={"color": "white"}
                        ))
                        added_node_ids.add(ent_id)
                    graph_edges.append(Edge(source=step_id, target=ent_id, label="INVOLVES"))

            # Config
            config = Config(
                width="100%",
                height=600,
                directed=True,
                physics={
                    "enabled": True,
                    "solver": "forceAtlas2Based",
                    "forceAtlas2Based": {
                        "gravitationalConstant": -50,
                        "centralGravity": 0.01,
                        "springLength": 100,
                        "springConstant": 0.08
                    },
                    "minVelocity": 0.75,
                    "stabilization": {
                        "enabled": True,
                        "iterations": 200, 
                        "updateInterval": 25
                    }
                },
                node={"labelProperty": "label"},
                backgroundColor="#212529"
            )

            try:
                # 컨테이너를 사용하여 렌더링 영역을 확보
                with st.container():
                    # agraph의 config 객체 내부에 고유 ID를 부여하여 캐시를 우회합니다.
                    # 일부 버전에서는 agraph 호출 시 파라미터가 아닌 
                    # config 객체의 구성을 통해 리프레시를 제어합니다.
                    
                    # 만약 key가 계속 에러난다면 아래처럼 key를 빼고 실행하세요.
                    # 대신 Reset View 시 st.rerun()이 화면을 다시 그리게 됩니다.
                    agraph(
                        nodes=graph_nodes, 
                        edges=graph_edges, 
                        config=config
                        # key 인자를 제거했습니다.
                    )
            except Exception as e:
                st.error(f"Graph Rendering Failed: {e}")

        # --- TAB 3: DB 적재 ---
        with tab3:
            st.info("검토가 완료되었으면 아래 버튼을 눌러 Neo4j 데이터베이스에 반영하세요.")
            
            total_entities = len(all_entities)
            new_entities = sum(1 for e in all_entities if e.is_new)
            
            col_stat1, col_stat2, col_stat3 = st.columns(3)
            col_stat1.metric("Total Steps", len(report.attack_flow))
            col_stat2.metric("Total Entities", total_entities)
            col_stat3.metric("New Entities", new_entities, delta="To Create", delta_color="normal")

            st.divider()

            if st.button("📥 Ingest into Neo4j", type="primary", use_container_width=True):
                with st.spinner("Merging data into Neo4j..."):
                    try:
                        # [변경] Repository 함수 호출
                        save_incident_to_graph(report)
                        st.success("Success! Incident graph created in Neo4j.")
                    except Exception as e:
                        st.error(f"Ingestion Error: {e}")