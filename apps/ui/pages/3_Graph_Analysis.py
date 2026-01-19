import streamlit as st
import sys
import os

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.services import graph as graph_service
from streamlit_agraph import agraph, Node, Edge, Config

st.set_page_config(page_title="Graph Analysis", page_icon="🕸️", layout="wide")

# ==============================================================================
# [STYLE] 커스텀 비주얼 스타일
# ==============================================================================
NODE_STYLES = {
    "Incident": {
        "color": "#FFD900", "shape": "hexagon", "size": 18,
        "font": {"color": "white", "face": "sans-serif", "background": "#440000"}
    },
    "Victim": {
        "color": "#2D8CFF", "shape": "box", "size": 14,
        "font": {"color": "white", "background": "#002B55"}
    },
    "Actor": {
        "color": "#FB0000", "shape": "star", "size": 14,
        "font": {"color": "white", "background": "#000000"}
    },
    "Malware": {
        "color": "#D32DFF", "shape": "diamond", "size": 11,
        "font": {"color": "white", "background": "#440055"}
    },
    "Vulnerability": {
        "color": "#FF9F1C", "shape": "triangle", "size": 11,
        "font": {"color": "white", "background": "#553300"}
    },
    "Indicator": {
        "color": "#00E096", "shape": "square", "size": 8,
        "font": {"color": "black", "background": "#004422"}
    },
    "Step": {
        "Success": {"color": "#00C853", "shape": "dot", "size": 6}, 
        "Fail":    {"color": "#FF3D00", "shape": "dot", "size": 6}
    }
}

st.title("🕸️ Graph Analysis")

# ==============================================================================
# 0. Session State 초기화
# ==============================================================================
if "graph_nodes" not in st.session_state: st.session_state.graph_nodes = set()
if "graph_edges" not in st.session_state: st.session_state.graph_edges = set()
if "store_nodes" not in st.session_state: st.session_state.store_nodes = []
if "store_edges" not in st.session_state: st.session_state.store_edges = []
if "incident_timeline" not in st.session_state: st.session_state.incident_timeline = []
if "last_selected_incident" not in st.session_state: st.session_state.last_selected_incident = None
if "layout_seed" not in st.session_state: st.session_state.layout_seed = 0
if "analysis_mode" not in st.session_state: st.session_state.analysis_mode = "Incident Walkthrough"

# ==============================================================================
# 1. UI Helpers: DB 데이터를 시각화 객체로 변환
# ==============================================================================

def add_node_to_state(node_id, label, type_key, title="", custom_color=None):
    if node_id not in st.session_state.graph_nodes:
        st.session_state.graph_nodes.add(node_id)
        
        style = NODE_STYLES.get(type_key, NODE_STYLES["Step"]["Success"]).copy()
        if custom_color: style["color"] = custom_color

        n = Node(
            id=node_id,
            label=label,
            title=title,
            shape=style.get("shape", "dot"),
            color=style.get("color", "#999"),
            size=style.get("size", 13),
            font=style.get("font", {"color": "white", "background": "#333"})
        )
        st.session_state.store_nodes.append(n)
        return True
    return False

def add_edge_to_state(source, target, label):
    edge_id = f"{source}-{label}-{target}"
    if edge_id not in st.session_state.graph_edges:
        st.session_state.graph_edges.add(edge_id)
        st.session_state.store_edges.append(Edge(source=source, target=target, label=label))
        return True
    return False

def reset_graph():
    st.session_state.graph_nodes = set()
    st.session_state.graph_edges = set()
    st.session_state.store_nodes = []
    st.session_state.store_edges = []
    st.session_state.incident_timeline = []

def map_node_to_vis(node_props, node_labels, element_id=None):
    """DB 노드 데이터를 시각화용 Node로 매핑 (Deduplication 및 에러 방지)"""
    nid = element_id or node_props.get('id') or node_props.get('name') or node_props.get('url')
    
    # Label 결정 및 산성화 (URL 등이 파일 경로로 오인되는 것 방지)
    raw_label = node_props.get('name') or node_props.get('title') or node_props.get('cve_id') or node_props.get('url', 'Unknown')
    label = graph_service.truncate_label(str(raw_label), 15)
    # URL 특수 문자 제거 (에러 방어용)
    label = label.replace("://", "_").replace("/", "_")
    
    type_key = "Step"
    if 'Incident' in node_labels: type_key = "Incident"
    elif 'Identity' in node_labels: type_key = "Victim"
    elif 'ThreatGroup' in node_labels: type_key = "Actor"
    elif 'Malware' in node_labels: type_key = "Malware"
    elif 'Vulnerability' in node_labels: type_key = "Vulnerability"
    elif 'Indicator' in node_labels: type_key = "Indicator"
    
    # tooltip용 title은 원본 유지
    title = f"[{type_key}] {raw_label}"
    if 'summary' in node_props: title += f"\n{node_props['summary']}"
    if 'description' in node_props: title += f"\n{node_props['description']}"

    add_node_to_state(nid, label, type_key, title=title)
    return nid

# ==============================================================================
# 2. Page Actions: 서비스 로직과 UI 상태 연결
# ==============================================================================

def load_incident_graph(inc_id):
    """지정된 사건의 서브그래프 로드"""
    data = graph_service.get_incident_subgraph(inc_id)
    if not data: return

    head = data['header']
    # 1. Header (Incident, Victim, Actor)
    add_node_to_state(inc_id, graph_service.truncate_label(head['title'], 12), "Incident", title=f"[Incident] {head['title']}")
    
    if head.get('victim_id'):
        add_node_to_state(head['victim_id'], graph_service.truncate_label(head['victim']), "Victim", title=f"[Victim] {head['victim']}")
        add_edge_to_state(inc_id, head['victim_id'], "TARGETS")
    
    if head.get('actor_id'):
        add_node_to_state(head['actor_id'], head['actor'], "Actor", title=f"[Actor] {head['actor']}")
        add_edge_to_state(inc_id, head['actor_id'], "ATTRIBUTED_TO")

    # 2. Steps & Artifacts
    prev_node = inc_id
    steps_map = {}

    for row in data['path']:
        sid = row['step_id']
        label = f"#{row['order']} {row['phase']}"
        step_color = NODE_STYLES["Step"]["Success"]["color"] if row['outcome'] == "Success" else NODE_STYLES["Step"]["Fail"]["color"]
        
        add_node_to_state(sid, label, "Step", title=f"{row['phase']}: {row['desc']}", custom_color=step_color)
        add_edge_to_state(prev_node, sid, "STARTS_WITH" if row['order'] == 1 else "NEXT")
        prev_node = sid
        
        if inc_id == st.session_state.last_selected_incident:
            if sid not in steps_map:
                steps_map[sid] = {"order": row['order'], "phase": row['phase'], "desc": row['desc'], "outcome": row['outcome'], "artifacts": []}

        if row['art_id']: # Artifact 발견
            art_props = row['props']
            art_labels = row['labels']
            art_val = art_props.get('name') or art_props.get('cve_id') or art_props.get('url')
            
            if inc_id == st.session_state.last_selected_incident:
                atype = "Indicator"
                if "Malware" in art_labels: atype = "Malware"
                elif "Vulnerability" in art_labels: atype = "Vulnerability"
                steps_map[sid]['artifacts'].append(f"[{atype}] {art_val}")

            aid = map_node_to_vis(art_props, art_labels, element_id=row['art_id'])
            add_edge_to_state(sid, aid, row['rel'])

    if inc_id == st.session_state.last_selected_incident:
        st.session_state.incident_timeline = sorted(steps_map.values(), key=lambda x: x['order'])

def expand_neighbors(node_id):
    """클릭된 노드의 주변 연결 엔티티 탐색"""
    # Incident 노드는 사건 데이터 로드
    # fetch_node_details를 통해 실제 라벨 확인
    target_node = graph_service.fetch_node_details(node_id)
    if not target_node: return 0
    
    labels = graph_service.graph_client.query("MATCH (n) WHERE elementId(n) = $id RETURN labels(n) as l", {"id": node_id})
    n_labels = labels[0]['l'] if labels else []

    if 'Incident' in n_labels:
        load_incident_graph(node_id)
        return 1
    
    # Step 노드는 확장 금지
    if 'AttackStep' in n_labels:
        st.warning("Attack Step은 확장이 지원되지 않습니다.")
        return 0
    
    current_inc = st.session_state.get('last_selected_incident')
    results = graph_service.explore_neighbors_query(node_id, current_inc)
    
    count = 0
    for r in results:
        res_id = r['res_id']
        res_label = r['res_label']
        res_type = r['type']
        rel = r['rel']

        # 노드 추가 (Deduplication)
        if add_node_to_state(res_id, graph_service.truncate_label(res_label, 12), res_type, title=res_label): count += 1
        
        if rel == 'ATTRIBUTED_TO' or rel == 'USED_IN' or rel == 'EXPLOITED_IN' or rel == 'SEEN_IN':
            # 관계의 방향성 고려 (Incident가 화살표 받는 쪽인 경우 등)
            if res_type == 'Incident': add_edge_to_state(res_id, node_id, rel)
            else: add_edge_to_state(node_id, res_id, rel)
        else:
            add_edge_to_state(node_id, res_id, rel)
    
    return count

def get_node_id_from_props(node_props):
    """Properties에서 agraph용 nid 추출 (중복 로직 방지)"""
    return node_props.get('id') or node_props.get('name') or node_props.get('cve_id') or node_props.get('url')

def run_path_discovery(start_val, end_val):
    """두 노드 간 최단 경로 탐색 실행 및 상태 업데이트"""
    # Hops를 0으로 고정하여 최단 경로만 가져옴
    results = graph_service.find_path_with_context(start_val, end_val, 0)
    if not results: return 0
    
    # 1. 최단 경로(Core) 처리
    if not results or not results[0].get('core_nodes'):
        return 0
        
    p = results[0]
    core_nodes_data = p['core_nodes']
    core_rels_data = p['core_rels']
    
    # Core 노드 매핑
    for n_data in core_nodes_data:
        map_node_to_vis(n_data['props'], n_data['labels'], element_id=n_data['id'])
    
    # Core 엣지 추가
    for rel in core_rels_data:
        add_edge_to_state(rel['s_id'], rel['e_id'], rel['type'])
            
    return 1

# ==============================================================================
# 3. Sidebar: 분석 모드 및 입력 제어
# ==============================================================================

with st.sidebar:
    st.header("⚙️ Graph Controls")
    
    # [핵심] 분석 모드 선택
    mode = st.radio(
        "Analysis Mode",
        ["Incident Walkthrough", "Connection Analysis"],
        index=0 if st.session_state.analysis_mode == "Incident Walkthrough" else 1
    )
    
    if mode != st.session_state.analysis_mode:
        st.session_state.analysis_mode = mode
        reset_graph()
        st.rerun()

    st.divider()

    if mode == "Incident Walkthrough":
        st.subheader("🗂️ Select Incident")
        incidents = graph_service.get_incidents()
        options = {r['title']: r['id'] for r in incidents}
        selected_label = st.selectbox("Historical Incidents", list(options.keys()))
        selected_id = options[selected_label]

        if selected_id != st.session_state.last_selected_incident:
            st.session_state.last_selected_incident = selected_id
            reset_graph()
            load_incident_graph(selected_id)
            st.rerun()
            
    else: # Connection Analysis
        st.subheader("🕸️ Connection Analysis")
        st.caption("엔트리 포인트와 타겟 간의 연결 고리를 탐색합니다.")

        # Unified Search UI (BloodHound style)
        if "src_selected" not in st.session_state: st.session_state.src_selected = None
        if "tgt_selected" not in st.session_state: st.session_state.tgt_selected = None

        # --- Source Selection ---
        src_query = st.text_input("Start Node (Keywords)", placeholder="Search entity...", key="src_q")
        src_options = graph_service.get_search_suggestions(src_query)
        src_node = st.selectbox("Select Start Entity", src_options, index=None, key="src_sel")

        # --- Target Selection ---
        tgt_query = st.text_input("Target Node (Keywords)", placeholder="Search entity...", key="tgt_q")
        tgt_options = graph_service.get_search_suggestions(tgt_query)
        tgt_node = st.selectbox("Select Target Entity", tgt_options, index=None, key="tgt_sel")

        # 버튼 클릭 또는 엔티티 변경 시 감지 로직
        auto_trigger = False
        if (src_node != st.session_state.src_selected or 
            tgt_node != st.session_state.tgt_selected):
            
            # 값이 바뀌었다면 업데이트 대상
            st.session_state.src_selected = src_node
            st.session_state.tgt_selected = tgt_node
            auto_trigger = True

        if src_node and tgt_node:
            if auto_trigger:
                with st.spinner("Finding paths..."):
                    reset_graph()
                    st.session_state.last_selected_incident = None 
                    num = run_path_discovery(src_node, tgt_node)
                    if num == 0:
                        st.warning("No connections found between these entities.")
        else:
            st.info("출발지와 목적지를 선택하면 경로가 자동으로 탐색됩니다.")

    st.divider()
    
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        if st.button("🔄 Reset View", use_container_width=True):
            reset_graph()
            if mode == "Incident Walkthrough" and st.session_state.last_selected_incident:
                load_incident_graph(st.session_state.last_selected_incident)
            st.rerun()
    with col_b2:
        if st.button("🎲 Re-Layout", use_container_width=True):
            st.session_state.layout_seed += 1
            if "graph_config" in st.session_state: del st.session_state.graph_config
            st.rerun()

# ==============================================================================
# 4. Visualization & Inspector
# ==============================================================================

# Graph Config Initialization
if "graph_config" not in st.session_state:
    spring_len = 250 + (st.session_state.layout_seed * 0.001)
    st.session_state.graph_config = Config(
        width="100%", height=750, directed=True, physics=True,
        backgroundColor="#212529", 
        link={'labelProperty': 'label', 'renderLabel': True, 'color': '#666666',
              'font': {'color': '#CCCCCC', 'size': 10, 'background': '#212529', 'strokeWidth': 0}},
        physics_options={"barnesHut": {"gravitationalConstant": 0, "centralGravity": 0, "springLength": spring_len, "avoidOverlap": 0.0001}}
    )

col_graph, col_info = st.columns([2.5, 1])

with col_graph:
    selected_node_id = agraph(
        nodes=st.session_state.store_nodes, 
        edges=st.session_state.store_edges, 
        config=st.session_state.graph_config
    )

with col_info:
    tab_inspect, tab_time = st.tabs(["🔍 Node Inspector", "📝 Attack Timeline"])
    
    with tab_inspect:
        if selected_node_id:
            st.markdown(f"**Selected:** `{selected_node_id}`")
            
            # --- 확장 제어 로직 ---
            can_expand = False
            details = graph_service.fetch_node_details(selected_node_id)
            if details:
                # DB 직접 조회로 라벨 확인
                res = graph_service.graph_client.query("MATCH (n) WHERE elementId(n) = $id RETURN labels(n) as l", {"id": selected_node_id})
                n_labels = res[0]['l'] if res else []
                
                # Step이 아니면서, 확장 가능한 타입들(Malware, Vuln, Actor, Indicator, Incident) 체크
                if 'AttackStep' not in n_labels and any(l in n_labels for l in ['Malware', 'Vulnerability', 'ThreatGroup', 'Indicator', 'Incident']):
                    can_expand = True

            if can_expand:
                btn_label = "📂 Expand Incident" if 'Incident' in n_labels else "🌐 Find Connections"
                if st.button(btn_label, use_container_width=True):
                    num = expand_neighbors(selected_node_id)
                    if num > 0:
                        st.success(f"{num}개의 새로운 연결을 찾았습니다.")
                        # rerun이 필요할 수 있음
                        st.rerun()
                    else:
                        st.info("추가로 발견된 연결이 없습니다.")
            elif 'AttackStep' in n_labels:
                st.info("공격 단계(Step)는 확장을 지원하지 않습니다.")
            else:
                st.info("이 노드는 확장이 지원되지 않습니다.")
            
            with st.expander("📄 Node Details", expanded=True):
                details = graph_service.fetch_node_details(selected_node_id)
                if details:
                    for k in ['name', 'title', 'cve_id', 'url', 'phase', 'description', 'summary']:
                        if k in details and details[k]:
                            st.markdown(f"**{k.capitalize()}:**")
                            st.write(details[k])
                    other_props = {k: v for k, v in details.items() if k not in ['name', 'title', 'cve_id', 'url', 'phase', 'description', 'summary'] and v}
                    if other_props:
                        st.divider()
                        st.json(other_props)
        else:
            st.info("Click a node to inspect.")

    with tab_time:
        timeline = st.session_state.incident_timeline
        if not timeline:
            st.caption("Select an incident to see its timeline.")
        else:
            for step in timeline:
                icon = "✅" if step['outcome'] == "Success" else "🚫"
                with st.expander(f"{icon} Step {step['order']}: {step['phase']}", expanded=True):
                    st.write(step['desc'])
                    if step['artifacts']:
                        st.markdown("**Artifacts:**")
                        for a in step['artifacts']: st.caption(f"- {a}")