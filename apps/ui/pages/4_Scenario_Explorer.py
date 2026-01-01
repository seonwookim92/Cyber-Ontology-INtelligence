import streamlit as st
import sys
import os

# 프로젝트 루트 경로 확보
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from src.core.graph_client import graph_client
from streamlit_agraph import agraph, Node, Edge, Config

st.set_page_config(page_title="Scenario Explorer", page_icon="🕸️", layout="wide")

# ==============================================================================
# [STYLE] 커스텀 비주얼 스타일
# ==============================================================================
NODE_STYLES = {
    "Incident": {
        "color": "#FF2B2B", "shape": "hexagon", "size": 18,
        "font": {"color": "white", "face": "sans-serif", "background": "#440000"}
    },
    "Victim": {
        "color": "#2D8CFF", "shape": "box", "size": 14,
        "font": {"color": "white", "background": "#002B55"}
    },
    "Actor": {
        "color": "#1A1A1A", "shape": "star", "size": 14,
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

st.title("🕸️ Interactive Incident Graph Explorer")
st.markdown("""
**Graph Walking Mode**: 아티팩트(Malware 등)를 눌러 연결된 사건을 찾고, **그 사건 노드를 다시 눌러** 전체 전말을 파헤치세요.
""")

# ==============================================================================
# 0. Session State 초기화
# ==============================================================================
if "graph_nodes" not in st.session_state: st.session_state.graph_nodes = set()
if "graph_edges" not in st.session_state: st.session_state.graph_edges = set()
if "store_nodes" not in st.session_state: st.session_state.store_nodes = []
if "store_edges" not in st.session_state: st.session_state.store_edges = []
if "incident_timeline" not in st.session_state: st.session_state.incident_timeline = []
if "last_selected_incident" not in st.session_state: st.session_state.last_selected_incident = None

# [신규] Re-Layout 트리거용 시드 (Config 변경 감지용)
if "layout_seed" not in st.session_state: st.session_state.layout_seed = 0

# ==============================================================================
# 1. Helper Functions
# ==============================================================================
def truncate_label(text, length=15):
    if not text: return "Unknown"
    return text if len(text) <= length else text[:length] + "..."

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
            size=style.get("size", 20),
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

# ==============================================================================
# 2. Core Logic: Merge Incident Subgraph
# ==============================================================================
def merge_incident_subgraph(inc_id):
    """특정 사건의 전체 그래프를 현재 상태에 병합"""
    q_head = """
    MATCH (i:Incident {id: $id})-[:TARGETS]->(v:Identity)
    OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(g:ThreatGroup)
    RETURN i.title as title, i.summary as summary, v.name as victim, g.name as actor
    """
    head = graph_client.query(q_head, {"id": inc_id})
    if not head: return 0

    title = head[0]['title']
    summary = head[0]['summary']
    victim = head[0]['victim']
    actor = head[0].get('actor')

    count = 0

    short_title = truncate_label(title, 12)
    if add_node_to_state(inc_id, short_title, "Incident", title=f"[Incident] {title}\n{summary}"): count += 1
    
    vic_id = f"VIC_{inc_id}"
    if add_node_to_state(vic_id, truncate_label(victim), "Victim", title=f"[Victim] {victim}"): count += 1
    add_edge_to_state(inc_id, vic_id, "TARGETS")
    
    if actor:
        act_id = f"ACT_{actor}"
        if add_node_to_state(act_id, actor, "Actor", title=f"[Actor] {actor}"): count += 1
        add_edge_to_state(inc_id, act_id, "ATTRIBUTED_TO")

    # CASE WHEN을 사용해 정확한 아티팩트 타입 판별
    q_path = """
    MATCH (i:Incident {id: $id})-[:STARTS_WITH|NEXT*]->(s:AttackStep)
    OPTIONAL MATCH (s)-[r]->(art)
    WHERE type(r) IN ['USES_MALWARE', 'EXPLOITS', 'HAS_INDICATOR']
    RETURN s.id as step_id, s.order as order, s.phase as phase, s.description as desc, s.outcome as outcome,
           type(r) as rel, 
           CASE 
             WHEN 'Malware' IN labels(art) THEN 'Malware'
             WHEN 'Vulnerability' IN labels(art) THEN 'Vulnerability'
             WHEN 'Indicator' IN labels(art) THEN 'Indicator'
             ELSE 'Unknown'
           END as type, 
           art.name as name, art.cve_id as cve, art.url as url
    ORDER BY s.order
    """
    path = graph_client.query(q_path, {"id": inc_id})
    
    prev_node = inc_id
    steps_map = {}

    for row in path:
        sid = row['step_id']
        label = f"#{row['order']} {row['phase']}"
        step_color = NODE_STYLES["Step"]["Success"]["color"] if row['outcome'] == "Success" else NODE_STYLES["Step"]["Fail"]["color"]
        
        if add_node_to_state(sid, label, "Step", title=f"{row['phase']}: {row['desc']}", custom_color=step_color): count += 1
        
        rel_name = "STARTS_WITH" if row['order'] == 1 else "NEXT"
        add_edge_to_state(prev_node, sid, rel_name)
        prev_node = sid
        
        if inc_id == st.session_state.last_selected_incident:
            if sid not in steps_map:
                steps_map[sid] = {"order": row['order'], "phase": row['phase'], "desc": row['desc'], "outcome": row['outcome'], "artifacts": []}

        if row['type'] and row['type'] != 'Unknown':
            art_val = row.get('name') or row.get('cve') or row.get('url')
            
            if inc_id == st.session_state.last_selected_incident:
                steps_map[sid]['artifacts'].append(f"[{row['type']}] {art_val}")

            aid = ""
            atype = ""
            display = ""
            
            if row['type'] == 'Malware':
                aid = f"MAL_{art_val}"; atype = "Malware"; display = art_val
            elif row['type'] == 'Vulnerability':
                aid = f"CVE_{art_val}"; atype = "Vulnerability"; display = art_val
            elif row['type'] == 'Indicator':
                aid = f"IOC_{art_val}"; atype = "Indicator"; display = truncate_label(art_val, 20)
            
            if aid:
                if add_node_to_state(aid, display, atype, title=f"[{atype}] {art_val}"): count += 1
                add_edge_to_state(sid, aid, row['rel'])

    if inc_id == st.session_state.last_selected_incident:
        st.session_state.incident_timeline = sorted(steps_map.values(), key=lambda x: x['order'])
        
    return count

def expand_node(node_id):
    if node_id.startswith("incident--"):
        cnt = merge_incident_subgraph(node_id)
        return cnt

    node_val = None
    q = None
    current_inc_id = st.session_state.last_selected_incident

    if node_id.startswith("MAL_"):
        node_val = node_id.replace("MAL_", "")
        q = """
        MATCH (m:Malware {name: $val})<-[:USES_MALWARE]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(other_inc:Incident) WHERE other_inc.id <> $current_id
        RETURN other_inc.id as res_id, other_inc.title as res_label, 'Incident' as type, 'USED_IN' as rel
        UNION
        MATCH (m:Malware {name: $val})<-[:USES]-(g:ThreatGroup)
        RETURN g.name as res_id, g.name as res_label, 'Actor' as type, 'USED_BY' as rel
        """
    elif node_id.startswith("CVE_"):
        node_val = node_id.replace("CVE_", "")
        q = """
        MATCH (v:Vulnerability {cve_id: $val})<-[:EXPLOITS]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(other_inc:Incident) WHERE other_inc.id <> $current_id
        RETURN other_inc.id as res_id, other_inc.title as res_label, 'Incident' as type, 'EXPLOITED_IN' as rel
        """
    elif node_id.startswith("IOC_"):
        node_val = node_id.replace("IOC_", "")
        q = """
        MATCH (i:Indicator {url: $val})<-[:HAS_INDICATOR]-(:AttackStep)<-[:STARTS_WITH|NEXT*]-(other_inc:Incident) WHERE other_inc.id <> $current_id
        RETURN other_inc.id as res_id, other_inc.title as res_label, 'Incident' as type, 'SEEN_IN' as rel
        """
    elif node_id.startswith("ACT_"):
        node_val = node_id.replace("ACT_", "")
        q = """
        MATCH (g:ThreatGroup {name: $val})<-[:ATTRIBUTED_TO]-(other_inc:Incident) WHERE other_inc.id <> $current_id
        RETURN other_inc.id as res_id, other_inc.title as res_label, 'Incident' as type, 'ATTRIBUTED_TO' as rel
        UNION
        MATCH (g:ThreatGroup {name: $val})-[:USES]->(m:Malware)
        RETURN m.name as res_id, m.name as res_label, 'Malware' as type, 'USES' as rel
        """
    else:
        return 0

    results = graph_client.query(q, {"val": node_val, "current_id": current_inc_id})
    count = 0
    if not results: return 0

    for r in results:
        res_type = r['type']
        res_id = r['res_id']
        res_label = r['res_label']
        rel = r['rel']

        new_id = ""
        if res_type == 'Incident':
            new_id = res_id
            if add_node_to_state(new_id, truncate_label(res_label, 10), "Incident", title=res_label): count += 1
            if rel == 'ATTRIBUTED_TO': add_edge_to_state(new_id, node_id, rel)
            else: add_edge_to_state(node_id, new_id, rel)

        elif res_type == 'Actor':
            new_id = f"ACT_{res_id}"
            if add_node_to_state(new_id, res_label, "Actor", title=res_label): count += 1
            add_edge_to_state(node_id, new_id, rel)

        elif res_type == 'Malware':
            new_id = f"MAL_{res_id}"
            if add_node_to_state(new_id, res_label, "Malware", title=res_label): count += 1
            add_edge_to_state(node_id, new_id, rel)

    return count

# ==============================================================================
# 3. Sidebar
# ==============================================================================
@st.cache_data(ttl=60)
def get_incidents():
    return graph_client.query("MATCH (i:Incident) RETURN i.id as id, i.title as title ORDER BY i.timestamp DESC LIMIT 30")

incidents = get_incidents()
if not incidents:
    st.error("No incidents found.")
    st.stop()

with st.sidebar:
    st.header("🗂️ Select Incident")
    options = {r['title']: r['id'] for r in incidents}
    selected_label = st.selectbox("Incidents", list(options.keys()))
    selected_id = options[selected_label]

    if selected_id != st.session_state.last_selected_incident:
        st.session_state.last_selected_incident = selected_id
        reset_graph()
        merge_incident_subgraph(selected_id)
        st.rerun()
    
    st.divider()
    
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        if st.button("🔄 Reset View", use_container_width=True):
            reset_graph()
            merge_incident_subgraph(selected_id)
            st.rerun()
    with col_b2:
        # [수정] 버튼 클릭 시 시드(Seed)를 변경하여 Config에 반영
        if st.button("🎲 Re-Layout", use_container_width=True):
            st.session_state.layout_seed += 1
            st.rerun()

# ==============================================================================
# 4. Main Config & Layout
# ==============================================================================

# [수정] 시드값을 이용해 물리 엔진 파라미터를 미세하게 변경 -> 강제 리렌더링 유도
# 0.001 정도의 차이는 시각적으로 동일하지만, Streamlit은 변경된 Config로 인식함
spring_len_tweak = 120 + (st.session_state.layout_seed * 0.001)

config = Config(
    width="100%",
    height=750,
    directed=True, 
    hierarchical=False,
    backgroundColor="#212529", 
    link={
        'labelProperty': 'label', 'renderLabel': True,
        'color': '#666666',
        'font': {'color': '#CCCCCC', 'size': 10, 'background': '#212529', 'strokeWidth': 0}
    },
    physics={
        "enabled": True,
        "barnesHut": {
            "gravitationalConstant": -4000, 
            "centralGravity": 0.3, 
            "springLength": spring_len_tweak, # <-- [핵심] 여기에 Seed 반영
            "springConstant": 0.04,
            "damping": 0.09,
            "avoidOverlap": 0.1
        },
        "stabilization": {
            "enabled": True,
            "iterations": 1000,
            "updateInterval": 25,
            "onlyDynamicEdges": False,
            "fit": True
        }
    }
)

col1, col2 = st.columns([2.5, 1])

with col1:
    selected_node_id = agraph(
        nodes=st.session_state.store_nodes, 
        edges=st.session_state.store_edges, 
        config=config
    )

with col2:
    tab1, tab2 = st.tabs(["🔍 Node Inspector", "📝 Attack Timeline"])
    
    with tab1:
        if selected_node_id:
            st.markdown(f"**Selected:** `{selected_node_id}`")
            
            if selected_node_id.startswith("incident--"):
                st.info("이 사건의 전체 공격 흐름(Step)을 보려면 확장하세요.")
                if st.button("📂 Expand Incident Details"):
                    cnt = expand_node(selected_node_id)
                    st.success(f"Graph merged with {cnt} new nodes.")
                    st.rerun()
            
            elif any(selected_node_id.startswith(p) for p in ["MAL_", "CVE_", "IOC_", "ACT_"]):
                st.info("연관된 다른 사건이나 정보를 찾습니다.")
                if st.button("🌐 Find Connections"):
                    cnt = expand_node(selected_node_id)
                    if cnt > 0:
                        st.success(f"{cnt} related items found!")
                        st.rerun()
                    else:
                        st.warning("No new connections found.")
            else:
                st.caption("No actions available for this node.")
        else:
            st.info("노드를 클릭하여 탐색하세요.")

        st.divider()
        st.markdown("#### 🏷️ Legend")
        st.caption("🛑 Incident / 👤 Actor / 🏢 Victim")
        st.caption("🦠 Malware / ⚠️ CVE / 🟩 IoC")

    with tab2:
        st.markdown(f"### ⚡ Timeline: {incidents[0]['title'][:10]}...")
        timeline = st.session_state.incident_timeline
        if not timeline:
            st.caption("Select the main incident node to see timeline.")
        else:
            for step in timeline:
                icon = "✅" if step['outcome'] == "Success" else "🚫"
                with st.expander(f"{icon} Step {step['order']}: {step['phase']}", expanded=True):
                    st.write(step['desc'])
                    if step['artifacts']:
                        st.markdown("**Artifacts:**")
                        for a in step['artifacts']:
                            st.caption(f"- {a}")