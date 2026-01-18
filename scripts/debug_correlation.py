
import os
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.core.graph_client import graph_client

artifacts = [
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

print("=== COIN Diagnostic: Node Search & Connectivity ===")

for art in artifacts:
    val = art["value"]
    print(f"\n[Artifact] {art['type']}: {val}")
    
    # Generic search across common properties
    # Using coalesce to avoid property key warnings where possible
    q = """
    MATCH (n)
    WHERE n.name = $val OR n.value = $val OR n.url = $val OR n.cve_id = $val
    RETURN labels(n) as labels, properties(n) as props
    """
    try:
        results = graph_client.query(q, {"val": val})
        if not results:
            # Try containment search as fallback if exact match fails
            q_cont = """
            MATCH (n)
            WHERE toLower(coalesce(n.name, '')) CONTAINS toLower($val) 
               OR toLower(coalesce(n.value, '')) CONTAINS toLower($val)
               OR toLower(coalesce(n.url, '')) CONTAINS toLower($val)
            RETURN labels(n) as labels, properties(n) as props LIMIT 3
            """
            results = graph_client.query(q_cont, {"val": val})
            if results:
                print(f"  (Found {len(results)} matches via CONTAINS)")
            else:
                print("  (No matches found)")
                continue
        
        for r in results:
            lbl = r['labels']
            p = r['props']
            # Safely get a display name
            disp_name = p.get('name') or p.get('cve_id') or p.get('url') or p.get('value') or "Unknown"
            print(f"  - Node: {lbl} -> {disp_name}")
            
            # Check for direct connections to ThreatGroup or Incident via APOC or standard MATCH
            # We'll use a standard MATCH with path to get length correctly
            q_conn = """
            MATCH (n)
            WHERE (n.name = $name AND n.name IS NOT NULL) 
               OR (n.value = $name AND n.value IS NOT NULL) 
               OR (n.url = $name AND n.url IS NOT NULL) 
               OR (n.cve_id = $name AND n.cve_id IS NOT NULL)
            MATCH p = (n)-[*1..3]-(target)
            WHERE target:ThreatGroup OR target:Incident
            // Filter out paths that are too long or irrelevant if needed
            WITH p, target, nodes(p) as ns, relationships(p) as rs
            RETURN 
                [r IN rs | type(r)] as rel_types,
                labels(target) as target_labels,
                coalesce(target.name, target.title) as target_name,
                length(p) as hops,
                [node IN ns | labels(node)[0] + ':' + coalesce(node.name, node.title, node.value, node.url, 'unnamed')] as path_nodes
            LIMIT 10
            """
            connections = graph_client.query(q_conn, {"name": disp_name})
            if not connections:
                print("    (No connections to ThreatGroup/Incident found within 3 hops)")
            for c in connections:
                path_str = " -> ".join(c['path_nodes'])
                print(f"    -> Link: {c['target_labels']} '{c['target_name']}' ({c['hops']} hops)")
                print(f"       Path: {path_str}")
                
    except Exception as e:
        print(f"  [Error] {e}")

print("\n=== End Diagnostic ===")
