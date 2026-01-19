# scripts/setup/init_db.py
import os
import sys
import time
from neo4j import GraphDatabase

# [중요] 프로젝트 루트 경로를 path에 추가하여 src 모듈을 import 할 수 있게 함
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
sys.path.append(PROJECT_ROOT)

# 이제 config에서 설정을 불러올 수 있습니다.
from src.core.config import settings

class GraphLoader:
    def __init__(self):
        # .env에서 로드된 settings 사용
        uri = settings.NEO4J_URI
        auth = (settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD)
        
        print(f"[*] Connecting to Neo4j at {uri} as user '{settings.NEO4J_USERNAME}'...")
        self.driver = GraphDatabase.driver(uri, auth=auth)

    def close(self):
        self.driver.close()

    def run_query_with_result(self, query, desc="Executing query", params=None):
        print(f"[*] {desc}...")
        start_time = time.time()
        with self.driver.session() as session:
            try:
                result = session.run(query, params or {})
                record = result.single()
                count_val = record[0] if record else 0
                elapsed = time.time() - start_time
                print(f"    -> Processed: {count_val} items ({elapsed:.2f}s)")
                return count_val
            except Exception as e:
                print(f"    [!] Error: {e}")
                return 0

    def init_db(self):
        # (기존 로직과 동일하지만 settings를 사용함)
        
        # 1. 초기화
        print("\n=== [1/6] Resetting Database ===")
        self.run_query_with_result("MATCH (n) DETACH DELETE n RETURN count(n)", "Deleting all existing nodes")
        
        # 사건 적재 로그 초기화 (재적재 보장)
        imported_log_path = os.path.join(PROJECT_ROOT, 'data', 'processed', 'incidents_imported.json')
        if os.path.exists(imported_log_path):
            os.remove(imported_log_path)
            print(f"    -> Cleared incident import log: {imported_log_path}")

        # 2. 스키마 설정
        print("\n=== [2/6] Creating Schema & Indexes ===")
        constraints = [
            "CREATE CONSTRAINT FOR (n:BaseNode) REQUIRE n.stix_id IS UNIQUE",
            "CREATE CONSTRAINT FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
            "CREATE CONSTRAINT FOR (i:Indicator) REQUIRE i.id IS UNIQUE",
            "CREATE INDEX FOR (i:Indicator) ON (i.url)"
        ]
        fulltext_index_query = """
        CREATE FULLTEXT INDEX mitre_text_index IF NOT EXISTS
        FOR (n:BaseNode) ON EACH [n.name, n.description]
        """
        
        with self.driver.session() as session:
            for q in constraints:
                try: session.run(q) 
                except: pass
            try: session.run(fulltext_index_query)
            except: pass
        print("    -> Constraints and Full-Text Indexes applied.")
        time.sleep(2)

        # 3. MITRE ATT&CK (load from host CSVs to avoid container import path issues)
        print("\n=== [3/6] Loading MITRE ATT&CK ===")
        mitre_nodes_path = os.path.join(PROJECT_ROOT, 'data', 'processed', 'mitre_nodes.csv')
        mitre_rels_path = os.path.join(PROJECT_ROOT, 'data', 'processed', 'mitre_rels.csv')

        def _batch(iterable, n=500):
            l = len(iterable)
            for i in range(0, l, n):
                yield iterable[i:i+n]

        # Load nodes via Python CSV and create using apoc.create.node in batches
        nodes_count = 0
        if os.path.exists(mitre_nodes_path):
            with open(mitre_nodes_path, 'r', encoding='utf-8') as f:
                reader = __import__('csv').DictReader(f)
                rows = [r for r in reader]
            for batch in _batch(rows, 500):
                q = """
                UNWIND $rows AS r
                CALL apoc.create.node([r.label, 'BaseNode'], {stix_id: r.stix_id, name: r.name, mitre_id: r.mitre_id, description: r.description}) YIELD node
                RETURN count(node) AS cnt
                """
                try:
                    self.run_query_with_result(q, desc=f"Loading MITRE Nodes (batch {nodes_count // 500 + 1})", params={"rows": batch})
                except Exception:
                    pass
                nodes_count += len(batch)
        else:
            print(f"    [!] Error: MITRE nodes CSV not found at {mitre_nodes_path}")

        # Load relationships via CSV and create using apoc.create.relationship in batches
        rels_count = 0
        if os.path.exists(mitre_rels_path):
            with open(mitre_rels_path, 'r', encoding='utf-8') as f:
                reader = __import__('csv').DictReader(f)
                rows = [r for r in reader]
            for batch in _batch(rows, 500):
                q = """
                UNWIND $rows AS r
                MATCH (s:BaseNode {stix_id: r.source_id})
                MATCH (t:BaseNode {stix_id: r.target_id})
                CALL apoc.create.relationship(s, r.type, {}, t) YIELD rel
                RETURN count(rel) AS cnt
                """
                try:
                    self.run_query_with_result(q, desc=f"Loading MITRE Relationships (batch {rels_count // 500 + 1})", params={"rows": batch})
                except Exception:
                    pass
                rels_count += len(batch)
        else:
            print(f"    [!] Error: MITRE relationships CSV not found at {mitre_rels_path}")

        # 4. CISA KEV
        print("\n=== [4/6] Loading CISA KEV ===")
        kev_path = os.path.join(PROJECT_ROOT, 'data', 'processed', 'cisa_kev_clean.csv')
        if os.path.exists(kev_path):
            with open(kev_path, 'r', encoding='utf-8') as f:
                reader = __import__('csv').DictReader(f)
                rows = [r for r in reader]
            kev_count = 0
            for batch in _batch(rows, 500):
                q = """
                UNWIND $rows AS r
                MERGE (v:Vulnerability {cve_id: r.cve_id})
                SET v.name = r.name, v.vendor = r.vendor, v.product = r.product, v.description = r.description
                RETURN count(v) AS cnt
                """
                try:
                    self.run_query_with_result(q, desc=f"Loading KEV Data (batch {kev_count // 500 + 1})", params={"rows": batch})
                except Exception:
                    pass
                kev_count += len(batch)
        else:
            print(f"    [!] Error: KEV CSV not found at {kev_path}")

        # 5. URLHaus
        print("\n=== [5/6] Loading URLHaus & Fuzzy Linking ===")
        urlhaus_path = os.path.join(PROJECT_ROOT, 'data', 'processed', 'urlhaus_indicators.csv')
        if os.path.exists(urlhaus_path):
            with open(urlhaus_path, 'r', encoding='utf-8') as f:
                reader = __import__('csv').DictReader(f)
                rows = [r for r in reader]
            url_count = 0
            for batch in _batch(rows, 500):
                # create indicators
                q_create = """
                UNWIND $rows AS r
                MERGE (i:Indicator {id: r.id})
                SET i.url = r.url, i.tags = r.tags
                RETURN count(i) AS cnt
                """
                try:
                    self.run_query_with_result(q_create, desc=f"Creating Indicators (batch {url_count // 500 + 1})", params={"rows": batch})
                except Exception:
                    pass

                # fuzzy linking based on tags
                q_link = """
                UNWIND $rows AS r
                WITH r, split(coalesce(r.tags, ''), ',') AS tags
                UNWIND tags AS tag
                WITH r, trim(tag) AS clean_tag
                WHERE size(clean_tag) > 3
                MATCH (i:Indicator {id: r.id})
                MATCH (m:Malware)
                WHERE toLower(m.name) = toLower(clean_tag)
                   OR toLower(m.name) CONTAINS toLower(clean_tag)
                   OR toLower(clean_tag) CONTAINS toLower(m.name)
                MERGE (i)-[rel:INDICATES]->(m)
                SET rel.method = 'fuzzy_match', rel.matched_tag = clean_tag
                RETURN count(rel) AS cnt
                """
                try:
                    self.run_query_with_result(q_link, desc=f"Linking Indicators (batch {url_count // 500 + 1})", params={"rows": batch})
                except Exception:
                    pass

                url_count += len(batch)
        else:
            print(f"    [!] Error: URLHaus CSV not found at {urlhaus_path}")

        # 6. Semantic Linking
        print("\n=== [6/6] Semantic Linking: KEV <-> MITRE ===")
        q_semantic_link = """
        MATCH (v:Vulnerability)
        WHERE v.product IS NOT NULL AND size(v.product) > 3
        
        WITH v, apoc.text.clean(v.product) AS clean_product
        WHERE size(clean_product) > 3
        
        CALL db.index.fulltext.queryNodes("mitre_text_index", clean_product) YIELD node, score
        WHERE score > 1.5 AND node:AttackTechnique 
        
        MERGE (v)-[r:RELATED_TO {reason: 'product_match'}]->(node)
        SET r.score = score, r.keyword = v.product
        RETURN count(r)
        """
        self.run_query_with_result(q_semantic_link, "Linking CVEs to Techniques")

        print("\n=== [+] Database Initialization Complete! ===")

if __name__ == "__main__":
    loader = GraphLoader() # 인자 없이 호출 (내부에서 settings 사용)
    try:
        loader.init_db()
    finally:
        loader.close()