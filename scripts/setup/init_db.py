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

    def run_query_with_result(self, query, desc="Executing query"):
        print(f"[*] {desc}...")
        start_time = time.time()
        with self.driver.session() as session:
            try:
                result = session.run(query)
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

        # 3. MITRE ATT&CK
        print("\n=== [3/6] Loading MITRE ATT&CK ===")
        q_mitre_nodes = """
        LOAD CSV WITH HEADERS FROM 'file:///mitre_nodes.csv' AS row
        CALL apoc.create.node([row.label, 'BaseNode'], {
            stix_id: row.stix_id,
            name: row.name,
            mitre_id: row.mitre_id,
            description: row.description
        }) YIELD node
        RETURN count(node)
        """
        self.run_query_with_result(q_mitre_nodes, "Loading MITRE Nodes")

        q_mitre_rels = """
        LOAD CSV WITH HEADERS FROM 'file:///mitre_rels.csv' AS row
        MATCH (s:BaseNode {stix_id: row.source_id})
        MATCH (t:BaseNode {stix_id: row.target_id})
        CALL apoc.create.relationship(s, row.type, {}, t) YIELD rel
        RETURN count(rel)
        """
        self.run_query_with_result(q_mitre_rels, "Loading MITRE Relationships")

        # 4. CISA KEV
        print("\n=== [4/6] Loading CISA KEV ===")
        q_kev = """
        LOAD CSV WITH HEADERS FROM 'file:///cisa_kev_clean.csv' AS row
        MERGE (v:Vulnerability {cve_id: row.cve_id})
        SET v.name = row.name,
            v.vendor = row.vendor,
            v.product = row.product,
            v.description = row.description
        RETURN count(v)
        """
        self.run_query_with_result(q_kev, "Loading KEV Data")

        # 5. URLHaus
        print("\n=== [5/6] Loading URLHaus & Fuzzy Linking ===")
        q_urlhaus = """
        LOAD CSV WITH HEADERS FROM 'file:///urlhaus_indicators.csv' AS row
        MERGE (i:Indicator {id: row.id})
        SET i.url = row.url, i.tags = row.tags
        
        WITH i, row
        WHERE row.tags IS NOT NULL AND row.tags <> ''
        
        WITH i, split(row.tags, ',') AS tags
        UNWIND tags AS tag
        WITH i, trim(tag) AS clean_tag
        WHERE size(clean_tag) > 3
        
        MATCH (m:Malware)
        WHERE toLower(m.name) = toLower(clean_tag)
           OR toLower(m.name) CONTAINS toLower(clean_tag)
           OR toLower(clean_tag) CONTAINS toLower(m.name)
           
        MERGE (i)-[r:INDICATES]->(m)
        SET r.method = 'fuzzy_match', r.matched_tag = clean_tag
        RETURN count(r)
        """
        self.run_query_with_result(q_urlhaus, "Loading URLHaus & Linking (Fuzzy)")

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