# src/core/graph_client.py
from neo4j import GraphDatabase
from src.core.config import settings  # <--- config에서 설정 가져옴

class Neo4jClient:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Neo4jClient, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        try:
            # 설정 파일의 정보 사용
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD)
            )
            self.verify_connectivity()
        except Exception as e:
            print(f"[!] Neo4j Connection Error: {e}")
            self.driver = None

    def verify_connectivity(self):
        if self.driver:
            try:
                self.driver.verify_connectivity()
                print(f"[*] Connected to Neo4j at {settings.NEO4J_URI}")
            except Exception as e:
                print(f"[!] Could not connect to Neo4j: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def query(self, cypher: str, params=None):
        if not self.driver:
            return []
        with self.driver.session() as session:
            try:
                result = session.run(cypher, params or {})
                return [record.data() for record in result]
            except Exception as e:
                print(f"[!] Query Error: {e}")
                return []

graph_client = Neo4jClient()