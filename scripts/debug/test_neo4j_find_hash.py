import os, sys
import warnings
warnings.filterwarnings("ignore")

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# scripts/debug/find_hash.py
from src.core.config import settings
from src.core.graph_client import graph_client

HASH = "bc644febfc0a9500bcc24d26fbfa9cae"

print("Using NEO4J_URI:", settings.NEO4J_URI)
print("== Exact match on e.name / e.original_value ==")
q_exact = '''
MATCH (e:Entity)
WHERE e.name = $v OR e.original_value = $v
OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
RETURN e.name AS name, e.original_value AS original, e.type AS type, collect(distinct i.title) AS incidents LIMIT 50
'''
print(graph_client.query(q_exact, {"v": HASH}))

print("\\n== Contains (case-insensitive) in name/original_value ==")
q_contains = '''
MATCH (e:Entity)
WHERE toLower(e.name) CONTAINS toLower($v) OR toLower(e.original_value) CONTAINS toLower($v)
OPTIONAL MATCH (s:AttackStep)-[:INVOLVES_ENTITY]->(e)
OPTIONAL MATCH (i)-[:HAS_ATTACK_FLOW]->(s)
RETURN i.title AS incident, s.phase AS phase, e.name AS entity_name, e.original_value AS original_value LIMIT 50
'''
print(graph_client.query(q_contains, {"v": HASH}))

print("\\n== Broader scan: any node property contains ==")
q_broad = '''
MATCH (n)
WHERE any(k IN keys(n) WHERE toLower(toString(n[k])) CONTAINS toLower($v))
RETURN labels(n) AS labels, n AS node_props LIMIT 50
'''
print(graph_client.query(q_broad, {"v": HASH}))