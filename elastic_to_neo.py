#|   ____||  |        /   \         /       |           ||  |  /      |   |           | /  __  \     |  \ |  | |   ____| /  __  \  | || |         |  | 
#|  |__   |  |       /  ^  \       |   (----`---|  |----`|  | |  ,----'   `---|  |----`|  |  |  |    |   \|  | |  |__   |  |  |  | | || |_        |  | 
#|   __|  |  |      /  /_\  \       \   \       |  |     |  | |  |            |  |     |  |  |  |    |  . `  | |   __|  |  |  |  | |__   _| .--.  |  | 
#|  |____ |  `----./  _____  \  .----)   |      |  |     |  | |  `----.       |  |     |  `--'  |    |  |\   | |  |____ |  `--'  |    | |   |  `--'  | 
#|_______||_______/__/     \__\ |_______/       |__|     |__|  \______|       |__|      \______/     |__| \__| |_______| \______/     |_|    \______/                                                                                                                                               
"""
Description: This script retrieves Suricata data from Elasticsearch and inserts it into Neo4j.
             The data is filtered based on the presence of source and destination IP addresses.

Usage: Fill in the config.py file with the connection information for Elasticsearch and Neo4j.
       Execute the script using python3 elastic_to_neo.py.
"""
from elasticsearch import Elasticsearch
from neo4j import GraphDatabase, basic_auth
import time
from config import ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD
from config import NEO4J_HOST, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE

elastic_state = False
neo4j_state = False

# Connect to Elasticsearch
def connect_elasticsearch():
    try:
        print("[INFO] Attempting to connect to Elasticsearch...")
        es = Elasticsearch([ELASTICSEARCH_HOST], http_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD))
        es.indices.get_alias()
        print("[INFO] Connection to Elasticsearch established successfully")
        elastic_state = True
    except Exception as e:
        es = None
        print("[ERROR] Unable to connect to Elasticsearch:", e)
        elastic_state = False
    return es, elastic_state
    
# Connect to Neo4j
def connect_neo4j():
    try:
        driver = GraphDatabase.driver(NEO4J_HOST, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))
        session = driver.session(database=NEO4J_DATABASE)
        print("[INFO] Attempting to connect to Neo4j...")
        session.run("MATCH (n) RETURN count(n)").data()
        print("[INFO] Connection to Neo4j established successfully")
        neo4j_state = True
    except Exception as e:
        session = None
        print("[ERROR] Unable to connect to Neo4j:", e)
        neo4j_state = False
    return session, neo4j_state
    

    
# Get data from Elasticsearch filtered by IPs
def get_suricata_data_from_elasticsearch(es,index):
    query = {
        "query": {
            "bool": {
                "must": {
                    "match_all": {}
                },
                "filter": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "destination.ip"}},
                            {"term": {"event.module": "suricata"}},
                            {"term": {"network.direction": "internal"}}, #COMMENT TO ALLOW PUBLIC IPs
                            {"range": {
                                "@timestamp": {
                                    "gt": "now-60m" #CHANGE HERE FOR COLLECT TIMEFRAME
                                }
                            }}
                        ]
                    }
                }
            }
        }
    }
    result = es.search(index="filebeat-7.17.18-2024.03.05-000001", body=query, size=10000)
    return result['hits']['hits']

# Function that insert Suricata data in Neo4j with link aggregation
def insert_suricata_data_into_neo4j(session, data):
    for item in data:
        source = item['_source']
        source_ip = source['source']['ip']
        destination_ip = source['destination']['ip']
        host_name = source.get('host', {}).get('name', None)
        source_port = source.get('source', {}).get('port', None)
        destination_port = source.get('destination', {}).get('port', None)
        protocol = source.get('network', {}).get('protocol', 'any')
        create_source_ip_query = (
            "MERGE (source:IP_Address {{ip_address: $source_ip}}) "
            "MERGE (destination:IP_Address {{ip_address: $destination_ip}}) "
            "MERGE (source)-[:{protocol}]->(destination) "
            "SET source.host_name = $host_name, destination.host_name = $host_name, "
            "source.port = $source_port, destination.port = $destination_port"
        )
        create_source_ip_query = create_source_ip_query.format(protocol=protocol)
        session.run(create_source_ip_query, source_ip=source_ip, destination_ip=destination_ip, 
                    host_name=host_name, source_port=source_port, destination_port=destination_port, protocol=protocol)

#Clean Neo4j database
def clear_neo4j_database(session):
    print("[PURGE] Cleaning Neo4j... (10sec...)")
    query = "MATCH (n) DETACH DELETE n"
    session.run(query)
    time.sleep(10)

# Function to execute the runtime agent that retrieves data from Elasticsearch and inserts it into Neo4j periodically

def runtime_agent(session, es, index):
    try:
        i=0
        y=0
        print("\n --- [AGENT] Runtime started. ---")
        while(i==0):
            print("\n[CYCLE] Starting a cycle.")
            time.sleep(1)
            print("[READ-ELASTIC] Retrieving data from Elasticsearch...")
            data = get_suricata_data_from_elasticsearch(es, index)
            time.sleep(1)
            if data:
                print("[SEND-NEO4J] Sending data to Neo4j...")
                insert_suricata_data_into_neo4j(session, data)
            else:
                print("[EMPTY] Nothing to send?")
            print("[CYCLE] End of cycle, waiting for the next cycle...")
            time.sleep(30)
            y = y+1
            if(y==10): #Clean Neo4j database every 10 cycles (approx. 5 minutes)
                clear_neo4j_database(session)
                y = 0
        
    except Exception as e:
        print("\n--- [RUNTIME ERROR] Error in the runtime agent:", e)
        print("[WAITING] The agent will restart itself in 2 minutes...")
        time.sleep(120)
        print("[RESTART] The runtime crashed, restarting...")
        time.sleep(2)
        runtime_agent(session, es)
        
        
# Main function
if __name__ == "__main__":
    print("[HELLO] Checking prerequisites...")
    
    # Connect to databases
    es, elastic_state = connect_elasticsearch()
    session, neo4j_state = connect_neo4j()
    
    # Check if both connections are established
    if elastic_state and neo4j_state:
        print("[READY] Databases are ready")
    else:
        print("[FATAL ERROR] Unable to connect to a database, script will exit...")
        exit(1)
    
    # Get the most recent filebeat index
    print("[INFO] Retrieving the most recent filebeat index...")
    indexes = es.indices.get_alias()
    filebeat_indexes = [index for index in indexes if "filebeat" in index]
    if not filebeat_indexes:
        print("[FATAL ERROR] No filebeat index found, script will exit...")
        exit(1)
    print("\n\n[INFO] Here are the found indexes:", filebeat_indexes)
    index = max(filebeat_indexes)
    print("[INFO] Most recent Filebeat index:", index)
    
    # Clean Neo4j database
    clear_neo4j_database(session)
    
    # Start the runtime agent
    print("\n --- [READY] Ready to launch the runtime.")
    time.sleep(2)
    print("[START] Launching the runtime...")
    runtime_agent(session, es, index)    
