import os
import time
import requests
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
DB_NAME = os.getenv("FLAGID_DB", "tulip")
COLLECTION = os.getenv("FLAGID_COLLECTION", "flagids")
FLAGID_URL = os.getenv("FLAGID_URL", "http://10.10.0.1:8081/flagId")
FETCH_INTERVAL = int(os.getenv("FLAGID_FETCH_INTERVAL", "60"))  # seconds

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLLECTION]

print(f"[flagid] Avvio fetch periodico da {FLAGID_URL} verso MongoDB {MONGO_URI}", flush=True)

while True:
    print(f"[flagid] Effettuo richiesta a {FLAGID_URL} ...", flush=True)
    try:
        resp = requests.get(FLAGID_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print(f"[flagid] Fetch OK, flagids ricevuti: {len(data)} servizi.", flush=True)
        now = datetime.utcnow()
        bulk = []
        for service, teams in data.items():
            for team, rounds in teams.items():
                for round_num, flagids in rounds.items():
                    for desc, flagid in flagids.items():
                        doc = {
                            "service": service,
                            "team": int(team),
                            "round": int(round_num),
                            "flagid": flagid,
                            "description": desc,
                            "timestamp": now
                        }
                        bulk.append(doc)
        if bulk:
            for doc in bulk:
                col.delete_many({
                    "service": doc["service"],
                    "team": doc["team"],
                    "round": doc["round"],
                    "flagid": doc["flagid"]
                })
            col.insert_many(bulk)
    except Exception as e:
        print(f"[flagid-fetch] Error: {e}", flush=True)
    time.sleep(FETCH_INTERVAL)
