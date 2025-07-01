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

TICK_SECONDS = 120 # round da 2 minuti
OFFSET_SECONDS = 5  

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLLECTION]


print(f"[flagid] Avvio fetch periodico da {FLAGID_URL} verso MongoDB {MONGO_URI}", flush=True)

while True:
    now = time.time()
    next_tick = (int(now) // TICK_SECONDS + 1) * TICK_SECONDS
    target_time = next_tick + OFFSET_SECONDS
    sleep_time = target_time - now
    if sleep_time > 0:
        time.sleep(sleep_time)
    # convert 

    try:
        resp = requests.get(FLAGID_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # print now as 2023-10-01T12:00:00Z format
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        print(f"[flagid] Ora {now} Fetch OK, flagids ricevuti: {len(data)} servizi.", flush=True)
        now_dt = datetime.utcnow()
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
                            "timestamp": now_dt
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
