#!/usr/bin/env python
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pymongo",
# ]
# ///

from pymongo import MongoClient

mongo_server = "localhost:27017"

client = MongoClient(
    mongo_server, serverSelectionTimeoutMS=200, unicode_decode_error_handler="ignore"
)
db = client.pcap
pcap_coll = db.pcap

pcap_coll.update_many({}, {"$pull": {"tags": {"$nin": ["flag-in", "flag-out"]}}})
