# FlagId Service for Tulip

This service periodically fetches flagids from the CTF infrastructure and stores them in MongoDB.

## Features
- Fetches JSON from http://10.10.0.1:8081/flagId every 2 minutes
- Stores flagids in MongoDB with service, team, round, flagid, description, timestamp

## Usage
- Configure MongoDB connection via environment variables
- Run with Docker (see Dockerfile)
