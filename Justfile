COMPOSE := "docker compose"

build:
    {{COMPOSE}} build --pull

dev:
    {{COMPOSE}} up -d mongo
    {{COMPOSE}} up -d api

wipe-tags:
    uv run scripts/wipe_tags.py
