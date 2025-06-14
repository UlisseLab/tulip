COMPOSE := "docker compose"

build:
    {{COMPOSE}} build

[confirm("Are you sure you want to replace the .env file? (y/n)")]
env:
    cp .env.example .env
