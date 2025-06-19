# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-only

COMPOSE := "docker compose"

build:
    {{COMPOSE}} build

[confirm("Are you sure you want to replace the .env file? (y/n)")]
env:
    cp .env.example .env
