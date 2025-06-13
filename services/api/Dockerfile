ARG PYTHON_VERSION=3.8

FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-alpine
WORKDIR /app

COPY ./requirements.txt ./
RUN uv venv \
    && uv pip install -r requirements.txt \
    && uv pip install gunicorn

COPY . .
CMD uv run gunicorn \
    --timeout 5 --graceful-timeout 3 \
    --bind 0.0.0.0:5000 \
    webservice:application
