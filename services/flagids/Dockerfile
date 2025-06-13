ARG PYTHON_VERSION=3.8

FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-alpine
WORKDIR /app

COPY ./requirements.txt ./
RUN uv venv && \
    uv pip install -r requirements.txt

COPY flagids.py ./
CMD ["uv", "run", "flagids.py"]
