# TF-IDF model is trained during the image build from data/processed.
# No Gemini key is read here. The embedding extra is not installed.
FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    MODEL_KIND=tfidf \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN python scripts/train.py --kind tfidf

EXPOSE 8000 8501

CMD ["uvicorn", "scamshield.api:app", "--host", "0.0.0.0", "--port", "8000"]
