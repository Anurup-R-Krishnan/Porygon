FROM python:3.13.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10004 porygon \
    && useradd --uid 10004 --gid porygon --create-home --shell /usr/sbin/nologin porygon

COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests

RUN pip install --no-cache-dir ".[test]" \
    && chown -R porygon:porygon /app

USER 10004:10004

EXPOSE 8003

CMD ["uvicorn", "porygon_responder.main:app", "--host", "0.0.0.0", "--port", "8003", "--no-access-log"]
