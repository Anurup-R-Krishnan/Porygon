FROM python:3.13.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10002 porygon \
    && useradd --uid 10002 --gid porygon --create-home --shell /usr/sbin/nologin porygon

COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests

RUN mkdir -p /var/lib/porygon \
    && pip install --no-cache-dir ".[test]" \
    && chown -R porygon:porygon /app /var/lib/porygon

USER 10002:10002

EXPOSE 8001

CMD ["uvicorn", "porygon_collector.main:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
