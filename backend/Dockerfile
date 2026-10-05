FROM python:3.13.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10001 porygon \
    && useradd --uid 10001 --gid porygon --create-home --shell /usr/sbin/nologin porygon

COPY pyproject.toml ./
COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic
COPY entrypoint.sh ./entrypoint.sh
COPY tests ./tests

RUN pip install --no-cache-dir ".[test]" \
    && chmod 0555 /app/entrypoint.sh \
    && chown -R porygon:porygon /app

USER 10001:10001

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
